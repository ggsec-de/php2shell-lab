<#
.SYNOPSIS
    Sync this lab tree to a remote host over ssh, verifying every byte.

.DESCRIPTION
    The Kali box has no credentials for the private repository, so updates travel as an archive.
    This script builds one from the current working tree, copies it over ssh, extracts it on the
    far side and verifies each file against a hash manifest generated here. The remote tree is
    only touched after the archive has arrived intact, and stale files are removed so a file
    deleted locally does not linger remotely.

    Excluded: .git, __pycache__, *.pyc, .vscode, OS noise.

.PARAMETER Remote
    ssh destination, default kali@192.168.0.25.

.PARAMETER Dest
    parent directory on the remote, default ~/labs/local/php2shell-lab. The tree lands in
    <Dest>/<name of this repository>.

.PARAMETER DryRun
    Build, upload and verify the archive, list what would land, then stop without touching the
    remote tree.

.PARAMETER KeepRemoteStale
    Do not delete remote files that no longer exist locally.

.EXAMPLE
    .\sync-to-kali.ps1 -DryRun
    .\sync-to-kali.ps1
    .\sync-to-kali.ps1 -Remote kali@10.0.0.5 -Dest '~/src/lab'
#>
[CmdletBinding()]
param(
    [string]$Remote = 'kali@192.168.0.25',
    [string]$Dest = '~/labs/local/php2shell-lab',
    [switch]$DryRun,
    [switch]$KeepRemoteStale
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$repoName = Split-Path -Leaf $repoRoot
$sshArgs = @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', '-o', 'StrictHostKeyChecking=accept-new')

$excluded = @('\.git\\', '\\__pycache__\\', '\.pyc$', '\.vscode\\', 'Thumbs\.db$', '\.DS_Store$')

$staging = Join-Path ([IO.Path]::GetTempPath()) ('sync-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$archive = Join-Path ([IO.Path]::GetTempPath()) ("$repoName-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.tar.gz')
$remoteArchive = '/tmp/' + [IO.Path]::GetFileName($archive)

# A leading ~ must become $HOME before it reaches the remote script. Quoted, bash does not expand
# tilde, and the tree lands in a directory literally named "~".
$destRemote = $Dest -replace '^~(?=/|$)', '$HOME'

try {
    Write-Host "sync $repoName -> ${Remote}:$Dest" -ForegroundColor Cyan

    $files = Get-ChildItem -LiteralPath $repoRoot -Recurse -File | Where-Object {
        $relative = $_.FullName.Substring($repoRoot.Length)
        -not ($excluded | Where-Object { $relative -match $_ })
    }
    if ($files.Count -eq 0) { throw "no files to sync under $repoRoot" }
    $totalBytes = ($files | Measure-Object -Property Length -Sum).Sum
    Write-Host ("  local: {0} files, {1:N1} KiB" -f $files.Count, ($totalBytes / 1kb))

    # Stage a copy so the manifest can sit inside the tree without dirtying the working copy.
    $stageRepo = Join-Path $staging $repoName
    New-Item -ItemType Directory -Force -Path $stageRepo | Out-Null
    $manifest = New-Object System.Text.StringBuilder
    foreach ($file in $files) {
        $relative = $file.FullName.Substring($repoRoot.Length).TrimStart('\', '/')
        $target = Join-Path $stageRepo $relative
        $dir = Split-Path -Parent $target
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        Copy-Item -LiteralPath $file.FullName -Destination $target -Force
        $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLower()
        [void]$manifest.Append($hash + '  ' + ($relative -replace '\\', '/') + "`n")
    }
    [IO.File]::WriteAllText((Join-Path $stageRepo 'MANIFEST.sha256'), $manifest.ToString(),
        (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ("  manifest: {0} entries" -f $files.Count)

    Write-Host '  contact:'
    $probe = & ssh @sshArgs $Remote 'hostname; uname -m' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "ssh failed: $probe" }
    $probe | ForEach-Object { Write-Host "    $_" }

    Push-Location -LiteralPath $staging
    try {
        & tar -czf $archive $repoName
        if ($LASTEXITCODE -ne 0) { throw 'tar failed' }
    }
    finally { Pop-Location }

    $archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLower()
    Write-Host ("  archive: {0:N1} KiB  sha256 {1}..." -f ((Get-Item -LiteralPath $archive).Length / 1kb), $archiveHash.Substring(0, 16))

    Write-Host '  upload:'
    & scp @sshArgs $archive "${Remote}:$remoteArchive" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'scp failed' }
    $remoteHash = (& ssh @sshArgs $Remote "sha256sum '$remoteArchive' | cut -d' ' -f1" 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "remote sha256 failed: $remoteHash" }
    if ($remoteHash -ne $archiveHash) {
        throw "archive corrupted in transit: local $archiveHash, remote $remoteHash"
    }
    Write-Host '    archive verified in transit'

    if ($DryRun) {
        Write-Host ''
        Write-Host 'dry run: the remote tree was not touched.' -ForegroundColor Yellow
        & ssh @sshArgs $Remote "rm -f '$remoteArchive'" | Out-Null
        Write-Host ("  would install {0} files into {1}/{2}:" -f $files.Count, $Dest, $repoName)
        $files | ForEach-Object { Write-Host ('    ' + $_.FullName.Substring($repoRoot.Length).TrimStart('\', '/')) }
        return
    }

    # Extract beside the target and rsync into place, so a file deleted locally is also removed
    # remotely and the destination is never left half-written.
    $deleteFlag = if ($KeepRemoteStale) { '' } else { ' --delete' }
    $remoteScript = @"
set -e
DEST="$destRemote"
NAME='$repoName'
mkdir -p "`$DEST"
TMP=`$(mktemp -d)
trap 'rm -rf "`$TMP"' EXIT
tar -xzf '$remoteArchive' -C "`$TMP"
[ -f "`$TMP/`$NAME/MANIFEST.sha256" ] || { echo 'manifest missing from archive' >&2; exit 1; }
cd "`$TMP/`$NAME"
sha256sum -c --quiet MANIFEST.sha256
mkdir -p "`$DEST/`$NAME"
rsync -a$deleteFlag --exclude='MANIFEST.sha256' "`$TMP/`$NAME/" "`$DEST/`$NAME/"
find "`$DEST/`$NAME" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
COUNT=`$(find "`$DEST/`$NAME" -type f | wc -l)
echo "  installed: `$COUNT files in `$DEST/`$NAME"
if [ "`$COUNT" != '$($files.Count)' ]; then
  echo "  expected $($files.Count) files, found `$COUNT" >&2
  exit 1
fi
rm -f '$remoteArchive'
"@

    # Send the script as a file, not through stdin: PowerShell prefixes a piped string with a BOM,
    # and bash then reads the first line as "set" with a corrupted flag.
    $localScript = Join-Path ([IO.Path]::GetTempPath()) ('install-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.sh')
    [IO.File]::WriteAllText($localScript, ($remoteScript -replace "`r`n", "`n"),
        (New-Object System.Text.UTF8Encoding($false)))
    $remoteScriptPath = '/tmp/' + [IO.Path]::GetFileName($localScript)
    try {
        & scp @sshArgs $localScript "${Remote}:$remoteScriptPath" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'scp of the install script failed' }

        Write-Host '  install:'
        $result = & ssh @sshArgs $Remote "bash '$remoteScriptPath'; rc=`$?; rm -f '$remoteScriptPath'; exit `$rc" 2>&1
        $code = $LASTEXITCODE
        $result | ForEach-Object { Write-Host "    $_" }
        if ($code -ne 0) { throw "remote install failed (exit $code)" }
    }
    finally {
        if (Test-Path -LiteralPath $localScript) { Remove-Item -LiteralPath $localScript -Force -ErrorAction SilentlyContinue }
    }

    Write-Host ''
    Write-Host ("done: {0} files hash-verified and installed at {1}:{2}/{3}" -f $files.Count, $Remote, $Dest, $repoName) -ForegroundColor Green
}
finally {
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue }
}
