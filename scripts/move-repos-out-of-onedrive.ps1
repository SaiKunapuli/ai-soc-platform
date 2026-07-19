<#
.SYNOPSIS
    Move SOC, ECA, and ai-speed-radar out of OneDrive into C:\Projects\,
    preserving .git so each repo's GitHub remote stays connected.

.DESCRIPTION
    One-shot migration. Defaults match the user's current local layout.

    Run elevated (Run as Administrator); the script refuses otherwise.

    Pause OneDrive before running: tray icon -> Pause syncing -> 2 hours.
    The script will warn if OneDrive is still running.

    By default the script copies and verifies but does NOT delete the
    originals. Pass -DeleteSources to optionally remove them after a
    confirmation prompt.

.PARAMETER SrcRoot
    Parent folder containing the repos. Default: the Obsidian Vault root.

.PARAMETER DstRoot
    Destination parent folder. Default: C:\Projects.

.PARAMETER Repos
    Repo names (immediate subfolders of $SrcRoot).
    Default: SOC, ECA, ai-speed-radar.

.PARAMETER DeleteSources
    After a clean copy + verify, prompt to delete the OneDrive originals.

.EXAMPLE
    # Just copy + verify, leave originals alone.
    powershell -ExecutionPolicy Bypass -File scripts\move-repos-out-of-onedrive.ps1

.EXAMPLE
    # After eyeballing C:\Projects, delete originals (with confirm prompt).
    powershell -ExecutionPolicy Bypass -File scripts\move-repos-out-of-onedrive.ps1 -DeleteSources
#>

[CmdletBinding()]
param(
    [string]$SrcRoot = "C:\Users\srika\OneDrive\Documents\Obsidian Vault",
    [string]$DstRoot = "C:\Projects",
    [string[]]$Repos = @("SOC", "ECA", "ai-speed-radar"),
    [switch]$DeleteSources
)

$ErrorActionPreference = "Stop"

# ----------------------------------------------------------------- helpers --

function Write-Step { param([string]$T) Write-Host "" ; Write-Host "=== $T ===" -ForegroundColor Cyan }
function Write-OK   { param([string]$T) Write-Host ("  OK    " + $T) -ForegroundColor Green }
function Write-Warn { param([string]$T) Write-Host ("  WARN  " + $T) -ForegroundColor Yellow }
function Write-Err  { param([string]$T) Write-Host ("  ERROR " + $T) -ForegroundColor Red }
function Write-Info { param([string]$T) Write-Host ("  INFO  " + $T) -ForegroundColor DarkGray }

# Delete a Windows-reserved-name file (e.g. one literally named "nul") that
# PowerShell's Remove-Item refuses. The \\?\ UNC prefix bypasses the
# reserved-device-name check so the parser recognises it as a real file.
function Remove-ReservedNameFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Info ("not present: " + $Path)
        return
    }
    $unc = "\\?\" + $Path
    try {
        $null = [System.IO.File]::Delete($unc)
        Write-OK ("deleted reserved-name file: " + $Path)
    } catch [System.IO.FileNotFoundException] {
        Write-Info ("not present: " + $Path)
    } catch {
        Write-Warn ("could not delete " + $Path + " (" + $_.Exception.Message + ")")
    }
}

# -------------------------------------------------------------------- main --

# Banner
Write-Host ""
Write-Host "Move repos out of OneDrive" -ForegroundColor Cyan
Write-Host ("  Source : " + $SrcRoot)
Write-Host ("  Dest   : " + $DstRoot)
Write-Host ("  Repos  : " + ($Repos -join ", "))
Write-Host ""

# Elevation check
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Err "This script must run ELEVATED (Run as Administrator)."
    exit 1
}
Write-OK "Running as Administrator"

# Preflight
Write-Step "PREFLIGHT"
if (Get-Process OneDrive -ErrorAction SilentlyContinue) {
    Write-Warn "OneDrive is running. Pause it (tray -> Pause syncing -> 2h) before continuing."
    Write-Info "robocopy /R:5 /W:3 will retry transient file locks, but pausing is safer."
}
if (-not (Test-Path $SrcRoot)) { throw ("Source root missing: " + $SrcRoot) }
Write-OK ("Source exists: " + $SrcRoot)
if (-not (Test-Path $DstRoot)) {
    New-Item -ItemType Directory -Force -Path $DstRoot | Out-Null
    Write-OK ("Created destination: " + $DstRoot)
} else {
    Write-OK ("Destination exists: " + $DstRoot)
}

# Scrub 'nul' reserved-name files that block naive copies
Write-Step "DELETE 'nul' RESERVED-NAME FILES"
$nulPaths = @(
    (Join-Path $SrcRoot "SOC\nul"),
    (Join-Path $SrcRoot "SOC\ai-soc-platform\nul")
)
foreach ($n in $nulPaths) { Remove-ReservedNameFile -Path $n }

# Copy each repo with robocopy
Write-Step "COPY REPOS"
$copyErrors = @()
foreach ($r in $Repos) {
    $src = Join-Path $SrcRoot $r
    $dst = Join-Path $DstRoot $r
    if (-not (Test-Path $src)) { Write-Warn ("skip (missing source): " + $src); continue }
    if (Test-Path $dst) {
        Write-Warn ("destination already exists, won't overwrite: " + $dst)
        $copyErrors += $r
        continue
    }

    Write-Host ""
    Write-Host ("COPY: " + $r) -ForegroundColor Cyan
    # /E   subdirs incl. empty    /COPYALL  preserve attributes     /R:5 /W:3  retry locks
    robocopy "$src" "$dst" /E /COPYALL /R:5 /W:3 /XF "nul" "NUL" /NFL /NDL /NP
    if ($LASTEXITCODE -ge 8) {
        Write-Err ("robocopy failed for " + $r + " (exit=" + $LASTEXITCODE + ")")
        $copyErrors += $r
    } else {
        Write-OK ("copied " + $r)
    }
}
if ($copyErrors.Count -gt 0) { throw ("Copy failed for: " + ($copyErrors -join ", ") + ". Sources untouched.") }

# Verify each repo's git is intact
Write-Step "VERIFY"
$verifyErrors = @()
foreach ($r in $Repos) {
    $dst = Join-Path $DstRoot $r
    if (-not (Test-Path (Join-Path $dst ".git"))) {
        Write-Info ("no .git -- plain folder: " + $r)
        continue
    }

    Push-Location $dst
    try {
        $branch    = (git rev-parse --abbrev-ref HEAD) 2>$null
        $remote    = (git remote get-url origin) 2>$null
        $dirty     = @(git status --porcelain 2>$null | Where-Object { $_ }).Count
        git fetch --dry-run 2>&1 | Out-Null
        $fetchOk   = ($LASTEXITCODE -eq 0)

        Write-Host ("   branch        : " + $branch)
        Write-Host ("   remote        : " + $remote)
        Write-Host ("   uncommitted   : " + $dirty)
        if ($fetchOk) {
            Write-Host "   fetch dry-run : OK" -ForegroundColor Green
        } else {
            Write-Host "   fetch dry-run : FAILED" -ForegroundColor Red
            $verifyErrors += $r
        }
    } finally {
        Pop-Location
    }
}
if ($verifyErrors.Count -gt 0) { throw ("Verify failed for: " + ($verifyErrors -join ", ") + ". Sources untouched.") }

# Summary
Write-Host ""
Write-Host ("COPY + VERIFY COMPLETE.  Source: " + $SrcRoot + "  ->  " + $DstRoot) -ForegroundColor Cyan

# Optional cleanup of OneDrive originals
if ($DeleteSources) {
    Write-Host ""
    $ans = Read-Host ("About to delete OneDrive originals at " + $SrcRoot + ". Type 'yes' to proceed (anything else aborts)")
    if ($ans -ieq 'yes') {
        foreach ($r in $Repos) {
            $p = Join-Path $SrcRoot $r
            if (-not (Test-Path $p)) { continue }
            try {
                Remove-Item -Recurse -Force $p
                Write-OK ("deleted " + $p)
            } catch {
                Write-Warn ("could not delete " + $p + " (" + $_.Exception.Message + ")")
            }
        }
    } else {
        Write-Warn ("declined -- originals remain")
    }
} else {
    Write-Host ("  Verify " + $DstRoot + " looks right, then re-run with -DeleteSources.") -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "Next:" -ForegroundColor White
Write-Host "  cd C:\Projects\SOC\wazuh-docker\single-node"
Write-Host "  docker compose -f generate-indexer-certs.yml run --rm --user 0:0 generator"
