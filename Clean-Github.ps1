# ---------- edit this if needed ----------
$repoUrl = "https://github.com/johnnymeintel/johnnycybersec.git"   
$remoteName = "origin"
# -----------------------------------------

# init repo if needed and ensure branch exists
if (-not (Test-Path .git)) {
    git init
    # Try main first, then master if that fails
    try {
        git checkout -b main 2>$null
    } catch {
        git checkout -b master
    }
}

# set or update remote
if (-not (git remote)) {
    if ($repoUrl -eq "REPO_URL") {
        Write-Host "No remote configured. Please set `$repoUrl above or run 'git remote add origin <URL>' manually." -ForegroundColor Yellow
        exit 1
    }
    git remote add $remoteName $repoUrl
} else {
    git remote set-url $remoteName $repoUrl
}

# try to determine remote default branch, fall back to main
$defaultBranch = $null
try {
    $symref = git ls-remote --symref $remoteName HEAD 2>$null
    if ($symref) {
        $m = ($symref | Select-String -Pattern 'ref: refs/heads/(.+)\s+HEAD')
        if ($m) { $defaultBranch = $m.Matches[0].Groups[1].Value }
    }
} catch { }

if (-not $defaultBranch) { $defaultBranch = "main" }

Write-Host "Using remote '$remoteName' -> $repoUrl, target branch: $defaultBranch" -ForegroundColor Cyan

# add everything, commit (allow-empty in case nothing changed)
git add -A
git commit -m "Replace repo contents with local snapshot ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))" --allow-empty

# force push current HEAD to remote default branch (overwrites remote history)
git push --force $remoteName HEAD:refs/heads/$defaultBranch