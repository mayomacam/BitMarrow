# Check if git is installed
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Error "Git is not installed or not in PATH."
    Pause
    exit
}

Write-Host "=== BitMarrow Git Updater ===" -ForegroundColor Cyan
Write-Host "Checking Status..." -ForegroundColor Gray
git status

# Check for uncommitted changes
$repoChanged = (git status --porcelain)

if (-not $repoChanged) {
    Write-Host "No local changes to commit." -ForegroundColor Yellow
} else {
    Write-Host "`nLocal changes detected." -ForegroundColor Cyan
    $userChoice = Read-Host "Do you want to stage and commit these changes? (y/n)"
    
    if ($userChoice -eq 'y') {
        Write-Host "Staging files..." -ForegroundColor Gray
        git add .
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $msgInput = Read-Host "Enter commit message (Default: 'Update $timestamp')"
        $commitMsg = if ([string]::IsNullOrWhiteSpace($msgInput)) { "Update $timestamp" } else { $msgInput }
        
        git commit -m "$commitMsg"
        Write-Host "Commit successful." -ForegroundColor Green
    } else {
        Write-Host "Skipping commit step." -ForegroundColor Yellow
    }
}

Write-Host "`nSyncing with Remote (Pulling)..." -ForegroundColor Cyan
# Using --rebase to keep history clean, but wrapping in try/catch equivalent logic
git pull origin main
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error during pull. You probably have merge conflicts." -ForegroundColor Red
    Write-Host "Please resolve conflicts manually, then run this script again." -ForegroundColor Red
    Pause
    exit
}

Write-Host "`nPushing to GitHub..." -ForegroundColor Cyan
git push origin main
if ($LASTEXITCODE -eq 0) {
    Write-Host "Success! Repository is up to date." -ForegroundColor Green
} else {
    Write-Host "Push failed. Check connection or permissions." -ForegroundColor Red
}

Write-Host "`nDone."
Pause
