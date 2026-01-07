# Check if git is installed
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Error "Git is not installed or not in PATH."
    Pause
    exit
}

Write-Host "=== BitMarrow Git Updater ===" -ForegroundColor Cyan

# --- Step 1: Pull from Remote ---
Write-Host "`n[Step 1/3] Syncing with Remote (Pulling)..." -ForegroundColor Cyan

# Check for local changes
$fileStatus = (git status --porcelain)
$stashed = $false

if ($fileStatus) {
    Write-Host "Local changes detected. Stashing currently to allow clean pull..." -ForegroundColor Gray
    git stash push -m "AutoWatcher-Temp-Stash"
    if ($LASTEXITCODE -eq 0) {
        $stashed = $true
    }
}

Write-Host "Pulling latest changes from GitHub..." -ForegroundColor Gray
git pull origin main
$pullStatus = $LASTEXITCODE

# Restore changes if we stashed them
if ($stashed) {
    Write-Host "Restoring your local changes..." -ForegroundColor Gray
    git stash pop
    if ($LASTEXITCODE -ne 0) {
        Write-Host "⚠️ CONFLICT DETECTED during stash pop!" -ForegroundColor Red
        Write-Host "Your changes and the remote changes overlap."
        Write-Host "Git has added conflict markers (<<<<<<<) to the files."
        Write-Host "Please open the files, fix the conflicts, and run this script again."
        Pause
        exit
    }
}

if ($pullStatus -ne 0) {
    Write-Host "⚠️ Error during pull. Check your connection or resolving merge conflicts." -ForegroundColor Red
    Pause
    exit
}
Write-Host "Pull complete." -ForegroundColor Green


# --- Step 2: Commit to Local Repo ---
Write-Host "`n[Step 2/3] Saving to Local Repository..." -ForegroundColor Cyan

# Check status again after pull/pop
$currentStatus = (git status --porcelain)

if (-not $currentStatus) {
    Write-Host "No changes to commit." -ForegroundColor Yellow
}
else {
    Write-Host "Files to be saved:" -ForegroundColor Gray
    git status -s
    
    $userChoice = Read-Host "`nDo you want to commit these changes? (y/n)"
    if ($userChoice -eq 'y') {
        git add .
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $msgInput = Read-Host "Enter commit message (Default: 'Update $timestamp')"
        $commitMsg = if ([string]::IsNullOrWhiteSpace($msgInput)) { "Update $timestamp" } else { $msgInput }
        
        git commit -m "$commitMsg"
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Changes saved to local repository." -ForegroundColor Green
        }
        else {
            Write-Host "Commit failed." -ForegroundColor Red
            Pause
            exit
        }
    }
    else {
        Write-Host "Skipping commit. (Note: Changes valid not be pushed)" -ForegroundColor Yellow
    }
}


# --- Step 3: Push to Remote ---
Write-Host "`n[Step 3/3] Pushing to GitHub..." -ForegroundColor Cyan

# Check if we are ahead of origin
$ahead = git status -sb | Select-String "ahead"
if ($ahead -or $currentStatus) {
    git push origin main
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Success! All data pushed to GitHub." -ForegroundColor Green
    }
    else {
        Write-Host "❌ Push failed. You might need to authenticate or check permissions." -ForegroundColor Red
    }
}
else {
    Write-Host "Nothing new to push." -ForegroundColor Green
}

Write-Host "`nOperation Complete."
Pause
