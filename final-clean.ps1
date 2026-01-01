# Final cleanup script for server.js
Write-Host "=== CLEANING SERVER.JS ===" 

# Read file content
$content = Get-Content 'server.js' -Raw

# Find the position of line 5882 (end of "});")
$lines = $content -split "`r?`n"
$newContent = @()

for ($i = 0; $i -lt [Math]::Min(5882, $lines.Count); $i++) {
    $newContent += $lines[$i]
}

# Save cleaned server.js
$newContent -join "`r`n" | Set-Content 'server.js' -NoNewline

Write-Host "✅ Trunacted server.js to line 5882"
Write-Host "=== ADDING CLEAN ROUTES ==="

# Add clean routes
Get-Content 'room-polls-routes-CLEAN.js' | Add-Content 'server.js'

Write-Host "✅ Routes added!"
Write-Host "=== FINAL server.js line count: $((Get-Content 'server.js').Count) ==="
