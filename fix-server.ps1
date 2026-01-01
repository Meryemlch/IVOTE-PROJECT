# PowerShell script to clean server.js and add routes once
Write-Host "Cleaning server.js..."

# Read the file
$content = Get-Content 'server.js' -Raw

# Split into lines
$lines = $content -split "`r`n"

Write-Host "Original line count: $($lines.Count)"

# Keep only first 5882 lines (original file)
$cleanedLines = $lines[0..5881]

# Save cleaned version
$cleanedLines -join "`r`n" | Set-Content 'server.js' -NoNewline

Write-Host "Cleaned to 5882 lines"

# Now add the room polls routes
Write-Host "Adding room polls routes..."
Get-Content 'room-polls-routes.js' | Add-Content 'server.js'

Write-Host "Done! Server.js is ready."

# Count final lines
$final = Get-Content 'server.js'
Write-Host "Final line count: $($final.Count)"
