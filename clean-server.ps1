$content = Get-Content 'c:\Users\HP\Desktop\IVOTE-PROJECT\server.js' -Raw
$lines = $content -split "`r`n"
$cleanedLines = $lines[0..5881]
$cleanedLines | Set-Content 'c:\Users\HP\Desktop\IVOTE-PROJECT\server-backup.js'
Get-Content 'c:\Users\HP\Desktop\IVOTE-PROJECT\room-polls-routes.js' | Add-Content 'c:\Users\HP\Desktop\IVOTE-PROJECT\server-backup.js'
Move-Item 'c:\Users\HP\Desktop\IVOTE-PROJECT\server.js' 'c:\Users\HP\Desktop\IVOTE-PROJECT\server-old.js' -Force
Move-Item 'c:\Users\HP\Desktop\IVOTE-PROJECT\server-backup.js' 'c:\Users\HP\Desktop\IVOTE-PROJECT\server.js' -Force
Write-Host "Server.js cleaned successfully!"
