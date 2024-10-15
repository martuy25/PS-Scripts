# Loading Windows Forms Assembly
Add-Type -AssemblyName System.Windows.Forms

# Time Window that checks for the last 24 hours
$StartDate = (Get-Date).AddDays(-1)

# Grabbing failed logon attempts by checking event logs ID codes
$FailedLogons = Get-EventLog -LogName Security -InstanceId 4625 -After $StartDate |
    Select-Object TimeGenerated,
        @{Name="User";Expression={($_.ReplacementStrings[5])}},
#        @{Name="IPAddress";Expression={($_.ReplacementStrings[18])}}, # Adjust index as needed
        Message

# Export to CSV
$CsvFile = "C:\Users\mrkdwn\Documents\FailedLogons-$(Get-Date -Format yyyyMMdd).csv"
$FailedLogons | Export-Csv -NoTypeInformation -Path $CsvFile

# Log to console (optional)
Write-Host "Failed logons report exported to $CsvFile"

# Threshold for failed sign on events
$Threshold = 2
$SuspiciousAttempts = $FailedLogons | Group-Object User | Where-Object {$_.Count -ge $Threshold}

if ($SuspiciousAttempts.Count -gt 0) {
    # Prepare log message with detailed information
    $logEntries = @()
    foreach ($attempt in $SuspiciousAttempts) {
        $user = $attempt.Name
        $count = $attempt.Count
        $timestamps = ($attempt.Group | Select-Object -ExpandProperty TimeGenerated) -join ", "
        $ipAddresses = ($attempt.Group | Select-Object -ExpandProperty IPAddress) -join ", "

        $logEntry = @{
            User          = $user
            AttemptCount  = $count
            Timestamps    = $timestamps
            IPAddresses   = $ipAddresses
        }
        $logEntries += $logEntry
    }

    $message = "Potential brute-force attack detected: " + ($logEntries | ConvertTo-Json -Depth 3)
    
    # Write to event log
    $logSource = "SecurityAlertScript"
    if (-not [System.Diagnostics.EventLog]::SourceExists($logSource)) {
        New-EventLog -LogName Application -Source $logSource
    }
    Write-EventLog -LogName Application -Source $logSource -EntryType Warning -EventId 3001 -Message $message

    # Optionally, write to a log file with timestamp
    $logTimestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'  # Format to include date and time
    $logFile = "C:\Users\mrkdwn\Documents\log_$logTimestamp.txt"
    $logContent = "${logTimestamp}: ${message}"
    Add-Content -Path $logFile -Value $logContent

    Write-Host "Alert logged: $message"

    # Create PopUp Alert using Windows Forms
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Security Alert"
    $form.Width = 400
    $form.Height = 200
    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Potential brute-force attack detected! View the logs here."
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point(50,30)
    $form.Controls.Add($label)
    
    # Button to Open/View Log File
    $button = New-Object System.Windows.Forms.Button
    $button.Text = "View Here"
    $button.Location = New-Object System.Drawing.Point(150,80)
    $button.Add_Click({
        Start-Process "notepad.exe" -ArgumentList $logFile
        $form.Close()
    })
    $form.Controls.Add($button)

    # Show the form
    $form.ShowDialog()
    
    # Write to event log
    $logSource = "SecurityAlertScript"
    if (-not [System.Diagnostics.EventLog]::SourceExists($logSource)) {
        New-EventLog -LogName Application -Source $logSource
    }
    Write-EventLog -LogName Application -Source $logSource -EntryType Warning -EventId 3001 -Message $message
    
    # Optionally, write to a log file
    $logFile = "C:\Users\mrkdwn\Documents\log.txt"
    $logTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logContent = "${logTimestamp}: ${message}"
    Add-Content -Path $logFile -Value $logContent
    
    Write-Host "Alert logged: $message"
} else {
    Write-Host "No suspicious activity detected"
}
