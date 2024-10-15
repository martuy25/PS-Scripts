# Loading Windows Forms Assembly
Add-Type -AssemblyName System.Windows.Forms

# Time Window that checks for the last 24 hours
$StartDate = (Get-Date).AddDays(-1)

# Grabbing failed logon attempts by checking event logs ID codes
$FailedLogons = Get-EventLog -LogName Security -InstanceId 4625 -After $StartDate |
    Select-Object TimeGenerated,
        @{Name="User";Expression={($_.ReplacementStrings[5])}}

# Viewing failed logon attempts
$FailedLogons | Out-GridView

$CsvFile = "FailedLogons-$(Get-Date -Format yyyyMMdd).csv"
$FailedLogons | Export-Csv -NoTypeInformation -Path $CsvFile

Write-Host "Failed logons report exported to $CsvFile"

# Threshold for failed sign on events
$Threshold = 2
$SuspiciousAttempts = $FailedLogons | Group-Object User | Where-Object {$_.Count -ge $Threshold}

if ($SuspiciousAttempts.Count -gt 0) {
    Write-Host "Potential attack detected!" -ForegroundColor Red

    # Create PopUp Alert via Windows Forms
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Security Alert"
    $form.Width = 400
    $form.Height = 200
    # Create label for message
    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Potential brute-force attack detected! View the logs here."
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point(50,30)
    $form.Controls.Add($label)
    # Create button to Open Event Viewer
    $button = New-Object System.Windows.Forms.Button
    $button.Text = "Open Event Viewer"
    $button.Location = New-Object System.Drawing.Point(50,80)
    $button.Add_Click({
        Start-Process "eventvwr.msc"
        $form.Close()
    })
    $form.Controls.Add($button)

    # Create button to Close
    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = "Close"
    $closeButton.Location = New-Object System.Drawing.Point(250, 80)
    $closeButton.Add_Click({
        $form.Close()
    })
    $form.Controls.Add($closeButton)

    # Show the form
    $form.ShowDialog()
} else {
    Write-Host "No suspicious activity detected"
}
