# IR-011 | PowerShell Account Discovery Detection
# Source: Sysmon Event ID 1
# ATT&CK: T1087.001 (Local Account), T1069.001 (Local Groups)
# This is the lab-validated detection logic; not a production-grade rule.
$start = (Get-Date).AddDays(-1)
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
    StartTime = $start
} -ErrorAction SilentlyContinue
$alerts = foreach ($event in $events) {
    [xml]$xml = $event.ToXml()
    $fields = @{}
    foreach ($item in $xml.Event.EventData.Data) {
        $fields[$item.Name] = $item.'#text'
    }
    $cmd = [string]$fields.CommandLine
    $image = [string]$fields.Image
    if (
        $image -match '(?i)\\(?:powershell|pwsh)\.exe$' -and
        $cmd -match '(?i)\b(Get-LocalUser|Get-LocalGroup|net\s+(user|localgroup))\b'
    ) {
        [PSCustomObject]@{
            TimeCreated = $event.TimeCreated
            EventID = $event.Id
            Detection = 'PowerShell Account Discovery'
            Severity = 'Medium'
            Image = $image
            CommandLine = $cmd
            ParentImage = $fields.ParentImage
            User = $fields.User
            ProcessGuid = $fields.ProcessGuid
        }
    }
}
$alerts | Format-List
Write-Host "IR-011 detection complete. Alerts: $(@($alerts).Count)"
