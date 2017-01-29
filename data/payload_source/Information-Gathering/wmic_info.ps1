$Info = wmic PROCESS GET CSName,Description,ExecutablePath,ProcessId /Format:HTABLE
$Info += wmic SERVICE GET Caption,Name,PathName,ServiceType,Started,StartMode,StartName /Format:HTABLE
$Info += wmic USERACCOUNT LIST FULL /Format:HTABLE
$Info += wmic GROUP LIST FULL /Format:HTABLE
$Info += wmic NICCONFIG WHERE IPEnabled='true' GET Caption,DefaultIPGateway,Description,DHCPEnabled,DHCPServer,IPAddress,IPSubnet,MACAddress /Format:HTABLE
$Info += wmic VOLUME GET Label,DeviceID,DriveLetter,FileSystem,Capacity,FreeSpace /Format:HTABLE
$Info += wmic NETUSE LIST FULL /Format:HTABLE
$Info += wmic QFE GET Caption,Description,HotFixID,InstalledOn /Format:HTABLE
$Info += wmic STARTUP GET Caption,Command,Location,User /Format:HTABLE
$Info += wmic PRODUCT GET Description,InstallDate,InstallLocation,PackageCache,Vendor,Version /Format:HTABLE
$Info += wmic OS GET Name,Version,InstallDate,LastBootUpTime,LocalDateTime,Manufacturer,RegisteredUser,ServicePackMajorVersion,SystemDirectory /Format:HTABLE
$Info += wmic TIMEZONE GET DaylightName,Description,StandardName /Format:HTABLE
