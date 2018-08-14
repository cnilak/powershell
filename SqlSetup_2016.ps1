#Step 1:
#Check drive/lun information on the server, it should be 64 KB, if not! reconfigure it maually using ServerManager/DiskManager.
Get-SQLServerDiskInfo -dbServer $SqlNode

#Step 2:
#Create a new MOF file
cd c:\temp
ConfigNFCU_SQLSetup2016 -InstanceName $SqlNode  -LoginCredential $ShackleCred  -ServiceAccountCredential $SQLserverSVCCred -SqlInstallCredential $dbaCred -OutputPath c:\Temp -Verbose -ConfigurationData $ConfigurationData

#Step 3:
#Copy-modules to the target server.
Copy-SQLModules -targetServer $SqlNode -Verbose

#Step 4:
#Deploy the MOF file
$config = Start-DscConfiguration -ComputerName $SqlNode -Force -Path .\ -Wait -Verbose

#Step 5: 
#you may get a message in the log "[] A reboot is required to progress further. Please reboot the system.", please run below script to reboot the server.
Restart-Computer $SqlNode -Verbose

#Step 6:
#Once the server is backonline, you now re-run step 4 again.

#Step7
#Install TDP
Install-TSM -dbServer $SqlNode -isCluster $False -Verbose -ErrorAction Continue
