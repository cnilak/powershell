#testing code in github

$dbaCred = get-credential
$nodList = @('SWPDCRVAMGDB02','SWWDCRVAMGDB02','SWSDHRVAMGDB02')

$nodList | % {
$SqlNode = $_
$ConfigurationData = @{
    AllNodes = @(
        @{
            # The "*" means "all nodes named in ConfigData" so we don't have to repeat ourselves
            NodeName="*"
            PSDscAllowDomainUser = $true
            PSDscAllowPlainTextPassword = $true
        },
        #however, each node still needs to be explicitly defined for "*" to have meaning
        @{
            NodeName = $SqlNode
            Role     = 'SingleNode'
            Environment = 'PROD' #INTG,QUAL,PERF,CONTROL,SNDBOX,PROD,DR
            SQLEdition = 'ENT'  #STD,ENT
            SourceFolder = 'SQL2014Ent'
            ServiceComponents = 'SQLENGINE'
            ProgramFolder = 'MSSQL12.MSSQLSERVER'
        }
    )
}
Configuration ConfigNFCU_SQLSetup2014 {
   param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $ServiceAccountCredential,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SqlInstallCredential,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $LoginCredential
    )
    Import-DscResource –ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName SqlServerDsc

    Node $AllNodes.NodeName {
        #region Install prerequisites for SQL Server
        WindowsFeature 'NetFramework35'
        {
            Name   = 'NET-Framework-Core'            
            Ensure = 'Present'
        }

        WindowsFeature 'NetFramework45'
        {
            Name   = 'NET-Framework-45-Core'
            Source = '\\SWVDCLVSNDBDB01\j$\software\dotNetFx45_Full_setup.exe' # Assumes built-in Everyone has read permission to the share and path.
            Ensure = 'Present'
        } 
        File SQLDirectoryCopy
        {
            Ensure = "Present"  # You can also set Ensure to "Absent"
            Type = "Directory" # Default is "File".
            Recurse = $true # Ensure presence of subdirectories, too
            SourcePath = "\\SWVDCLVSNDBDB01\software\$($Node.SourceFolder)"              
            DestinationPath = "J:\Temp\$($Node.SourceFolder)"
            PsDscRunAsCredential = $SqlInstallCredential
            Credential = $SqlInstallCredential
        }
        
        File SQLScriptsCopy
        {
            Ensure = "Present"  # You can also set Ensure to "Absent"
            Type = "Directory" # Default is "File".
            Recurse = $true # Ensure presence of subdirectories, too
            SourcePath = "\\svr-sndbx08\DBAScripts\SqlSetupScripts"            
            DestinationPath = "J:\Temp\SqlSetupScripts"
            PsDscRunAsCredential = $SqlInstallCredential
            Credential = $SqlInstallCredential
        }        
        File SQLCMDCopy
        {
            Ensure = "Present"  # You can also set Ensure to "Absent"
            Type = "Directory" # Default is "File".
            Recurse = $true # Ensure presence of subdirectories, too
            SourcePath = "\\swvdclvsndbdb01.nfcu.net\software\userIDnew"            
            DestinationPath = "D:\SQLCommand"
            PsDscRunAsCredential = $SqlInstallCredential
            Credential = $SqlInstallCredential
        }        
        #endregion Install prerequisites for SQL Server
        #single instance
        #region Install SQL Server        
        SqlSetup 'InstallDefaultInstance'
        {  
            InstanceName         = 'MSSQLSERVER'
            Features             = 'SQLENGINE'
            SQLCollation         = 'SQL_Latin1_General_CP1_CI_AS'
            SQLSvcAccount        = $ServiceAccountCredential
            AgtSvcAccount        = $ServiceAccountCredential
            SQLSysAdminAccounts  = 'NFCU\SQL_Admin_UG', $SqlInstallCredential.UserName
            InstallSharedDir     = 'D:\Program Files\Microsoft SQL Server'
            InstallSharedWOWDir  = 'D:\Program Files (x86)\Microsoft SQL Server'
            InstanceDir          = 'D:\Program Files\Microsoft SQL Server'
            InstallSQLDataDir    = "G:\$($AllNodes.ProgramFolder)\MSSQL\DATA"
            SQLUserDBDir         = "G:\$($AllNodes.ProgramFolder)\MSSQL\DATA"
            SQLUserDBLogDir      = "I:\$($AllNodes.ProgramFolder)\MSSQL\TLog"
            SQLTempDBDir         = "E:\$($AllNodes.ProgramFolder)\MSSQL\DATA"
            SQLTempDBLogDir      = "E:\$($AllNodes.ProgramFolder)\MSSQL\TLog"
            SQLBackupDir         = "J:\$($AllNodes.ProgramFolder)\MSSQL\Backup"
            SourcePath           = "J:\Temp\$($AllNodes.SourceFolder)"
            UpdateEnabled        = 'False'
            ForceReboot          = $True
            PsDscRunAsCredential = $SqlInstallCredential
            DependsOn            = '[WindowsFeature]NetFramework35', '[WindowsFeature]NetFramework45','[File]SQLDirectoryCopy'
        }

        SqlScript SqlConfigScript1
        {
            ServerInstance       = $AllNodes.NodeName
            SetFilePath          = '\\SWVDCLVSNDBDB01\software\StandardSQLConfigurationScript.sql'
            TestFilePath         = '\\SWVDCLVSNDBDB01\software\StandardSQLConfigurationScript.sql'
            GetFilePath          = '\\SWVDCLVSNDBDB01\software\StandardSQLConfigurationScript.sql'
            Variable             = @('FilePath=J:\temp\SqlSetupScripts\log')
            PsDscRunAsCredential = $SqlInstallCredential
            DependsOn            = '[SqlSetup]InstallDefaultInstance'

        }
        SqlScript SqlConfigScript2
        {
            ServerInstance       = $AllNodes.NodeName
            SetFilePath          = '\\SWVDCLVSNDBDB01\software\StandardSQLConfigurationScriptAddition.sql'
            TestFilePath         = '\\SWVDCLVSNDBDB01\software\StandardSQLConfigurationScriptAddition.sql'
            GetFilePath          = '\\SWVDCLVSNDBDB01\software\StandardSQLConfigurationScriptAddition.sql'
            Variable             = @('FilePath=J:\temp\SqlSetupScripts\log')
            PsDscRunAsCredential = $SqlInstallCredential
            DependsOn            = '[SqlSetup]InstallDefaultInstance', '[SqlScript]SqlConfigScript1'

        }
        SqlScript SqlConfigScript3
        {
            ServerInstance       = $AllNodes.NodeName
            SetFilePath          = '\\SWVDCLVSNDBDB01\software\userIDnew\sp_LoginsTm.sql'
            TestFilePath         = '\\SWVDCLVSNDBDB01\software\userIDnew\sp_LoginsTm.sql'
            GetFilePath          = '\\SWVDCLVSNDBDB01\software\userIDnew\sp_LoginsTm.sql'
            Variable             = @('FilePath=J:\temp\SqlSetupScripts\log')
            PsDscRunAsCredential = $SqlInstallCredential
            DependsOn            = '[SqlSetup]InstallDefaultInstance', '[SqlScript]SqlConfigScript2'

        }
        SqlScript SqlConfigScript4
        {
            ServerInstance       = $AllNodes.NodeName
            SetFilePath          = '\\SWVDCLVSNDBDB01\software\userIDnew\gensql.sql'
            TestFilePath         = '\\SWVDCLVSNDBDB01\software\userIDnew\gensql.sql'
            GetFilePath          = '\\SWVDCLVSNDBDB01\software\userIDnew\gensql.sql'
            Variable             = @('FilePath=J:\temp\SqlSetupScripts\log')
            PsDscRunAsCredential = $SqlInstallCredential
            DependsOn            = '[SqlSetup]InstallDefaultInstance', '[SqlScript]SqlConfigScript3'

        }
        File TSMInstallDirectory
        {
            Ensure = "Present"  # You can also set Ensure to "Absent"
            Type = "Directory" # Default is "File".
            SourcePath = "\\svr-sndbx08\dbascripts\TSM-TDP 8.1.4"
            DestinationPath = "J:\Temp\TSM-TDP 8.1.4"
            Recurse = $True
            PsDscRunAsCredential = $SqlInstallCredential
            Credential = $SqlInstallCredential
            Force = $True
        }        
        File SSMSInstallFile
        {
            Ensure = "Present"  # You can also set Ensure to "Absent"
            Type = "Directory" # Default is "File".
            Recurse = $True # Ensure presence of subdirectories, too
            SourcePath = "\\SWVDCLVSNDBDB01\software\SQL2016_SSMS"            
            DestinationPath = "J:\Temp\SQL2016_SSMS"
            PsDscRunAsCredential = $SqlInstallCredential
            Credential = $SqlInstallCredential
        } 
        Package SSMS_2016
        {
            Ensure = "Present"
            Name = "Microsoft SQL Server Management Studio 2016"
            Path = "J:\Temp\SQL2016_SSMS\SSMS-Setup-ENU.exe"
            ProductId = "8833D818-8B1C-4F4C-8B9B-358DA3719F7C"
            LogPath = "J:\Temp\SQL2016_SSMS\InstallSSMS2016.log"
            Arguments = "/Install /silent /passive /promptrestart /log J:\Temp\SQL2016_SSMS\InstallSSMS2016.txt"            
            DependsOn = '[SqlSetup]InstallDefaultInstance','[File]SSMSInstallFile'
            PsDscRunAsCredential = $SqlInstallCredential
            Credential = $SqlInstallCredential
        }      
    }
}

    $securePwdSQLSvc = ConvertTo-SecureString -String (Get-SqlPlainPassword -pwdFile SQLSvc) -AsPlainText -Force
    $svcCred = New-Object System.Management.Automation.PSCredential ("NFCU\SQLSvc", $securePwdSQLSvc)

    $securePwdSQLserverSVC = ConvertTo-SecureString -String (Get-SqlPlainPassword -pwdFile SQLserverSVC) -AsPlainText -Force
    $SQLserverSVCCred = New-Object System.Management.Automation.PSCredential ("NFCU\SQLserverSVC", $securePwdSQLserverSVC)

    $securePwdShackle = ConvertTo-SecureString -String (Get-SqlPlainPassword -pwdFile shacklePROD) -AsPlainText -Force
    $ShackleCred = New-Object System.Management.Automation.PSCredential ("Shackle", $securePwdShackle)

    ConfigNFCU_SQLSetup2014 -InstanceName $SqlNode  -LoginCredential $ShackleCred  -ServiceAccountCredential $SQLserverSVCCred -SqlInstallCredential $dbaCred -OutputPath c:\Temp -Verbose -ConfigurationData $ConfigurationData
}
$nodList | % {
    #Copy-SQLModules -targetServer $_ -Verbose
    <#
    $targetServer = $_
    Get-ChildItem -Path "C:\Windows\assembly\GAC_MSIL" -Filter "*SqlServer*" -Recurse -Depth 1 | % {
        $folder = $_.Name
        Copy-Item -Path "C:\Windows\assembly\GAC_MSIL\$folder\13.0.0.0__89845dcd8080cc91" -Destination "\\$targetServer\C$\Windows\assembly\GAC_MSIL\$folder\" -Recurse -Force -Verbose
    }
    #>
    #Copy-Item -Path "C:\Windows\assembly\GAC_MSIL\Microsoft.SqlServer.ConnectionInfo\13.0.0.0__89845dcd8080cc91" -Destination "\\$_\C$\Windows\assembly\GAC_MSIL\Microsoft.SqlServer.ConnectionInfo\" -Recurse -Force -Verbose
    #Copy-Item -Path "C:\Windows\assembly\GAC_MSIL\Microsoft.SqlServer.Management.Sdk.Sfc\13.0.0.0__89845dcd8080cc91" -Destination "\\$_\C$\Windows\assembly\GAC_MSIL\Microsoft.SqlServer.Management.Sdk.Sfc\" -Recurse -Force -Verbose
    #Copy-Item -Path "C:\Windows\assembly\GAC_MSIL\Microsoft.SqlServer.SqlEnum\13.0.0.0__89845dcd8080cc91" -Destination "\\$_\C$\Windows\assembly\GAC_MSIL\Microsoft.SqlServer.SqlEnum\" -Recurse -Force -Verbose        
    #Copy-Item -Path "C:\Windows\assembly\GAC_MSIL\Microsoft.SqlServer.Smo" -Destination "\\$_\C$\Windows\assembly\GAC_MSIL\" -Recurse -Force -Verbose
    #Copy-Item -Path "C:\Windows\assembly\GAC_MSIL\Microsoft.SqlServer.SmoExtended" -Destination "\\$_\C$\Windows\assembly\GAC_MSIL\" -Recurse -Force -Verbose    
    #Copy-Item -Path "C:\Windows\assembly\GAC_MSIL\Microsoft.SqlServer.BatchParserClient" -Destination "\\$_\C$\Windows\assembly\GAC_MSIL\" -Recurse -Force -Verbose        
    #Copy-Item -Path "C:\Windows\assembly\GAC_MSIL\Microsoft.SqlServer.Dmf" -Destination "\\$_\C$\Windows\assembly\GAC_MSIL\" -Recurse -Force -Verbose        
    #Copy-Item -Path "C:\Windows\assembly\GAC_MSIL\Microsoft.SqlServer.SqlClrProvider" -Destination "\\$_\C$\Windows\assembly\GAC_MSIL\" -Recurse -Force -Verbose        
    Restart-Computer $_ -Force -Verbose
}
$config = Start-DscConfiguration -ComputerName SWPDCRVAMGDB02 -Force -Path .\ -Wait -Verbose
$config = Start-DscConfiguration -ComputerName SWWDCRVAMGDB02 -Force -Path .\ -Wait -Verbose
$config = Start-DscConfiguration -ComputerName SWSDHRVAMGDB02 -Force -Path .\ -Wait -Verbose

notepad "\\$SqlNode\C$\Program Files\Microsoft SQL Server\130\Setup Bootstrap\Log\Summary.txt"

notepad "\\SWVDCIVSPDB03\C$\Program Files\Microsoft SQL Server\130\Setup Bootstrap\Log\Summary.txt"

Get-WinEvent -ComputerName $SqlNode -LogName "Microsoft-Windows-Dsc/Operational" | select -First 10 -ExpandProperty Message

Install-TSM -dbServer $SqlNode -isCluster $True -Verbose -ErrorAction Continue

Restart-Computer $SqlNode -Verbose -Force

$msSQL = Get-WmiObject -ComputerName SVR-SNDBX08 -Class win32_service | ? {$_.Name -eq 'MSSQLSERVER'}
$msSQL = Get-WmiObject -ComputerName SVR-SNDBX08 -Class win32_service | ? {$_.Name -match 'SQL'} | Format-Table -wrap
Get-EventLog -LogName Application -ComputerName SVR-SNDBX08 -Newest 20 | ?{$_.Message -match 'service'}

$msSQL.StartName

Get-Service -ComputerName SVR-SNDBX08 -Name MSSQLSERVER -DependentServices -Verbose

Enter-PSSession -ComputerName SWVDCRVSQLDB12

Get-SQLPackageInfo -dbServer 'SWVDCIVSPDB04' -Verbose -ErrorAction Stop | ? {$_.DisplayName -match 'SQL Server 2016'} | Format-Table -Wrap
Get-SQLPackageInfo -dbServer SWVDCFVAPSPDB01 -Verbose -ErrorAction Stop | ? {$_.DisplayName -match 'IBM'} | Format-Table -Wrap




Enter-PSSession $SqlNode -EnableNetworkAccess 
Invoke-Expression "& `"J:\Temp\TSM-TDP 8.1.4\SP_DBS_8.1.4_DP_MS_SQL_ML.exe /Y`"" -Verbose

Invoke-Expression "& '\\svr-sndbx08\DBAScripts\TSM-TDP 8.1.4\SP_DBS_8.1.4_DP_MS_SQL_ML.exe'"

\\$SqlNode\TSMSQL_WIN\fcm\x64\mmc\8140\enu\IBM Spectrum Protect for Databases - MS SQL - Management Console.msi
\\$SqlNode\TSMSQL_WIN\fcm\x64\sql\8140\enu\IBM Spectrum Protect for Databases - MS SQL.msi

J:\Temp\TSM-TDP 8.1.4\

"\\SWVDCIVSPDB04\j`$\Temp\TSMSQL_WIN\fcm\x64\sql\8100\enu\IBM Spectrum Protect for Databases - MS SQL - Management Console.msi"

"\\SWVDCIVSPDB04\j`$\Temp\TSMSQL_WIN\fcm\x64\sql\8100\enu\IBM Spectrum Protect for Databases - MS SQL.msi"

'\\svr-sndbx08\DBAScripts\TSM-TDP 8.1.4\TSMSQL_WIN\fcm\x64\sql\8140\enu\IBM Spectrum Protect for Databases - MS SQL.msi'