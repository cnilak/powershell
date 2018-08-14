
if(-not (Get-Module -Name SqlServer)) {
    if(-not (Import-Module SqlServer)) {        
        Install-Module SqlServer -Verbose		
    }
}

function Get-SQLBackupInfo ([parameter (Mandatory=$true)][string]$dbName, [parameter (Mandatory=$true)][string]$dbServer) {
    $query = $query = ((Get-Content -Path \\SVR-SNDBX08\DBAScripts\Chita\sqlLib\GetBackupInfo.sql).Replace('<DBNAME>',$dbName)) | Out-String   
    Invoke-Sqlcmd -ServerInstance $dbServer -Database $dbName -Query $query -Verbose
}

function Remove-SQLFiles_old1 ([parameter (Mandatory=$true)][string]$dbServer, [parameter (Mandatory=$true)][string]$dbName, [parameter (Mandatory=$true)][string]$sqlUser, [parameter (Mandatory=$true)][string]$sqlPwd) {
    $fileInfo = Get-SQLDatabaseLogicalFileName -dbServer $dbServer -dbName $dbName
    $fileInfo | % {
        $phyName = $_.PhysicalFileName
        $query = "EXEC MASTER..XP_CMDSHELL 'powershell.exe ""ls $phyName""'"
        $result = Invoke-Sqlcmd -ServerInstance $dbServer -Database Master -Query $query   
        if($result) {
            $lastWriteDate = $result[7][0].Split("  ")[8]
            if([datetime]$lastWriteDate -lt (get-date).AddDays(-21)) {
                Write-Verbose "Deleting file: $($result[7][0]) .........."
                $query = "EXEC MASTER..XP_CMDSHELL 'del ""$phyName""'"
                #$result = Invoke-Sqlcmd -ServerInstance $dbServer -Database Master -Query $query   
                Write-Verbose "$query"
            }
        }
    }
}

function Remove-SQLFiles ([parameter (Mandatory=$true)][string]$dbServer, [parameter (Mandatory=$true)][string]$dbName, [parameter (Mandatory=$true)][string]$sqlUser, [parameter (Mandatory=$true)][string]$sqlPwd) {
    $dataPath = ((Get-SQLDataLogDefaultPath -dbServer $dbServer -sqlID $sqlUser -sqlPass $sqlPwd).DataPath).ToString().Replace(":","$")
    
    if(Test-Path \\$dbServer\$dataPath) {
        ls  \\$dbServer\$dataPath | ? {$_.Name -match $dbName} | Remove-Item -Verbose
        Write-Verbose "\\$dbServer\$dataPath\$dbName has been deleted"
    }

    $logPath = ((Get-SQLDataLogDefaultPath -dbServer $dbServer -sqlID $sqlUser -sqlPass $sqlPwd).LogPath).ToString().Replace(":","$")
    if(Test-Path \\$dbServer\$logPath) {
        ls  \\$dbServer\$logPath | ? {$_.Name -match $dbName} | Remove-Item -Verbose
        Write-Verbose "\\$dbServer\$logPath\$dbName has been deleted"
    }     
}

function Get-SQLDataLogDefaultPath ([parameter (Mandatory=$true)][string]$dbServer, [string]$sqlID, [string]$sqlPass) {
    $query = "
            SELECT DataPath = CONVERT(sysname, SERVERPROPERTY('InstanceDefaultDataPath')),
                 LogPath = CONVERT(sysname, SERVERPROPERTY('InstanceDefaultLogPath'));
            "
    if(($sqlPass -ne '') -and ($sqlID -ne ''))  {
        return (Invoke-Sqlcmd -ServerInstance $dbServer -Query $query -Database Master -Username $sqlID -Password $sqlPass -Verbose  )
     }
     else {
        return (Invoke-Sqlcmd -ServerInstance $dbServer -Query $query -Database Master -Verbose)
     }
}

##
function Remove-SQLDatabase ([parameter (Mandatory=$True)][string]$dbServer, [parameter (Mandatory=$True)][string]$dbName) {   
    
    #drop dbs
    $dbDrop = $dbName.Replace("'","")
    
    #check if it's in AVG  
    $avgName = (Get-SQLAvgInfo $dbServer | Select-Object -Property AVGName -Unique).AVGName
    $replicas = (Get-SQLAvgInfo $dbServer | Select-Object -Property Replicas -Unique).Replicas

    try {
        if($avgName -ne $null) {  
            $queryAvg = "
                USE [master] 
                ALTER AVAILABILITY GROUP $AvgName REMOVE DATABASE [$dbDrop]
            "
            Invoke-Sqlcmd -ServerInstance $dbServer -Query $queryAvg  -Verbose
            Write-Verbose "Dropped Database: $dbName from AVG Group: $avgName"
            $dbServer = $replicas
        }

        #drop database
        $query1 = "    
            USE master
            ALTER DATABASE [$dbDrop] SET  SINGLE_USER WITH ROLLBACK IMMEDIATE
            GO
            USE [master]
            GO
            DROP DATABASE [$dbDrop]
            GO                 
          "
        $dbServer | % {
            Invoke-Sqlcmd -ServerInstance $_ -Query $query1  -Verbose
            Write-Verbose "Database: $dbName has been dropped"    
            #remove db files    
            Remove-SQLFiles -dbServer $_ -dbName $dbName    
        }    
    }
    catch {
        Write-Host ($_.Exception.Message), Failed item: ($_.Exception.ItemName) -ForegroundColor Magenta
    }
}

function Get-SQLServerInfo ([parameter (Mandatory=$true)][string]$serverName) {
    $result = Invoke-Sqlcmd -ServerInstance SVR-SNDBX08 -InputFile \\SVR-SNDBX08\DBAScripts\Chita\sqlLib\ServerInfo.sql | ? {$_.ServerName -like $serverName} 
    if(-not $result ) {
        $result = Invoke-Sqlcmd -ServerInstance SVR-SNDBX08 -InputFile \\SVR-SNDBX08\DBAScripts\Chita\sqlLib\ServerOnlyInfo.sql | ? {$_.ServerName -like $serverName} 
    }
    return $result
}

function ConvertTo-GB ($bytes) {
    ([int](((($bytes)/1024)/1024)/1024)).ToString() + 'GB'
}
function Get-SQLServerDiskInfo ($dbServer) {
    Invoke-Command -ComputerName $dbServer -ScriptBlock  {   
        $wql = "SELECT Label, Blocksize, Name, Capacity, FreeSpace FROM Win32_Volume WHERE FileSystem='NTFS'"
        Get-WmiObject -Query $wql -ComputerName $Using:dbServer | Select-Object Label, Blocksize, Name, @{Name="Capacity"; Expression = {([int](((($_.Capacity)/1024)/1024)/1024)).ToString() + 'GB'}},  @{Name="FreeSpace"; Expression = {([int](((($_.FreeSpace)/1024)/1024)/1024)).ToString() + 'GB'}} | Format-Table -AutoSize
    }
}

function Get-SQLServerDotNetFeature ([parameter (Mandatory=$true)][string]$dbServer) {
    Invoke-Command -ComputerName $dbServer -ScriptBlock  { 
        Get-WindowsFeature -Name NET-Framework-Features
    }
}


function Add-SQLDatabaseToAvg ([parameter (Mandatory=$true)][string]$avgName, [parameter (Mandatory=$true)][string]$dbServer,[parameter (Mandatory=$true)][string]$dbName) {
    $query = ((Get-Content -Path \\SVR-SNDBX08\DBAScripts\Chita\NodeOneAddToAVG.sql).Replace('<AVGNAME>',$avgName)).Replace('<DBNAME>',$dbName) | Out-String   
    Write-Host $query -ForegroundColor Cyan
    Invoke-Sqlcmd -ServerInstance $dbServer -Database Master -Query $query -Verbose
}
function Join-SQLDatabaseToAvg ([parameter (Mandatory=$true)][string]$avgName, [parameter (Mandatory=$true)][string]$dbServer,[parameter (Mandatory=$true)][string]$dbName) {
    $query = ((Get-Content -Path \\SVR-SNDBX08\DBAScripts\Chita\NodeTwoAddToAVG.sql).Replace('<AVGNAME>',$avgName)).Replace('<DBNAME>',$dbName) | Out-String   
    Write-Host $query -ForegroundColor Cyan
    Invoke-Sqlcmd -ServerInstance $dbServer -Database Master -Query $query -Verbose
}

function Get-SQLDatabaseBackupDir ([parameter (Mandatory=$true)][string]$dbServer) {
     $query = "
    EXEC  master.dbo.xp_instance_regread  
     N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer',N'BackupDirectory'
     "
    return (Invoke-Sqlcmd -ServerInstance $dbServer -Database Master -Query $query).Data 

}


function Get-SQLDatabaseLogicalFileName ([parameter (Mandatory=$true)][string]$dbServer, [parameter (Mandatory=$true)][string]$dbName) {
$query = "
SELECT DB_NAME(database_id) AS DatabaseName, name AS LogicalFileName, physical_name AS PhysicalFileName 
FROM sys.master_files AS mf
where DB_NAME(database_id) = '$dbName'
"
return (Invoke-Sqlcmd -ServerInstance $dbServer -Query $query -Database Master -Verbose)

}


function Backup-RestoreSQLDatabase ([parameter(Mandatory=$true)][string]$dbPrimaryServer, [parameter(Mandatory=$true)][string]$dbSecondaryServer, [parameter(Mandatory=$true)][string]$dbName, [switch] $Recover, [switch] $NoLog) {
    
    $backupDirPrimaryServer = Get-SQLDatabaseBackupDir -dbServer $dbPrimaryServer
    $backupDirSecondaryServer = Get-SQLDatabaseBackupDir -dbServer $dbSecondaryServer

    $backupDBFile = $dbName + '_' + (Get-Date -UFormat '%m_%d_%y') + '.bak'
    $backupTranFile = $dbName + '_' + (Get-Date -UFormat '%m_%d_%y') + '.trn'

    
    $DatabaseBackupFilePrimaryServer = "$backupDirPrimaryServer\$backupDBFile"
    $LogBackupFilePrimaryServer = "$backupDirPrimaryServer\$backupTranFile"

    $DatabaseBackupFileSecondaryServer = "$backupDirSecondaryServer\$backupDBFile"
    $LogBackupFileSecondaryServer = "$backupDirSecondaryServer\$backupTranFile"
    
    #creating backup on primary node
    $query = ((Get-Content -Path \\SVR-SNDBX08\DBAScripts\Chita\NodeOneBackup.sql).Replace('<BAKFILELOCATION>',$DatabaseBackupFilePrimaryServer)).Replace('<TRNFILELOCATION>',$LogBackupFilePrimaryServer).Replace('<DBNAME>',$dbName) | Out-String   
    Write-Host $query -ForegroundColor Cyan
    Invoke-Sqlcmd -ServerInstance $dbPrimaryServer -Database Master -Query $query -ConnectionTimeout ([int]::MaxValue) -Verbose

    if(-not $NoLog) {
        #creating log backup on primary node
        $query = ((Get-Content -Path \\SVR-SNDBX08\DBAScripts\Chita\NodeOneLogBackup.sql).Replace('<BAKFILELOCATION>',$DatabaseBackupFilePrimaryServer)).Replace('<TRNFILELOCATION>',$LogBackupFilePrimaryServer).Replace('<DBNAME>',$dbName) | Out-String   
        Write-Host $query -ForegroundColor Cyan
        Invoke-Sqlcmd -ServerInstance $dbPrimaryServer -Database Master -Query $query -ConnectionTimeout ([int]::MaxValue) -Verbose
    }

    #copy files on secondary node
    #copy of db file
    Copy-Item ('\\' + $dbPrimaryServer + '\' + $backupDirPrimaryServer.Replace(":","$") + '\' + $backupDBFile) -Destination ('\\' + $dbSecondaryServer + '\' + $backupDirSecondaryServer.Replace(":","$") + '\' + $backupDBFile) -Verbose -Force      

    if(-not $NoLog) {
        #copy of trn file
        Copy-Item ('\\' + $dbPrimaryServer + '\' + $backupDirPrimaryServer.Replace(":","$") + '\' + $backupTranFile) -Destination ('\\' + $dbSecondaryServer + '\' + $backupDirSecondaryServer.Replace(":","$") + '\' + $backupTranFile) -Verbose -Force   
    }
    #restore backup on secondary node
    <#
    $query = ((Get-Content -Path \\SVR-SNDBX08\DBAScripts\Chita\NodeTwoRestore.sql).Replace('<BAKFILELOCATION>',$DatabaseBackupFileSecondaryServer)).Replace('<TRNFILELOCATION>',$LogBackupFileSecondaryServer).Replace('<DBNAME>',$dbName) | Out-String   
    Write-Host $query -ForegroundColor Cyan
    Invoke-Sqlcmd -ServerInstance $dbSecondaryServer -Database Master -Query $query -Verbose  
    #>

    #get target server file path
    $defaultPath = Get-SQLDataLogDefaultPath -dbServer $dbSecondaryServer
    $dbTargetPath = $defaultPath.DataPath
    $logTargetPath = $defaultPath.LogPath

    #get logical name of the database to be moved from the source server
    $logicName = Get-SQLDatabaseLogicalFileName -dbServer $dbPrimaryServer -dbName $dbName
    $dbLogicName  = ($logicName | ? {$_.PhysicalFileName -match '.mdf'}).LogicalFileName
    $logLogicName  = ($logicName | ? {$_.PhysicalFileName -match '.ldf'}).LogicalFileName

    #create relocate path
    $RelocateData = New-Object Microsoft.SqlServer.Management.Smo.RelocateFile("$dbLogicName", "$dbTargetPath$dbLogicName.mdf")
    $RelocateLog = New-Object Microsoft.SqlServer.Management.Smo.RelocateFile("$logLogicName", "$logTargetPath$logLogicName.ldf")
    
    #restore
    Restore-SqlDatabase -ServerInstance $dbSecondaryServer -ConnectionTimeout ([int]::MaxValue) -Database $dbName -ReplaceDatabase -BackupFile $DatabaseBackupFileSecondaryServer  -RelocateFile @($RelocateData,$RelocateLog) -NoRecovery -Verbose 
    
    #log restore
    if(-not $NoLog) {
        Restore-SqlDatabase -ServerInstance $dbSecondaryServer -ConnectionTimeout ([int]::MaxValue) -Database $dbName -ReplaceDatabase -BackupFile $LogBackupFileSecondaryServer  -RestoreAction Log -NoRecovery  -Verbose
    }

    #Recover
    if($Recover) {
        Invoke-Sqlcmd -ServerInstance $dbSecondaryServer -Query "restore database [$dbName] with recovery" -Database Master -ConnectionTimeout ([int]::MaxValue) -Verbose
    }
}

function New-DatabaseToAVG ([Parameter(Mandatory=$True)][string]$dbPrimaryServer, [Parameter(Mandatory=$True)][string]$dbSecondaryServer, [Parameter(Mandatory=$True)][string]$avgName, [Parameter(Mandatory=$True)][string]$dbName, [switch]$useTSM) {            
    Add-SQLDatabaseToAvg -avgName $avgName -dbServer $dbPrimaryServer -dbName $dbName
    if($useTSM) {        
        Backup-TSMSQLDatabase -dbServer $dbPrimaryServer -dbName $dbName -backupType Full -stripes 6 -alwaysOn -ErrorAction Stop
        Restore-TSMSQLBackupPIT -dbServer $dbPrimaryServer -dbTargetServer $dbSecondaryServer -dbName $dbName -noRecovery  -ErrorAction Stop
    } else {
        Backup-RestoreSQLDatabase -dbPrimaryServer $dbPrimaryServer -dbSecondaryServer $dbSecondaryServer -dbName $dbName  
    }
    Join-SQLDatabaseToAvg -avgName $avgName -dbServer $dbSecondaryServer -dbName $dbName
}

function Copy-SQLDatabase ([Parameter(Mandatory=$True)][string]$dbSourceServer, [Parameter(Mandatory=$True)][string]$dbTargetServer, [Parameter(Mandatory=$True)][string]$dbName) {
    Backup-RestoreSQLDatabase -dbPrimaryServer $dbSourceServer -dbSecondaryServer $dbTargetServer -dbName $dbName -Recover -NoLog
}

function Test-SQLDatabase 
{
    param( 
    [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True)] [string] $Server,
    [Parameter(Position=1, Mandatory=$True)] [string] $Database,
    [Parameter(Position=2, Mandatory=$True, ParameterSetName="SQLAuth")] [string] $Username,
    [Parameter(Position=3, Mandatory=$True, ParameterSetName="SQLAuth")] [string] $Password,
    [Parameter(Position=2, Mandatory=$True, ParameterSetName="WindowsAuth")] [switch] $UseWindowsAuthentication
    )

    # connect to the database, then immediatly close the connection. If an exception occurrs it indicates the conneciton was not successful. 
    process { 
        $dbConnection = New-Object System.Data.SqlClient.SqlConnection
        if (!$UseWindowsAuthentication) {
            $dbConnection.ConnectionString = "Data Source=$Server; uid=$Username; pwd=$Password; Database=$Database;Integrated Security=False"
            $authentication = "SQL ($Username)"
        }
        else {
            $dbConnection.ConnectionString = "Data Source=$Server; Database=$Database;Integrated Security=True;"
            $authentication = "Windows ($env:USERNAME)"
        }
        try {
            $connectionTime = measure-command {$dbConnection.Open()}
            $Result = @{
                Connection = "Successful"
                ElapsedTime = $connectionTime.TotalSeconds
                Server = $Server
                Database = $Database
                User = $authentication}
        }
        # exceptions will be raised if the database connection failed.
        catch {
                $Result = @{
                Connection = "Failed"
                ElapsedTime = $connectionTime.TotalSeconds
                Server = $Server
                Database = $Database
                User = $authentication}
        }
        Finally{
            # close the database connection
            $dbConnection.Close()
            #return the results as an object
            $outputObject = New-Object -Property $Result -TypeName psobject
            write-output $outputObject 
        }
    }
}

function Set-SQLServiceCrentials ([Parameter(Mandatory=$True)][string]$serviceName, [Parameter(Mandatory=$True)][string]$dbServer, $credential) {
    \\svr-sndbx08\DBAScripts\Chita\Modules\Set-ServiceCredential.ps1 -ServiceName $serviceName -ComputerName $dbServer -ServiceCredential $credential -Verbose 
    Write-Host "Credentials for Service:$serviceName changed successfully on server:'$dbServer' " -ForegroundColor Green
}

function Update-SQLUserPassword ([Parameter(Mandatory=$True)][string]$dbServer,[Parameter(Mandatory=$True)][string]$login,[Parameter(Mandatory=$True)][string]$password ) {
    #Load the SQL Server SMO Assemly
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null

    #Create a new SMO instance for this $ServerName
    $srv = New-Object "Microsoft.SqlServer.Management.Smo.Server" $dbServer

    #Find the SQL Server Login and Change the Password
    $SQLUser = $srv.Logins | ? {$_.Name -eq "$login"};
    $SQLUser.ChangePassword($password);
    $SQLUser.PasswordPolicyEnforced = 1;
    $SQLUser.Alter();
    $SQLUser.Refresh();
    Write-Host "Password for Login:'$login' changed successfully on server:'$dbServer' " -ForegroundColor Green
}

function Restart-SQLService ([Parameter(Mandatory=$True)][string]$dbServer) {
    Get-Service -ComputerName $dbServer -Name MSSQLSERVER | Stop-Service -Force -Verbose 
    Get-Service -ComputerName $dbServer -Name MSSQLSERVER | Start-Service -Verbose
    Get-Service -ComputerName $dbServer -Name MSSQLSERVER -DependentServices | Start-Service -Verbose 4>&1 
}

function Get-SQLADGroupMember ([Parameter(Mandatory=$True)][string]$groupName) {
    Invoke-Command -ComputerName SWHADCRVSQLDBA -ScriptBlock {
        Import-Module ActiveDirectory -Verbose
        Get-ADGroupMember  -Identity Get-ADGroupMember $Using:groupName -Verbose 4>&1 
    }
}
function Get-SQLDatabasePermissions ([Parameter(Mandatory=$True)][string]$dbServer, [Parameter(Mandatory=$True)][string]$dbDatabase) {
    Invoke-Sqlcmd -ServerInstance $dbServer -InputFile \\SVR-SNDBX08\DBAScripts\Chita\sqlLib\GetDatabasePermissionMap.sql -Database $dbDatabase -Verbose 4>&1 
}

function Export-SQLServerCertificate {
    Get-ChildItem Cert:\localmachine\My -Verbose | Where-Object { $_.hasPrivateKey } |  Foreach-Object {
            &certutil.exe @('-exportpfx', '-p', 'secret',  $_.Thumbprint, "$($_.Subject).pfx")
         }  
}

<#
    .SYNOPSIS 
    Add a missing login from source server to target server for databases.
    
    .DESCRIPTION
    Add a missing login from source server to target server for databases.

    .EXAMPLE	 
    Add-SQLMissingLogins -dbSourceServer SWVDCRVDELTDB01 -dbTargetServer SWVDCRVDELTDB02 -dbName TDR_NFCU
	*This example adds missing login for TDR_NFCU database after it was moved from SWVDCRVDELTDB01 ==> SWVDCRVDELTDB02
#>
function Add-SQLMissingLogins  ([Parameter(Mandatory=$True)][string]$dbSourceServer, [Parameter(Mandatory=$True)][string]$dbTargetServer, [Parameter(Mandatory=$True)][string]$dbName) {
    $userList = Invoke-Sqlcmd -ServerInstance $dbTargetServer -InputFile \\SVR-SNDBX08\DBAScripts\Chita\sqlLib\GetOrphanLoginInfo.sql -Database $dbName  -Verbose 4>&1    

    #Get orphan login from the source server and apply to the target server (primary node)
    $userList | Select-Object -Property user_name | ForEach-Object {
            $login = $_.user_name
            $query = "exec sp_help_revlogin '$login'"
            Write-Host $query -ForegroundColor Yellow
        
            #run the query on source server to generate create login script            
            Invoke-Sqlcmd -ServerInstance $dbSourceServer -Query $query -Verbose 4>&1 | Out-File c:\temp\tmpQuery.txt -Encoding string  -Verbose -Force
                         
            #run the query on the target 1st server to create the missing login.                
            try {
                ((Get-Content C:\TEMP\tmpQuery.txt).Replace("HQ\","NFCU\").Replace("No login(s) found.","").Replace("/* sp_help_revlogin script","").Replace("*/","").Replace("**","--")) | Set-Content -Path C:\TEMP\tmpQuery.txt -Force -Verbose                
                Invoke-Sqlcmd -ServerInstance $dbTargetServer -InputFile C:\TEMP\tmpQuery.txt -Verbose 4>&1  -ErrorAction Stop           
            }
            catch {
                #nothing
            }
    }
}
  <#
    .SYNOPSIS 
      Moves a SQL database using either SQL Local backup/restore or TSM
    
    .DESCRIPTION
      Moves a SQL database using either SQL Local backup/restore or TSM, supports all below four scenarios 
	   - Standalone ==> Standalone
       - Standalone ==> Availability group (including add database to AVG group)
       - Availability group ==> Availability group (including add database to AVG group)
       - Availability group ==> Standalone

    .EXAMPLE	 
    Move-SQLDatabase -dbServer SWVDCRVDBADB01 -dbTargetServer SWWDCRVDBADB01 -dbName ChitaGen1 -pointInTime (get-date).AddMinutes(-1) -Verbose
	*This example moves database name ChitaGen1 from SWVDCRVDBADB01 ==> SWWDCRVDBADB01 for point in time = -1 minute from the current datetime
    
    .EXAMPLE	
    Move-SQLDatabase -dbServer svr-sndbx08 -dbTargetServer SWVDCRVDBADB01 -dbName ChitaGen1 -addMissingLogins -addToAVG  -Verbose
	*This example moves database name ChitaGen1 from a single node svr-sndbx08 ==> SWVDCRVDBADB01 (cluster node) using the current system datetime,
    :if the node is in AVG then it will also add the database to AVG, if the -addToAVG parameter is not supplied, it will not add database to AVG group. 
    :if there are missing logins it will add those missing logins to the target server as well, if -addMissingLogins is not supplied, missing logs won't be added to the target server.
    : addMissingLogins, pointInTime, and addToAVG are optional parameters

    .EXAMPLE	     
    Move-SQLDatabase -dbServer svr-sndbx08 -dbTargetServer SWVDCRVDBADB01 -dbName ChitaGen1 -addMissingLogins -addToAVG  -Verbose
	*This example moves database name ChitaGen1 from a single node svr-sndbx08 ==> SWVDCRVDBADB01 (cluster node) using the current system datetime,
    :if the node is in AVG then it will also add the database to AVG 
    :if there are missing logins it will add those missing logins to the target server as well
    : addMissingLogins, pointInTime, and addToAVG are optional parameters

    .EXAMPLE	 
     $databaseList = @("ChitaGen1","ChitaENC1")
     $databaseList | ForEach-Object {Move-SQLDatabase -dbSourceServer svr-sndbx08 -dbTargetServer SWVDCRVDBADB01 -dbList $_  -Verbose}	 
     *This example moves multiple databases from a single node svr-sndbx08 ==> SWVDCRVDBADB01 (cluster node) using the current system datetime
      : if you want to add the databases to the AVG group, please use -addToAVG optional parameter
  #>

function Move-SQLDatabase ([parameter(Mandatory=$True)][string]$dbSourceServer,[parameter(Mandatory=$True)][string]$dbTargetServer, [parameter(Mandatory=$True)][string]$dbList, [Parameter(ParameterSetName='TSM')][switch] $useTSM, [Parameter(ParameterSetName='TSM')][datetime]$tsmPointInTime, [switch] $addMissingLogins,[switch] $addToAVG) {
    
    BEGIN {
        Write-Verbose "Starting the MOVE - SQL Database Process" 
        $Error.Clear()
    }
    PROCESS {
        #get avg info
        $dbTargetAVGName = Get-SQLAvgInfo -dbServer $dbTargetServer 

        #default value of pit
        if(-not $tsmPointInTime) {$tsmPointInTime = (get-date).AddSeconds(-10)}

        #Step1: Copy database from source to target (primary node)
        if($useTSM) {
            $dbList | % {Restore-TSMSQLBackupPIT -dbServer $dbSourceServer -dbTargetServer $dbTargetServer -dbName $_ -pointInTime $tsmPointInTime -ErrorAction Stop}
        } else {
            $dbList | ForEach-Object {Copy-SQLDatabase -dbSourceServer $dbSourceServer -dbTargetServer $dbTargetServer -dbName $_ -ErrorAction Stop}
        }

        #check if the database is in simple recovery mode and it needs to be added to AVG
        $dbList | % {
            $_dbName = $_
            $recModel = (Get-SQLDatabaseRecoveryModel -dbServer $dbTargetServer | ?{$_.name -eq $_dbName}).recovery_model_desc 
            if($recModel -eq "SIMPLE" -and $addToAVG) {
                #change recover mode to FULL
                Update-SQLDatabaseRecoveryModel -dbServer $dbTargetServer -dbName $_dbName -recoveryModel FULL -ErrorAction Stop -Verbose
            }
        }

        #Step2:
        #if target server has AVG and the add to AVG flag is used
        if($dbTargetAVGName -ne $null) {
            #take a full backup on the target node first before adding to the AVG        
            if($useTSM) {
                $dbList | ForEach-Object {Backup-TSMSQLDatabase -dbServer $dbTargetServer -dbName $_ -backupType Full -stripes 6 -alwaysOn -ErrorAction Stop}
            } else {
                $dbList | ForEach-Object {Backup-SqlDatabase -ServerInstance $dbTargetServer -Database $_ -BackupAction Database -Verbose}
            }

            if($addToAVG) {
                #Copy-database from primary node to secondary node and add it to the AVG.
                $dbList | ForEach-Object {New-DatabaseToAVG -dbPrimaryServer $dbTargetAVGName[0].Replicas -dbSecondaryServer $dbTargetAVGName[1].Replicas -avgName ($dbTargetAVGName[0].AVGName) -dbName $_  -ErrorAction Stop}
            }
        }
    
        #Step3: Identify orphan login and add them to target node
        if($addMissingLogins) {
            $dbList | ForEach-Object {
                Add-SQLMissingLogins -dbSourceServer $dbSourceServer -dbTargetServer $dbTargetServer -dbName $_
                Write-Verbose "successfully added the missing login to Primary node" 
            } 
        }
    }
    END {
        Write-Verbose -Message "Ending the MOVE - SQL Database Process"         
    }
}

function Get-SQLWhoIsActive ([Parameter(Mandatory=$True)][string]$dbServer) {
    $isExist = Invoke-Sqlcmd -ServerInstance $dbServer -Query "SELECT * FROM sys.objects WHERE type = 'P' AND name like '%WhoIsAct%'"
    if($isExist -eq $null) {
        #load store proc on the server
        Invoke-Sqlcmd -ServerInstance $dbServer -InputFile '\\svr-sndbx08\DBAScripts\Chita\sqlLib\who_is_active_v11_30.sql' -Verbose 4>&1 
    }
    #db file usage across dbs
    Invoke-Sqlcmd -ServerInstance $dbServer -InputFile '\\svr-sndbx08\DBAScripts\Chita\sqlLib\who_is_active' -Verbose 4>&1 
}
function Get-SQLAvgInfo ([Parameter(Mandatory=$True)][string]$dbServer) {
    Invoke-Sqlcmd -ServerInstance $dbServer -InputFile '\\svr-sndbx08\DBAScripts\Chita\sqlLib\GetAVGInfo.sql' -Verbose 4>&1 
}
function Get-SQLReplicaInfo ([Parameter(Mandatory=$True)][string]$dbServer) {
    Invoke-Sqlcmd -ServerInstance $dbServer -Query "select * from sys.availability_replicas" -Verbose 4>&1 
}

function Get-SQLDatbaseInfo ([Parameter(Mandatory=$True)][string]$dbName) {
    $query = ((Get-Content -Path \\SVR-SNDBX08\DBAScripts\Chita\sqlLib\GetDatabaseInfo.sql).Replace('<DBName>',$dbName)) | Out-String   
    Invoke-Sqlcmd -ServerInstance SWHADCRVSQLDBA  -Database DBAdmin -Query $query -Verbose 4>&1 
}
function Move-SQLDatabaseToAVG ([Parameter(Mandatory=$True)][string]$dbSourceServer,[Parameter(Mandatory=$True)][string]$dbTargetPrimaryServer,[Parameter(Mandatory=$True)][string]$dbTargetSecondaryServer,[Parameter(Mandatory=$True)][string]$dbTargetAVGName,$dbList) {
    #Step1: Copy database from source to target (primary node)
    $dbList | ForEach-Object {Copy-SQLDatabase -dbSourceServer $dbSourceServer -dbTargetServer $dbTargetPrimaryServer -dbName $_}

    #Step2: Copy-database from primary node to secondary node and add it to the AVG.
    $dbList | ForEach-Object {New-DatabaseToAVG -dbPrimaryServer $dbTargetPrimaryServer -dbSecondaryServer $dbTargetSecondaryServer -avgName $dbTargetAVGName -dbName $_}

    #Step3: Identify orphan login and add them to new AVG
    $dbList | ForEach-Object {
        Add-SQLMissingLogins -dbSourceServer $dbSourceServer -dbTargetServer $dbTargetPrimaryServer -dbName $_
        Write-Host successfully added the missing login to Primary node: $dbTargetPrimaryServer -ForegroundColor Green
    } 
    ##############################################################
}
function Add-FolderPermission ([Parameter(Mandatory=$True)][string]$folderPath,[Parameter(Mandatory=$True)][string]$nfcuUserOrGroupName, [System.Security.AccessControl.FileSystemRights] $permission) {    
    $Acl = Get-Acl "$folderPath"
    $Ar  = New-Object  system.security.accesscontrol.filesystemaccessrule("NFCU\$($nfcuUserOrGroupName)",$permission,"Allow")
    $Acl.SetAccessRule($Ar) 
    Set-Acl "$folderPath" $Acl -Verbose
}

function Backup-TSMSQLDatabase ([Parameter(Mandatory=$True)][string]$dbServer,[Parameter(Mandatory=$True)][string]$dbName, [ValidateSet('Full','Diff','Log','*')] $backupType ,$stripes, [switch]$alwaysOn) {
    if($alwaysOn) {
        Write-Host "Creating backup on Always On: $dbServer :  $dbName" -ForegroundColor Cyan
        $avgName = (Get-SQLAvgInfo $dbServer | Select-Object -Property AVGName -Unique).AVGName
        #take backup
        Invoke-Command -ComputerName $dbServer -ScriptBlock  {       
           C:\Progra~1\Tivoli\TSM\TDPSql\tdpsqlc.exe BACKUP "$Using:dbName" $Using:backupType /TSMP="$Using:dbServer"_MSSQL /USEALWAYSONNODE /STRIPes=$Using:stripes
        } -Verbose
    }
    else {
        Write-Host "Creating backup on regular: $dbServer :  $dbName" -ForegroundColor Cyan
        Invoke-Command -ComputerName $dbServer -ScriptBlock  {       
           C:\Progra~1\Tivoli\TSM\TDPSql\tdpsqlc.exe BACKUP "$Using:dbName" $Using:backupType /TSMP="$Using:dbServer"_MSSQL /STRIPes=$Using:stripes
        } -Verbose        
    }
}

function Get-TSMSQLBackupInfo ([Parameter(Mandatory=$True)][string]$dbServer,[Parameter(Mandatory=$True)][string]$dbName,[ValidateSet('Full','Diff','Log','All')] $backupType, [switch]$alwaysOn,[string]$tsmpPassPara) {
   if($alwaysOn) {
        #get the listener info
        $listner = Get-SQLAvgInfo $dbServer | Select-Object -Property Listner -Unique
    }
    if(-not $tsmpPassPara) {
        $tsmpPassPara = "$($dbServer)_MSSQL"
    }    
   if($listner -ne $null) {  
        $query = "& C:\Progra~1\Tivoli\TSM\TDPSql\tdpsqlc.exe query tsm $dbName * /all /querynode=AlwaysOn /tsmp=$($tsmpPassPara)"
        #$query = "exec master..xp_cmdshell  'C:\Progra~1\Tivoli\TSM\TDPSql\tdpsqlc.exe query tsm $dbName * /all /querynode=AlwaysOn /tsmp=$($dbServer)_MSSQL'"        
   } else {
       $query = "& C:\Progra~1\Tivoli\TSM\TDPSql\tdpsqlc.exe query tsm $dbName * /all /tsmp=$($tsmpPassPara)"        
       #$query = "exec master..xp_cmdshell  'C:\Progra~1\Tivoli\TSM\TDPSql\tdpsqlc.exe query tsm $dbName * /all /tsmp=$($dbServer)_MSSQL'"        
   }
    #Invoke-Sqlcmd -ServerInstance $dbServer -Query "$query" -Verbose
    Write-Host Collecting Backupinfo Using TSM query: $query ............ -ForegroundColor Yellow
    
    $result = Invoke-Command -ComputerName $dbServer -ScriptBlock {
                   Invoke-Expression $Using:query -Verbose
                }
    
    #$result = Invoke-Sqlcmd -ServerInstance $dbServer -Query $query -Database Master -ErrorAction Stop
    $output = $result | Select-String 'SQL Server Name', 'SQL Database Name','Backup Object Type','Creation Date','Object Name'

    if($output -eq $null) {
        $result | % {Write-Host $_ -ForegroundColor Magenta}
    }
    else {
        $colList = New-Object System.Collections.ArrayList
        $colList = @(
            "SQLServerName"
            "SQLDatabaseName"
            "BackupObjectType"
            "BackupCreationDateTime"
            "DatabaseObjectName"
        )
        $psTable = New-PSTable -tabName "TSMInfo" -colList $colList
        $count = 0

        $output | Select-Object -Property Line  | % {        
            $data = $_.Line
            #Create a row
            if($count -eq 0) {
                $row = $psTable.NewRow()
            }
            #Enter data in the row
            $colName = ($_.Line.Substring(0,$_.Line.IndexOf(" ."))).Trim()
            switch ($colName)
            {
                'SQL Server Name' {$row.SQLServerName = $data.Substring($data.IndexOf(". ")+2)}
                'SQL Database Name' {$row.SQLDatabaseName = $data.Substring($data.IndexOf(". ")+2)}
                'Backup Object Type' {$row.BackupObjectType = $data.Substring($data.IndexOf(". ")+2)}
                'Backup Creation Date / Time' {$row.BackupCreationDateTime = $data.Substring($data.IndexOf(". ")+2)}
                'Database Object Name' {$row.DatabaseObjectName = $data.Substring($data.IndexOf(". ")+2)}
            }       
            $count ++
            #Add the row to the table
            if($count -eq 5) {
                $psTable.Rows.Add($row)
                $count = 0
            }
        }
        #return tablular data
        if($backupType -match "All") { return $psTable}
        else { return ($psTable | ? {$_.BackupObjectType -match "$backupType"}) }
     }
}

function Restore-TSMSQLDatabase ([Parameter(Mandatory=$True)][string]$dbServer,[Parameter(Mandatory=$True)][string]$dbName,[ValidateSet('Full','Diff','Log=*','*')] $backupType, [Parameter(Mandatory=$True)][string]$targetServer, $fromSqlServer, $objectId,[ValidateSet('YES','NO')] $recovery, [switch]$alwaysOn, [switch]$closeExistingConnections) {
    
    $result = $null
    $replace = ""
    $targetOPTPath = "\\$dbServer\c$\Program Files\Tivoli\TSM\TDPSql\dsm.opt"
    $resetOPT = $False

    #replace logic
    if($backupType -eq "Full") {
        $replace = "/Replace"
    }
    #from sql server
    if($fromSqlServer -eq $null) {
        $fromSqlServer = $dbServer #source server default
    }
    #*************************************************************
    #update the opt file if the source server is AlwaysOn, but Target server is StandAlone
    if(((Get-SQLAvgInfo $dbServer) -ne $null) -and ((Get-SQLAvgInfo $targetServer) -eq $null)) {
        $targetOPTPath = "\\SWVDCRVDBADB01\J$\Temp\dsm_temp_$($fromSqlServer).opt"
        (Get-Content -Path "$targetOPTPath").Replace("CLUSTERnode yes","*CLUSTERnode yes") | Set-Content -Path $targetOPTPath -Verbose -Force
        $resetOPT = $True
    }
    #*************************************************************
    if($closeExistingConnections) {
        $sql = "USE [master] ALTER DATABASE [$dbName] SET SINGLE_USER WITH ROLLBACK IMMEDIATE"
        Invoke-Sqlcmd -ServerInstance $targetServer -Query $sql -Verbose
    }
    #*************************************************************
    #get relocate directory path
    $relocateDir = Get-SQLDataLogDefaultPath -dbServer $targetServer        
    #check if it's always on
    if($alwaysOn) {
        Write-Verbose "Restoring backup on Always On: $targetServer : Database: $dbName"
        #$query = "exec master..xp_cmdshell  'C:\Progra~1\Tivoli\TSM\TDPSql\tdpsqlc.exe restore $dbName $backupType /QueryNODE=AlwaysON /fromsqlserver=$fromSqlServer /tsmp=$($dbServer)_mssql /sqlserver=$targetServer /Replace /recovery=$recovery /object=$objectId /TSMOPTFile=""\\$dbServer\c$\Program Files\Tivoli\TSM\TDPSql\dsm.opt"" /ConfigFile=""\\$dbServer\c$\Program Files\Tivoli\TSM\TDPSql\tdpsql.cfg"" /relocatedir=$($relocateDir.DataPath),$($relocateDir.LogPath)'"
        if($targetServer -eq $fromSqlServer) {
            $query = "exec master..xp_cmdshell  'C:\Progra~1\Tivoli\TSM\TDPSql\tdpsqlc.exe restore $dbName $backupType /QueryNODE=AlwaysON /fromsqlserver=$fromSqlServer /tsmp=$($dbServer)_mssql $replace /object=$objectId /recovery=$recovery'"        
        } else {        
            $query = "exec master..xp_cmdshell  'C:\Progra~1\Tivoli\TSM\TDPSql\tdpsqlc.exe restore $dbName $backupType /QueryNODE=AlwaysON /fromsqlserver=$fromSqlServer /tsmp=$($dbServer)_mssql /sqlserver=$targetServer $replace /object=$objectId /recovery=$recovery /TSMOPTFile=""$targetOPTPath"" /ConfigFile=""\\$dbServer\c$\Program Files\Tivoli\TSM\TDPSql\tdpsql.cfg"" /relocatedir=$($relocateDir.DataPath),$($relocateDir.LogPath)'"        
        }
        Write-Verbose $query
        $result = Invoke-Sqlcmd -ServerInstance $targetServer -Query $query -QueryTimeout ([int]::MaxValue)
    }
    else {
            Write-Verbose "Restoring backup on stand-alone: $targetServer : Database: $dbName"
            #restore
            #$query = "exec master..xp_cmdshell  'C:\Progra~1\Tivoli\TSM\TDPSql\tdpsqlc.exe restore $dbName $backupType /fromsqlserver=$dbServer /tsmnode=$($dbServer)_MSSQL /tsmp=$($dbServer)_mssql /sqlserver=$targetServer /object=$objectId /Replace /recovery=$recovery /relocatedir=$($relocateDir.DataPath),$($relocateDir.LogPath),J:\'"
            #$query = "exec master..xp_cmdshell  'C:\Progra~1\Tivoli\TSM\TDPSql\tdpsqlc.exe restore $dbName $backupType /fromsqlserver=$fromSqlServer /tsmp=$($dbServer)_mssql $replace /object=$objectId /recovery=$recovery'"        
            if($targetServer -eq $fromSqlServer) {
                $query = "exec master..xp_cmdshell  'C:\Progra~1\Tivoli\TSM\TDPSql\tdpsqlc.exe restore $dbName $backupType /fromsqlserver=$fromSqlServer /tsmp=$($dbServer)_mssql $replace /object=$objectId /recovery=$recovery'"        
            } else {        
                $query = "exec master..xp_cmdshell  'C:\Progra~1\Tivoli\TSM\TDPSql\tdpsqlc.exe restore $dbName $backupType /fromsqlserver=$fromSqlServer /tsmp=$($fromSqlServer)_mssql /sqlserver=$targetServer $replace /object=$objectId /recovery=$recovery /TSMOPTFile=""$targetOPTPath"" /ConfigFile=""\\$fromSqlServer\c$\Program Files\Tivoli\TSM\TDPSql\tdpsql.cfg"" /relocatedir=$($relocateDir.DataPath),$($relocateDir.LogPath)'"        
            }
            Write-Verbose $query
            $result = Invoke-Sqlcmd -ServerInstance $targetServer -Query $query -QueryTimeout ([int]::MaxValue)
    }   
    #*************************************************************
    if($resetOPT -eq $True) {
        #$targetOPTPath = "\\SWVDCRVDBADB01\J$\Temp\dsm_temp_$($fromSqlServer).opt"
        (Get-Content -Path "$targetOPTPath").Replace("*CLUSTERnode yes","CLUSTERnode yes") | Set-Content -Path $targetOPTPath -Verbose -Force
    }
    #*************************************************************
    if($closeExistingConnections) {
        $sql2 = "ALTER DATABASE [$dbName] SET MULTI_USER"
        Write-Verbose $sql2
        Invoke-Sqlcmd -ServerInstance $targetServer -Query $sql2 -Verbose
    }
    #*************************************************************
    return $result       
}

function Restore-TSMSQLDatabase_bak ([Parameter(Mandatory=$True)][string]$dbServer,[Parameter(Mandatory=$True)][string]$dbName,[ValidateSet('Full','Diff','Log','*')] $backupType, $targetServer, $objectId, [switch]$alwaysOn, [ValidateSet('YES','NO')] $recovery) {
    $fromSqlServer = $dbServer #source server default

    #get relocate directory path
    $relocateDir = Get-SQLDataLogDefaultPath -dbServer $targetServer        
    if($alwaysOn) {
        #get the listener info
        $listner = Get-SQLAvgInfo $dbServer | Select-Object -Property Listner -Unique
        $avgName = (Get-SQLAvgInfo $dbServer | Select-Object -Property AVGName -Unique).AVGName
        $isInAvg = (Get-SQLAvgDbInfo -dbServer $dbServer) | ? {$_.name -match $dbName}   
        if($isInAvg -ne $null) {
           $fromSqlServer = $avgName
         }
        Invoke-Command -ComputerName $targetServer -Credential(Get-Credential)  -ScriptBlock  {       
            #restore
            Write-Host "Restoring backup on Always On: $Using:dbServer : In AVG-Database: $Using:dbName" -ForegroundColor Cyan
            C:\Progra~1\Tivoli\TSM\TDPSql\tdpsqlc.exe restore $Using:dbName $Using:backupType /QueryNODE=AlwaysON /fromsqlserver=$Using:fromSqlServer /tsmp=$($Using:dbServer)_mssql /sqlserver=$Using:targetServer /object=$Using:objectId /TSMOPTFile="\\$Using:dbServer\c$\Program Files\Tivoli\TSM\TDPSql\dsm.opt" /ConfigFile="\\$Using:dbServer\c$\Program Files\Tivoli\TSM\TDPSql\tdpsql.cfg" /relocatedir="$($Using:relocateDir.DataPath),$($Using:relocateDir.LogPath)" /Replace /recovery=$recovery
            #C:\Progra~1\Tivoli\TSM\TDPSql\tdpsqlc.exe restore $Using:dbName $Using:backupType /QueryNODE=AlwaysON /fromsqlserver=$Using:avgName /tsmp=$($Using:dbServer)_mssql /sqlserver=$Using:targetServer /object=$Using:objectId  /Replace /recovery=YES
        } -Verbose
    }
    else {
        Write-Host "Restoring backup on stand-alone: $dbServer :  $dbName" -ForegroundColor Cyan
        Invoke-Command -ComputerName $targetServer -Credential(Get-Credential) -ScriptBlock  {       
            #restore
            C:\Progra~1\Tivoli\TSM\TDPSql\tdpsqlc.exe restore $Using:dbName $Using:backupType /tsmp=$($Using:dbServer)_mssql /object=$Using:objectId /Replace /recovery=$recovery
        } -Verbose        
    }
}

function Add-SQLTDECertificateOnReplica ([Parameter(Mandatory=$True)][string]$dbCertServer,[Parameter(Mandatory=$True)][string]$dbReplicaServer, [Parameter(Mandatory=$True)][string]$decryPwd) {

    #check if the certificate not already exist
    $oldTDECert = (Invoke-Sqlcmd -ServerInstance $dbCertServer -Query "select * from sys.certificates where name = '$($dbReplicaServer)_TDE'"  -Verbose 4>&1).name 
    if($oldTDECert -ne $null) {
        Write-Verbose "A TDE Certificate:$oldTDECert already exist on $dbCertServer"
    }
    else {
        $pfxFile = ''
        $certFiles = ''
        Get-ChildItem \\SWVDCLVSNDBDB01\j$\software\SSLCert\ | ? {$_.Name -match $dbReplicaServer} | % {
            $pfxFile = $_.GetFiles() | ? {$_.Name -match "$($dbReplicaServer).nfcu.net.pfx"}
            $certFiles = $_.GetFiles() | ? {$_.Name -match ".cer"}
        }
        #Step: Run the PVK converter to create cert file and pvk file.
        if($certFiles -eq $null) {
           Invoke-Command -ComputerName SWVDCLVSNDBDB01 -ScriptBlock {
              Invoke-Expression "& `"J:\Program Files (x86)\Microsoft\PVKConverter\PVKConverter.exe`" -i j:\software\SSLCert\$Using:dbReplicaServer\$Using:dbReplicaServer.nfcu.net -o J:\software\SSLCert\$Using:dbReplicaServer\$Using:dbReplicaServer -d $Using:certPlainPwd -e $Using:certPlainPwd" -Verbose
           } -Verbose    
        }
        #$certFile = Get-ChildItem \\SWVDCLVSNDBDB01\j$\software\SSLCert\$dbReplicaServer\ | ? {$_.Name -match 'cer'} | ? {$_.Mode -match 'a'}
        $pvkFile = Get-ChildItem \\SWVDCLVSNDBDB01\j$\software\SSLCert\$dbReplicaServer\ | ? {$_.Name -match 'pvk'} | ? {$_.Mode -match 'a'}
        $certFile = $pvkFile.FullName.Replace(".pvk",".cer")
        Write-Verbose "$certFile , $pvkFile files have been created/exist"

        $query3 = "
            CREATE CERTIFICATE $($dbReplicaServer)_TDE 
            FROM FILE = '$($certFile)'
            WITH PRIVATE KEY (FILE = '$($pvkFile.FullName)', DECRYPTION BY PASSWORD = '$decryPwd');
            GO
        "
        Write-Verbose $query3
        Invoke-Sqlcmd -ServerInstance $dbCertServer -Query $query3  -Verbose 4>&1 
    
        $newTDECert = (Invoke-Sqlcmd -ServerInstance $dbCertServer -Query "select * from sys.certificates where name = '$($dbReplicaServer)_TDE'" -Verbose 4>&1).name 
        Write-Verbose "A new TDE Certificate:$newTDECert has been successfully created on $dbCertServer"
    }
}


function Add-SQLTDECertificate ([parameter(Mandatory=$True)][string]$dbCertServer, [parameter(Mandatory=$True)][string]$decryPwd) {
    #check if the certificate not already exist
    $oldTDECert = (Invoke-Sqlcmd -ServerInstance $dbCertServer -Query "select * from sys.certificates where name = '$($dbCertServer)_TDE'" -Verbose 4>&1).name 
    if($oldTDECert -ne $null) {
        Write-Verbose "A TDE Certificate:$oldTDECert already exist on $dbCertServer"
    }
    else {
        $pfxFile = ''
        $certFiles = ''
        Get-ChildItem \\SWVDCLVSNDBDB01\j$\software\SSLCert\ | ? {$_.Name -match $dbCertServer} | % {
            $pfxFile = $_.GetFiles() | ? {$_.Name -match "$($dbCertServer).nfcu.net.pfx"}
            $certFiles = $_.GetFiles() | ? {$_.Name -match ".cer"}
        }
        #Step: Run the PVK converter to create cert file and pvk file.
        if($certFiles -eq $null) {
           Invoke-Command -ComputerName SWVDCLVSNDBDB01 -ScriptBlock {
              Invoke-Expression "& `"J:\Program Files (x86)\Microsoft\PVKConverter\PVKConverter.exe`" -i j:\software\SSLCert\$Using:dbCertServer\$Using:dbCertServer.nfcu.net -o J:\software\SSLCert\$Using:dbCertServer\$Using:dbCertServer -d $Using:certPlainPwd -e $Using:certPlainPwd" -Verbose
           } -Verbose    
        }
        #$certFile = Get-ChildItem \\SWVDCLVSNDBDB01\j$\software\SSLCert\$dbCertServer\ | ? {$_.Name -match 'cer'} | ? {$_.Mode -match 'a'}
        $pvkFile = Get-ChildItem \\SWVDCLVSNDBDB01\j$\software\SSLCert\$dbCertServer\ | ? {$_.Name -match 'pvk'} | ? {$_.Mode -match 'a'}
        $certFile = $pvkFile.FullName.Replace(".pvk",".cer")
        Write-Verbose "$certFile',' $pvkFile files have been created/exist"

        $query3 = "
            CREATE CERTIFICATE $($dbCertServer)_TDE 
            FROM FILE = '$certFile'
            WITH PRIVATE KEY (FILE = '$($pvkFile.FullName)', DECRYPTION BY PASSWORD = '$decryPwd');
            GO
        "
        Write-Verbose $query3
        Invoke-Sqlcmd -ServerInstance $dbCertServer -Query $query3 -Verbose 4>&1 
    
        $newTDECert = (Invoke-Sqlcmd -ServerInstance $dbCertServer -Query "select * from sys.certificates where name = '$($dbCertServer)_TDE'" -Verbose 4>&1).name 
        Write-Verbose "A new TDE Certificate:$newTDECert has been successfully created on $dbCertServer"
    }
}

function Add-SQLTDECertificateOnReplica_bak ($dbCertServer,$dbReplicaServer, $decryPwd) {
    #check if the certificate not already exist
    $oldTDECert = (Invoke-Sqlcmd -ServerInstance $dbCertServer -Query "select * from sys.certificates where name = '$($dbReplicaServer)_TDE'"  -Verbose 4>&1).name 
    if($oldTDECert -ne $null) {
        Write-Host A TDE Certificate:$oldTDECert already exist on $dbCertServer  -ForegroundColor Magenta
    }
    else {
            $certFile = Get-ChildItem \\SWVDCLVSNDBDB01\j$\software\SSLCert\$dbCertServer\ | ? {$_.Name -match 'cer'} | ? {$_.Mode -match 'a'}
            $pvkFile = Get-ChildItem \\SWVDCLVSNDBDB01\j$\software\SSLCert\$dbCertServer\ | ? {$_.Name -match 'pvk'} | ? {$_.Mode -match 'a'}
    
        $query3 = "
            CREATE CERTIFICATE $($dbReplicaServer)_TDE 
            FROM FILE = '$($certFile.FullName)'
            WITH PRIVATE KEY (FILE = '$($pvkFile.FullName)', DECRYPTION BY PASSWORD = '$decryPwd');
            GO
        "
        Invoke-Sqlcmd -ServerInstance $dbCertServer -Query $query3  -Verbose 4>&1 
    
        $newTDECert = (Invoke-Sqlcmd -ServerInstance $dbCertServer -Query "select * from sys.certificates where name = '$($dbReplicaServer)_TDE'"  -Verbose 4>&1).name 
        Write-Host A new TDE Certificate:$newTDECert has been successfully created on $dbCertServer  -ForegroundColor Green
    }
}
function Get-SQLFileUsage ([Parameter(Mandatory=$True)][string]$dbServer) {
    #db file usage across dbs
    Invoke-Sqlcmd -ServerInstance $dbServer -InputFile '\\nfcu.net\user\homedir\57814\sqlLib\All Database Data %26 log file daily checklist.sql' -Verbose 4>&1
}
function Get-SQLBackupHistory([Parameter(Mandatory=$True)]$dbServer) {
    Invoke-Sqlcmd -ServerInstance $dbServer -InputFile '\\nfcu.net\user\homedir\57814\sqlLib\backupHistory.sql' -Verbose 4>&1
}
function Get-SQLEncryptionStatus ([Parameter(Mandatory=$True)][string]$dbServer) {
    $query = "
        SELECT db_name(database_id) as dbname, encryption_state, 
        encryptor_thumbprint, encryptor_type, percent_complete
        FROM sys.dm_database_encryption_keys
    "
    Invoke-Sqlcmd -ServerInstance $dbServer -Query $query  -Verbose 4>&1 | Sort-Object -Property Column1,encryption_state | Format-Table -Wrap  
}
function Update-SQLDatabaseEncryption ([Parameter(Mandatory=$True)][string[]]$userDBList,[Parameter(Mandatory=$True)][string]$dbCertServer) {
    #Change encryption key/certificate on the database
    $userDBList | % {
        $query6 = "
            USE $_
            ALTER DATABASE ENCRYPTION KEY
            ENCRYPTION BY SERVER CERTIFICATE $($dbCertServer)_TDE;
            GO
        "
        Invoke-Sqlcmd -ServerInstance $dbCertServer -Query $query6  -Verbose 4>&1 
    }
}

#$envionmentList = Invoke-Sqlcmd -ServerInstance svr-sndbx08 -Database DBAAdmin -Query "SELECT distinct Environment from [DBAdmin].[dbo].[SqlServer] where Environment is not null" -ErrorAction Stop
function New-SQLDbaAdminInfo ([Parameter(Mandatory=$True)][string]$dbServer,[Parameter(Mandatory=$True)][string]$applicationName,[Parameter(Mandatory=$True)][string]$description, $businessGroup,$businessContact,$environment,$licenseId,$numLicenses) {    
    Write-Host "Step 1 --Executing on both SWVDCRVDBADB01 and SWWDCRVDBADB01 instances to add linked server" -ForegroundColor Yellow 
    $dbaServerList | % {
        $linkExist = Invoke-Sqlcmd -ServerInstance $_ -Query "EXEC sp_linkedservers" -Verbose | ? {$_.SRV_NAME -match $dbServer}
    }
    if($linkExist -eq $null) {
        $query1 = "
            EXEC [DBAdmin].[dbo].[AddNewlinkedServer] @servername = '$dbServer', @user = '$sqlUser', @password = '$sqlProdPass'
        "
        $dbaServerList = @('svr-sndbx08','SWVDCRVDBADB01','SWWDCRVDBADB01')
        $dbaServerList | % {
            Invoke-Sqlcmd -ServerInstance $_ -Query $query1 -Verbose 
            Write-Host $query1 -ForegroundColor Cyan
        }
    }    
    Write-Host "Step 2 --Executing on svr-sndbx08, and swhadcrvsqldba instances" -ForegroundColor Yellow     
    $query2 = ((Get-Content -Path \\SVR-SNDBX08\DBAScripts\Chita\sqlLib\UpdateDBAdminSQLInfo.sql).Replace('<DBSERVER>',$dbServer)).Replace('<ApplicationName>',$applicationName).Replace('<BusinessGroup>',$businessGroup).Replace('<BusinessContact>',$businessContact).Replace('<Environment>',$environment).Replace('<LicenseId>',$licenseId).Replace('<NumLicenses>',$numLicenses).Replace('<Description>',$description) | Out-String   
    Write-Host $query2 -ForegroundColor Cyan
    Invoke-Sqlcmd -ServerInstance swhadcrvsqldba -Database Master -Query $query2 -Verbose
    Invoke-Sqlcmd -ServerInstance svr-sndbx08 -Database Master -Query $query2 -Verbose
}

function Add-SqlSecurePasswords {
    if (-not (Test-Path \\nfcu.net\user\homedir\$env:USERNAME\securepwd)) {
        New-Item \\nfcu.net\user\homedir\$env:USERNAME\securepwd -ItemType Directory -Verbose
            (Get-Credential -Message "Please enter TDE-Cert Password for PROD" -UserName "Not Applicable").Password  | ConvertFrom-SecureString | Out-File \\nfcu.net\user\homedir\$env:USERNAME\securepwd\TDE_PROD.secure  -Force -verbose
            (Get-Credential -Message "Please enter TDE-Cert Password for DEV" -UserName "Not Applicable").Password   | ConvertFrom-SecureString | Out-File \\nfcu.net\user\homedir\$env:USERNAME\securepwd\TDE_DEV.secure  -Force -verbose
            (Get-Credential -Message "Please enter Password" -UserName "NFCU\SQLserverSVC").Password | ConvertFrom-SecureString | Out-File \\nfcu.net\user\homedir\$env:USERNAME\securepwd\SQLserverSVC.secure  -Force -verbose
            (Get-Credential -Message "Please enter Password" -UserName "NFCU\SQLSvc").Password | ConvertFrom-SecureString | Out-File \\nfcu.net\user\homedir\$env:USERNAME\securepwd\SQLSvc.secure  -Force -verbose
            (Get-Credential -Message "Please enter Password(NFCUTEST)" -UserName "HQ\SQLSvc").Password | ConvertFrom-SecureString | Out-File \\nfcu.net\user\homedir\$env:USERNAME\securepwd\HQSQLSvc_NFCUTEST.secure  -Force -verbose
            (Get-Credential -Message "Please enter Password for DEV" -UserName "shackle").Password | ConvertFrom-SecureString | Out-File \\nfcu.net\user\homedir\$env:USERNAME\securepwd\shackleDEV.secure  -Force -verbose
            (Get-Credential -Message "Please enter Password for PROD" -UserName "shackle").Password | ConvertFrom-SecureString | Out-File \\nfcu.net\user\homedir\$env:USERNAME\securepwd\shacklePROD.secure  -Force -verbose
    }
}
function Get-SqlPlainPassword ([ValidateSet('HQSQLSvc_NFCUTEST','shackleDEV','shacklePROD','SQLserverSVC','SQLSvc','TDE_DEV','TDE_PROD')]$pwdFile) {
    return (New-Object System.Management.Automation.PSCredential "UserID",(ConvertTo-SecureString (Get-Content \\nfcu.net\user\homedir\$env:USERNAME\securepwd\$pwdFile.secure) )).GetNetworkCredential().Password
}

function Get-SqlSecurePassword ([ValidateSet('HQSQLSvc_NFCUTEST','shackleDEV','shacklePROD','SQLserverSVC','SQLSvc','TDE_DEV','TDE_PROD')]$pwdFile) {
    return (New-Object System.Management.Automation.PSCredential "UserID",(ConvertTo-SecureString (Get-Content \\nfcu.net\user\homedir\$env:USERNAME\securepwd\$pwdFile.secure) )).Password
}


function Install-SqlTDECertificate_BAK ([parameter (Mandatory=$True)][string]$dbCertServer, [parameter (Mandatory=$True)][string]$certPlainPwd, [switch]$restartSQLService, [switch]$encryptUserDBs) {

    if($dbCertServer -eq $null) {
        $dbCertServer = $env:COMPUTERNAME    
    }
    $certSecPwd = ConvertTo-SecureString ($certPlainPwd) -AsPlainText -Force -Verbose

    #Step0: Check if the certificate already exist on the server 
    $dbCertificate = Invoke-Command -ComputerName $dbCertServer -ScriptBlock {
        (Get-ChildItem Cert:\LocalMachine\My -Verbose) 
    }
    if ($dbCertificate -eq $null) {
        Write-Host No certificate is installed on the server: $dbCertServer -ForegroundColor Yellow
    }
    else {
        $oldCert = $dbCertificate
        $dbCertificate = $null
    }
    #Step: Check if the pfx file exist on the DBA box for that server.
    $pfxFile = ''
    $certFiles = ''
    Get-ChildItem \\SWVDCLVSNDBDB01\j$\software\SSLCert\ | ? {$_.Name -match $dbCertServer} | % {
        $pfxFile = $_.GetFiles() | ? {$_.Name -match "$($dbCertServer).nfcu.net.pfx"}
        $certFiles = $_.GetFiles() | ? {$_.Name -cmatch ".cer"}
    }
    #Step: Run the PVK converter to create cert file and pvk file.
    if($certFiles -eq $null) {
       Invoke-Command -ComputerName SWVDCLVSNDBDB01 -ScriptBlock {
          Invoke-Expression "& `"J:\Program Files (x86)\Microsoft\PVKConverter\PVKConverter.exe`" -i j:\software\SSLCert\$Using:dbCertServer\$Using:dbCertServer.nfcu.net -o J:\software\SSLCert\$Using:dbCertServer\$Using:dbCertServer -d $Using:certPlainPwd -e $Using:certPlainPwd" -Verbose
       } -Verbose    
    }
    $certFile = Get-ChildItem \\SWVDCLVSNDBDB01\j$\software\SSLCert\$dbCertServer\ | ? {$_.Name -match 'cer'} | ? {$_.Mode -match 'a'}
    $pvkFile = Get-ChildItem \\SWVDCLVSNDBDB01\j$\software\SSLCert\$dbCertServer\ | ? {$_.Name -match 'pvk'} | ? {$_.Mode -match 'a'}
    Write-Host $certFile',' $pvkFile files have been created/exist -ForegroundColor Green

    #Step: Import or overwrite certificate on the server My folder if it does not exist

    #run ouput of below command on the certificate server
    if($oldCert -eq $null) {      
       #Invoke-Command  -ComputerName $dbCertServer -Authentication Credssp -Credential (Get-Credential -Message RemoteServerAdmin) -ScriptBlock {
         Import-PfxCertificate -FilePath $($pfxFile.FullName) -Password $certSecPwd -CertStoreLocation Cert:\LocalMachine\My -Exportable -Verbose 
       #} -EnableNetworkAccess
    }

    #Step: Get the certificate from the local server
    $newCert = Get-ChildItem Cert:\LocalMachine\My | Select-Object -First 1             

    #Step: Check if SQL certificate is already instaleld on the server.
    $oldSqlCert = get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\*\MSSQLServer\SuperSocketNetLib" -Name "Certificate"  -Verbose

    $setNewCert = $True
    if($oldSqlCert -ne $null) {
        if($oldSqlCert.Certificate -eq $newCert.Thumbprint) {
           Write-host  CERT: $oldSqlCert.Certificate already exist on SQL Server:$dbCertServer -ForegroundColor Yellow
           $setNewCert = $false
        }
    }
    if($setNewCert = $True) {
        #Step: Load the certificate on the SQL server
        $certificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $PfxPath = "\\SWVDCLVSNDBDB01\j$\software\SSLCert\$dbCertServer\$pfxFile"
        $certificateObject.Import($PfxPath, $certSecPwd , [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)

        Set-ItemProperty -Path $(get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\*\MSSQLServer\SuperSocketNetLib").PsPath -Name "Certificate" -Type String -Value "$($certificateObject.Thumbprint)" -Verbose

        #Step: Restart SQL Service
        if($restartSQLService) {
            Restart-SQLService -dbServer $dbCertServer
        }

        #Step: Check error log file
        #Get-SqlErrorLog  -ServerInstance $dbCertServer  -Since Midnight -Verbose | ? {$_.Text -match 'encryption'}
    }

    #######################################################
    #                 ENABLE TDE                          # 
    #######################################################    
    New-SQLMasterKey -dbCertServer $dbCertServer -certPlainPwd $certPlainPwd
    #Check if the server is part of an AVG group, if yes! then replicate the certificate (TDE only) on other replicas before encrypting any database.
    Add-SQLTDECertificate -dbCertServer $dbCertServer -decryPwd $certPlainPwd

    $otherReplica = Get-SQLAvgInfo -dbServer $dbCertServer | ? {$_.Replicas -notmatch $dbCertServer} | Select-Object -Property Replicas
    if($otherReplica -ne $null) {
        #import TDE certificate on the other replica node
        $otherReplica | % {        
            New-SQLMasterKey -dbCertServer ($_.Replicas) -certPlainPwd $certPlainPwd
            Add-SQLTDECertificateOnReplica -dbCertServer ($_.Replicas) -dbReplicaServer $dbCertServer -decryPwd $certPlainPwd  
            #Add-SQLTDECertificate -dbCertServer ($_.Replicas) -decryPwd $certPlainPwd
        }
    }
    
    #get list of user databases
    if($encryptUserDBs) {
        Enable-TDEOnUserDatabases -dbCertServer $dbCertServer
    }

}

function Install-SqlTDECertificate ([parameter (Mandatory=$True)][string]$dbCertServer, [parameter (Mandatory=$True)][string]$certPlainPwd, [switch]$restartSQLService, [switch]$encryptUserDBs) {

    if($dbCertServer -eq $null) {
        $dbCertServer = $env:COMPUTERNAME    
    }
    $certSecPwd = ConvertTo-SecureString ($certPlainPwd) -AsPlainText -Force -Verbose

    #use sql service account for remote login
    $svcCred = [System.Management.Automation.PSCredential]::new("NFCU\SQLserverSVC",(ConvertTo-SecureString (Get-SqlPlainPassword -pwdFile SQLserverSVC) -AsPlainText -Force))
    $securePwdShackle = ConvertTo-SecureString -String (Get-SqlPlainPassword -pwdFile shacklePROD) -AsPlainText -Force
    $ShackleCred = New-Object System.Management.Automation.PSCredential ("Shackle", $securePwdShackle)


    #Step0: Check if the certificate already exist on the server 
    $dbCertificate = Invoke-Command -ComputerName $dbCertServer -ScriptBlock {
        (Get-ChildItem Cert:\LocalMachine\My -Verbose) 
    } -Credential $svcCred
    
    <#
    if ($dbCertificate -eq $null) {
        Write-Verbose "No certificate is installed on the server: $dbCertServer"
    }
    else {
        $oldCert = $dbCertificate
        $dbCertificate = $null
    }
    #>

    #Step: Check if the pfx file exist on the DBA box for that server.
    $pfxFile = ''
    $certFiles = ''
    Get-ChildItem \\SWVDCLVSNDBDB01\j$\software\SSLCert\ | ? {$_.Name -match $dbCertServer} | % {
        $pfxFile = $_.GetFiles() | ? {$_.Name -match "$($dbCertServer).nfcu.net.pfx"}
        $certFiles = $_.GetFiles() | ? {$_.Name -cmatch ".cer"}
    }
    #Step: Run the PVK converter to create cert file and pvk file.
    if($certFiles -eq $null) {
       Invoke-Command -ComputerName SWVDCLVSNDBDB01 -ScriptBlock {
          Invoke-Expression "& `"J:\Program Files (x86)\Microsoft\PVKConverter\PVKConverter.exe`" -i j:\software\SSLCert\$Using:dbCertServer\$Using:dbCertServer.nfcu.net -o J:\software\SSLCert\$Using:dbCertServer\$Using:dbCertServer -d $Using:certPlainPwd -e $Using:certPlainPwd" -Verbose
       } -Verbose    
    }
    $certFile = Get-ChildItem \\SWVDCLVSNDBDB01\j$\software\SSLCert\$dbCertServer\ | ? {$_.Name -match 'cer'} | ? {$_.Mode -match 'a'}
    $pvkFile = Get-ChildItem \\SWVDCLVSNDBDB01\j$\software\SSLCert\$dbCertServer\ | ? {$_.Name -match 'pvk'} | ? {$_.Mode -match 'a'}
    Write-Verbose "$certFile , $pvkFile files have been created/exist"

    #Step: import certificate
    if($oldCert -eq $null) { 
        if((-not (Test-Path "\\$dbCertServer\J$\Temp\"))) {
            New-Item -Path "\\$dbCertServer\J$\" -Name "Temp" -ItemType Directory -Force -Verbose 
        }
        Copy-Item "\\SWVDCLVSNDBDB01\j$\software\SSLCert\$dbCertServer\$($dbCertServer).nfcu.net.pfx" -Destination "\\$dbCertServer\J$\Temp\" -Force -Verbose
        Invoke-Command -ComputerName $dbCertServer -ScriptBlock  { 
            certutil –f –p "$Using:certPlainPwd" –importpfx "J:\Temp\$($Using:dbCertServer).nfcu.net.pfx"
        } -Credential $svcCred -Verbose
    }
    
    #Step: Get the certificate from the local server
    $newCert = Invoke-Command -ComputerName $dbCertServer -ScriptBlock {
        Get-ChildItem Cert:\LocalMachine\My | Select-Object -First 1             
    } -Credential $svcCred

    #Step: Check if SQL certificate is already instaleld on the server.
    $oldSqlCert = Invoke-Command -ComputerName $dbCertServer -ScriptBlock { 
        get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\*\MSSQLServer\SuperSocketNetLib" -Name "Certificate"  -Verbose
    } -Credential $svcCred

    $setNewCert = $True
    if($oldSqlCert -ne $null) {
        if($oldSqlCert.Certificate -eq $newCert.Thumbprint) {
           Write-Verbose  "CERT: $oldSqlCert.Certificate already exist on SQL Server:$dbCertServer"
           $setNewCert = $false
        }
    }
    if($setNewCert = $True) {
        #Step: Load the certificate on the SQL server
        $certificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $PfxPath = "\\SWVDCLVSNDBDB01\j$\software\SSLCert\$dbCertServer\$pfxFile"
        $certificateObject.Import($PfxPath, $certSecPwd , [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
        Invoke-Command -ComputerName $dbCertServer -ScriptBlock {
            Set-ItemProperty -Path $(get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\*\MSSQLServer\SuperSocketNetLib").PsPath -Name "Certificate" -Type String -Value "$($Using:certificateObject.Thumbprint)" -Verbose
        } -Credential $svcCred

        #Step: Restart SQL Service
        if($restartSQLService) {
            Restart-SQLService -dbServer $dbCertServer
        }

        #Step: Check error log file
        Get-SqlErrorLog  -ServerInstance $dbCertServer  -Since Midnight -Verbose  | ? {$_.Text -match 'encryption'}
    }

    #######################################################
    #                 ENABLE TDE                          # 
    #######################################################    
    New-SQLMasterKey -dbCertServer $dbCertServer -certPlainPwd $certPlainPwd
    
    #Check if the server is part of an AVG group, if yes! then replicate the certificate (TDE only) on other replicas before encrypting any database.
    Add-SQLTDECertificate -dbCertServer $dbCertServer -decryPwd $certPlainPwd

    $otherReplica = Get-SQLAvgInfo -dbServer $dbCertServer | ? {$_.Replicas -notmatch $dbCertServer} | Select-Object -Property Replicas
    if($otherReplica -ne $null) {
        #import TDE certificate on the other replica node
        $otherReplica | % {        
            New-SQLMasterKey -dbCertServer ($_.Replicas) -certPlainPwd $certPlainPwd
            Add-SQLTDECertificateOnReplica -dbCertServer ($_.Replicas) -dbReplicaServer $dbCertServer -decryPwd $certPlainPwd  
            #Add-SQLTDECertificate -dbCertServer ($_.Replicas) -decryPwd $certPlainPwd
        }
    }
    
    #get list of user databases
    if($encryptUserDBs) {
        Enable-TDEOnUserDatabases -dbCertServer $dbCertServer
    }

}

function Enable-TDEOnUserDatabases ([Parameter(Mandatory=$True)][string]$dbCertServer, [string[]]$userDBList) {
    
    if($userDBList -eq $null) {
        #get list of user databases
        $query4 = "
            select * from sys.sysdatabases
            where name not in ('master','tempdb','model','msdb')
        "
        Write-Verbose $query4 
        $userDBList = (Invoke-Sqlcmd -ServerInstance $dbCertServer -Query $query4  -Verbose 4>&1 | Select-Object -Property name).name
    }
    #Step: Encrypt user database
    $userDBList | ?{$_ -notmatch 'ReportServer'} | % {
        $query5 = "
            USE $_
            CREATE DATABASE ENCRYPTION KEY
            WITH ALGORITHM = AES_256
            ENCRYPTION BY SERVER CERTIFICATE $($dbCertServer)_TDE;
            GO

            ALTER DATABASE $_
            SET ENCRYPTION ON;
            GO
        "
        Write-Verbose $query5 
        Invoke-Sqlcmd -ServerInstance $dbCertServer -Query $query5  -Verbose 4>&1 
    }    
}

function New-SQLMasterKey ([parameter(Mandatory=$True)][string]$dbCertServer,[parameter(Mandatory=$True)][string]$certPlainPwd) {
    #Step: Create new Master key, if not already exist
    $masterKey = (Invoke-Sqlcmd -ServerInstance $dbCertServer -Query "select * from sys.symmetric_keys"  | ? {$_.name -match 'DatabaseMaster'}|Select-Object -Property name).name
    if($masterKey -eq $null) {
        $query2 = "
            USE master
            CREATE MASTER KEY ENCRYPTION BY PASSWORD = '$certPlainPwd';
            GO
        "    
        Invoke-Sqlcmd -ServerInstance $dbCertServer -Query $query2  -Verbose
        $masterKey = Invoke-Sqlcmd -ServerInstance $dbCertServer -Query "select * from sys.symmetric_keys" | Select-Object -Property name
        Write-Verbose "New masterKey: $($masterKey[0]) has been created on $dbCertServer"
    }
    else {
        Write-Verbose "masterKey: $masterKey is already been found on $dbCertServer"
        $query21 = "
            ALTER MASTER KEY REGENERATE WITH ENCRYPTION BY PASSWORD = '$($certPlainPwd)';  
            GO  
        "
        Invoke-Sqlcmd -ServerInstance $dbCertServer -Query $query21 -Verbose
        Write-Verbose "masterKey: $masterKey has been regenerated w/ new password on Server:$dbCertServer"
    }
}

function Get-SQLAvgDbInfo ([Parameter(Mandatory=$True)][string]$dbServer) {
     $query = "   
        select B.name, A.synchronization_state from sys.dm_hadr_database_replica_states A, sys.databases B
        where B.database_id = A.database_id
     "
     Invoke-Sqlcmd -ServerInstance $dbServer -Query $query -Verbose 4>&1   
}
function Get-SQLInputBuffer ([Parameter(Mandatory=$True)][string]$sessionID) {
    Invoke-Sqlcmd -ServerInstance $dbServer -Query "dbcc inputbuffer ($($sessionID))" 
}
function Get-SQLRequestQueue ([Parameter(Mandatory=$True)][string]$dbServer) {
    $queue = Invoke-Sqlcmd -ServerInstance $dbServer -InputFile \\SVR-SNDBX08\DBAScripts\Chita\sqlLib\GetRequestQueueInfo.sql -Verbose 4>&1 
    return $queue
}
function New-PSTable ([Parameter(Mandatory=$True)][string]$tabName, [System.Collections.ArrayList] $colList) 
{
    #Create Table object
    $table = New-Object system.Data.DataTable “$tabName”

    #Define Columns
    $colList | % {
        $col1 = New-Object system.Data.DataColumn $_,([string])        
        $table.columns.add($col1)
    }
    return , [system.Data.DataTable]$table
}
  <#
    .DESCRIPTION
         Restores a SQL database using TSM ONLY, supports all below four scenarios: 
	   - Standalone ==> Standalone
       - Standalone ==> Availability group
       - Availability group ==> Availability group
       - Availability group ==> Standalone
    
    .SYNOPSIS 
      Restores a SQL database using TSM ONLY
    
    .EXAMPLE
      Restore-TSMSQLBackupPIT -dbServer SWVDCRVDBADB01 -dbTargetServer SWWDCRVDBADB01 -dbName ChitaGen1 -pointInTime (get-date).AddMinutes(-1) -Verbose
	  This example restores database name ChitaGen1 from SWVDCRVDBADB01 ==> SWWDCRVDBADB01 for point in time = -1 minute from the current datetime
  #>
  
function Restore-TSMSQLBackupPIT ([parameter(Mandatory=$True)][string]$dbServer,[parameter(Mandatory=$True)][string]$dbTargetServer,[parameter(Mandatory=$True)][string]$dbName, [parameter(Mandatory=$False,HelpMessage="MM/DD/YYYY hh:mm:ss")][ValidateScript({$_ -le (get-date)})][DateTime]$pointInTime, [switch]$closeExistingConnections, [switch]$noRecovery) {
    
    $alwaysOn = [switch]::new($False)     
    
    #if point in time is not supplied
    if(-not $pointInTime) {$pointInTime = (get-date).AddSeconds(-10)} #gets latest date time window

    if((Get-SQLAvgInfo -dbServer $dbServer) -ne $null) {
            $alwaysOn = [switch]::Present
    }
    if($alwaysOn) {$backupInfo = Get-TSMSQLBackupInfo -dbServer $dbServer -dbName $dbName -backupType All -alwaysOn -Verbose}
    else {$backupInfo = Get-TSMSQLBackupInfo -dbServer $dbServer -dbName $dbName -backupType All -Verbose}
    
    #*************************************************************
    #pick the last full backup
    $lastFull = $backupInfo | ? {($_.BackupCreationDateTime -lt "$pointInTime") -and ($_.BackupObjectType -eq 'Full')} | Sort-Object -Property BackupCreationDateTime -Descending | Select-Object -First 1
    
    Write-Verbose "Full backup info:"
    $lastFull | Format-Table -Wrap
    
    #pick set of logs since the last full backup
    $lastLogs =  $backupInfo | ? {($_.BackupCreationDateTime -gt $lastFull.BackupCreationDateTime) -and ($_.BackupCreationDateTime -lt "$pointInTime") -and ($_.BackupObjectType -match 'Log')} | Sort-Object -Property BackupCreationDateTime
    $lastLogsObjectID = ($lastLogs | Select-Object -Last 1).DatabaseObjectName

    Write-Verbose "Log backup info:"
    $lastLogs | Format-Table -Wrap
    #*************************************************************
    $fullResult = $null
    $fullRecovery = "No"
        
    if($lastLogs -eq $null -and $noRecovery -ne $True) {$fullRecovery = "Yes"}

    if($lastFull -ne $null) {    
         #check if we need to close connection before overwriting it
         if($closeExistingConnections) {
            $sql = "USE [master] ALTER DATABASE [$dbName] SET SINGLE_USER WITH ROLLBACK IMMEDIATE"
            Invoke-Sqlcmd -ServerInstance $dbTargetServer -Query $sql -Verbose
         } 
   
        $lastFull | % {
            Write-Verbose "Starting Recovery of Full backup for timestamp: $($_.BackupCreationDateTime)"
            if($alwaysOn) {
                $fullResult = Restore-TSMSQLDatabase -dbServer $dbServer -dbName $dbName -backupType Full -fromSqlServer $_.SQLServerName  -targetServer $dbTargetServer  -objectId $_.DatabaseObjectName -recovery $fullRecovery -alwaysOn
            }
            else {
                $fullResult = Restore-TSMSQLDatabase -dbServer $dbServer -dbName $dbName -backupType Full -fromSqlServer $_.SQLServerName  -targetServer $dbTargetServer  -objectId $_.DatabaseObjectName -recovery $fullRecovery 
            }
        }
        while($fullResult -eq $null) {
            Start-Sleep -Seconds 5;
        }
        if(($fullResult | Out-String | ? {$_ -match "invalid"}) -or ($fullResult | Out-String | ? {$_ -match "error"})) {
            Write-Verbose ($fullResult | Out-String)
        }
        else {
            if($lastLogs -eq $null) {
                Write-Verbose "No T-Logs backup found on TSM to recover"
            }
            else {
                $lastLogs | % {
                    Write-Verbose "Starting Recovery of TLog backup for timestamp: $($_.BackupCreationDateTime)"
                    if($_.DatabaseObjectName -eq $lastLogsObjectID) {
                        $recovery = "Yes"
                    } else {
                        $recovery = "No"
                    }
                    if($alwaysOn) {
                        $logResult = Restore-TSMSQLDatabase -dbServer $dbServer -dbName $dbName -backupType Log=* -fromSqlServer $_.SQLServerName -targetServer $dbTargetServer -objectId $_.DatabaseObjectName -recovery $recovery -alwaysOn $alwaysOn
                    }  
                    else {
                        $logResult = Restore-TSMSQLDatabase -dbServer $dbServer -dbName $dbName -backupType Log=* -fromSqlServer $_.SQLServerName -targetServer $dbTargetServer -objectId $_.DatabaseObjectName -recovery $recovery
                    }
                    Write-Verbose ($logResult | Out-String)
                }
                while($logResult -eq $null) {
                    Start-Sleep -Seconds 5;
                }
            }
            #set it back to multi user
            if($closeExistingConnections) {
                $sql2 = "ALTER DATABASE [$dbName] SET MULTI_USER"
                Write-Verbose "$sql2"
                Invoke-Sqlcmd -ServerInstance $dbTargetServer -Query $sql2 -Verbose
            } 
            Write-Verbose "Database has been successfully recovered until timestamp: $pointInTime"
        } 
    }
    else {
        Write-Verbose "No backup info found for: $pointInTime"
    }     
}
function Copy-TSMSqlDatabase ([Parameter(Mandatory=$True)][string]$dbSourceServer,[Parameter(Mandatory=$True)][string]$dbTargetServer,$dbList, [datetime]$pointInTime) {
    $dbList | % {Restore-TSMSQLBackupPIT -dbServer $dbSourceServer -dbTargetServer $dbTargetServer -dbName $_ -pointInTime $pointInTime}
    $dbList | ForEach-Object {
        Add-SQLMissingLogins -dbSourceServer $dbSourceServer -dbTargetServer $dbTargetServer -dbName $_
        Write-Host successfully added the missing login to Primary node -ForegroundColor Green   
    } 
}

function Get-SQLServerTDEdbInfo([Parameter(Mandatory=$True)][string]$dbServer) {
    return (
        Invoke-Sqlcmd -ServerInstance $dbServer -Query "
            USE master 
            GO 
            SELECT db_name(database_id) [TDE Encrypted DB Name], c.name as CertName, encryptor_thumbprint 
                FROM sys.dm_database_encryption_keys dek 
                INNER JOIN sys.certificates c on dek.encryptor_thumbprint = c.thumbprint
        " -Verbose -ErrorAction Stop
    )
}
function Get-SQLServerTDEInfo([Parameter(Mandatory=$True)][string]$dbServer) {
    $result = Invoke-Sqlcmd -ServerInstance $dbServer -Query "select * from sys.dm_database_encryption_keys" -Verbose
    if($result) {
    $query = "
        select b.name,
         a.encryption_state,
         a.encryptor_thumbprint,
         a.key_algorithm,
         a.percent_complete,
         c.name as CertificateName,
         c.issuer_name,         
         a.create_date,
         c.expiry_date,
         a.regenerate_date
        from 
        sys.dm_database_encryption_keys a, sys.databases b , sys.certificates c
        where 
        b.database_id = a.database_id
        and c.thumbprint = a.encryptor_thumbprint
    "
    Invoke-Sqlcmd -ServerInstance $dbServer -Query $query  -Verbose
    } else {
        Invoke-Sqlcmd -ServerInstance $dbServer -Query "select * from sys.certificates where pvt_key_encryption_type = 'MK'" -Verbose
    }
}

function Get-SQLClusterInfo ([Parameter(Mandatory=$True)][string]$nodeServer) {
    get-wmiobject -class "MSCluster_Cluster" -namespace "root\mscluster" -computername "$nodeServer" | select -ExpandProperty name
}

function Get-SQLDatabaseRecoveryModel([Parameter (Mandatory=$True)] [string]$dbServer) {
    $query = "
        USE [master]
        GO
        select name, recovery_model, recovery_model_desc from sys.databases order by name
    "
    Invoke-Sqlcmd -ServerInstance $dbServer -Query $query -Verbose
}

function Update-SQLDatabaseRecoveryModel([Parameter (Mandatory=$True)] [string]$dbServer,[Parameter (Mandatory=$True)][string]$dbName, [Parameter (Mandatory=$True)][ValidateSet("SIMPLE","FULL")][string]$recoveryModel) {
    $query = "
        USE [master]
        GO
        ALTER DATABASE $dbName SET RECOVERY $recoveryModel WITH NO_WAIT
        GO
    "
    Invoke-Sqlcmd -ServerInstance $dbServer -Query $query -Verbose
}
function Get-SQLServerTDERequestInfo {

    import-csv \\nfcu.net\user\homedir\57814\TDECetInfo.csv | % {        
        try {
            $tdeInstalled = Invoke-Sqlcmd -ServerInstance $_.ServerName -Query "select * from sys.certificates where name like '%_TDE%'"
            if($tdeInstalled) {
                Write-host TDE is installed on Server: $_.ServerName, Certificate name is: $($tdeInstalled.name) -ForegroundColor Cyan
            }
        }
        catch {
        }
    }

}
function Get-DynamicParam ([Parameter(Mandatory=$True)][string]$paramName,$validSet, $RuntimeParamDic) {
     $ParamAttrib  = New-Object System.Management.Automation.ParameterAttribute
      $ParamAttrib.Mandatory  = $true
      $ParamAttrib.ParameterSetName  = '__AllParameterSets'    

      $AttribColl = New-Object  System.Collections.ObjectModel.Collection[System.Attribute]
      $AttribColl.Add($ParamAttrib)      
      $AttribColl.Add((New-Object  System.Management.Automation.ValidateSetAttribute($validSet)))  

      $RuntimeParam  = New-Object System.Management.Automation.RuntimeDefinedParameter($paramName,  [string], $AttribColl)
      
      if($RuntimeParamDic -eq $Null) {
        $RuntimeParamDic  = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
      }
                  
      $RuntimeParamDic.Add($paramName,  $RuntimeParam) 
      return  $RuntimeParamDic
}

Function New-DynamicParam {
<#
    .SYNOPSIS
        Helper function to simplify creating dynamic parameters
    
    .DESCRIPTION
        Helper function to simplify creating dynamic parameters

        Example use cases:
            Include parameters only if your environment dictates it
            Include parameters depending on the value of a user-specified parameter
            Provide tab completion and intellisense for parameters, depending on the environment

        Please keep in mind that all dynamic parameters you create will not have corresponding variables created.
           One of the examples illustrates a generic method for populating appropriate variables from dynamic parameters
           Alternatively, manually reference $PSBoundParameters for the dynamic parameter value

    .NOTES
        Credit to http://jrich523.wordpress.com/2013/05/30/powershell-simple-way-to-add-dynamic-parameters-to-advanced-function/
            Added logic to make option set optional
            Added logic to add RuntimeDefinedParameter to existing DPDictionary
            Added a little comment based help

        Credit to BM for alias and type parameters and their handling

    .PARAMETER Name
        Name of the dynamic parameter

    .PARAMETER Type
        Type for the dynamic parameter.  Default is string

    .PARAMETER Alias
        If specified, one or more aliases to assign to the dynamic parameter

    .PARAMETER ValidateSet
        If specified, set the ValidateSet attribute of this dynamic parameter

    .PARAMETER Mandatory
        If specified, set the Mandatory attribute for this dynamic parameter

    .PARAMETER ParameterSetName
        If specified, set the ParameterSet attribute for this dynamic parameter

    .PARAMETER Position
        If specified, set the Position attribute for this dynamic parameter

    .PARAMETER ValueFromPipelineByPropertyName
        If specified, set the ValueFromPipelineByPropertyName attribute for this dynamic parameter

    .PARAMETER HelpMessage
        If specified, set the HelpMessage for this dynamic parameter
    
    .PARAMETER DPDictionary
        If specified, add resulting RuntimeDefinedParameter to an existing RuntimeDefinedParameterDictionary (appropriate for multiple dynamic parameters)
        If not specified, create and return a RuntimeDefinedParameterDictionary (appropriate for a single dynamic parameter)

        See final example for illustration

    .EXAMPLE
        
        function Show-Free
        {
            [CmdletBinding()]
            Param()
            DynamicParam {
                $options = @( gwmi win32_volume | %{$_.driveletter} | sort )
                New-DynamicParam -Name Drive -ValidateSet $options -Position 0 -Mandatory
            }
            begin{
                #have to manually populate
                $drive = $PSBoundParameters.drive
            }
            process{
                $vol = gwmi win32_volume -Filter "driveletter='$drive'"
                "{0:N2}% free on {1}" -f ($vol.Capacity / $vol.FreeSpace),$drive
            }
        } #Show-Free

        Show-Free -Drive <tab>

    # This example illustrates the use of New-DynamicParam to create a single dynamic parameter
    # The Drive parameter ValidateSet populates with all available volumes on the computer for handy tab completion / intellisense

    .EXAMPLE

    # I found many cases where I needed to add more than one dynamic parameter
    # The DPDictionary parameter lets you specify an existing dictionary
    # The block of code in the Begin block loops through bound parameters and defines variables if they don't exist

        Function Test-DynPar{
            [cmdletbinding()]
            param(
                [string[]]$x = $Null
            )
            DynamicParam
            {
                #Create the RuntimeDefinedParameterDictionary
                $Dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        
                New-DynamicParam -Name AlwaysParam -ValidateSet @( gwmi win32_volume | %{$_.driveletter} | sort ) -DPDictionary $Dictionary

                #Add dynamic parameters to $dictionary
                if($x -eq 1)
                {
                    New-DynamicParam -Name X1Param1 -ValidateSet 1,2 -mandatory -DPDictionary $Dictionary
                    New-DynamicParam -Name X1Param2 -DPDictionary $Dictionary
                    New-DynamicParam -Name X3Param3 -DPDictionary $Dictionary -Type DateTime
                }
                else
                {
                    New-DynamicParam -Name OtherParam1 -Mandatory -DPDictionary $Dictionary
                    New-DynamicParam -Name OtherParam2 -DPDictionary $Dictionary
                    New-DynamicParam -Name OtherParam3 -DPDictionary $Dictionary -Type DateTime
                }
        
                #return RuntimeDefinedParameterDictionary
                $Dictionary
            }
            Begin
            {
                #This standard block of code loops through bound parameters...
                #If no corresponding variable exists, one is created
                    #Get common parameters, pick out bound parameters not in that set
                    Function _temp { [cmdletbinding()] param() }
                    $BoundKeys = $PSBoundParameters.keys | Where-Object { (get-command _temp | select -ExpandProperty parameters).Keys -notcontains $_}
                    foreach($param in $BoundKeys)
                    {
                        if (-not ( Get-Variable -name $param -scope 0 -ErrorAction SilentlyContinue ) )
                        {
                            New-Variable -Name $Param -Value $PSBoundParameters.$param
                            Write-Verbose "Adding variable for dynamic parameter '$param' with value '$($PSBoundParameters.$param)'"
                        }
                    }

                #Appropriate variables should now be defined and accessible
                    Get-Variable -scope 0
            }
        }

    # This example illustrates the creation of many dynamic parameters using New-DynamicParam
        # You must create a RuntimeDefinedParameterDictionary object ($dictionary here)
        # To each New-DynamicParam call, add the -DPDictionary parameter pointing to this RuntimeDefinedParameterDictionary
        # At the end of the DynamicParam block, return the RuntimeDefinedParameterDictionary
        # Initialize all bound parameters using the provided block or similar code

    .FUNCTIONALITY
        PowerShell Language

#>
param(
    
    [string]
    $Name,
    
    [System.Type]
    $Type = [string],

    [string[]]
    $Alias = @(),

    [string[]]
    $ValidateSet,
    
    [switch]
    $Mandatory,
    
    [string]
    $ParameterSetName="__AllParameterSets",
    
    [int]
    $Position,
    
    [switch]
    $ValueFromPipelineByPropertyName,
    
    [string]
    $HelpMessage,

    [validatescript({
        if(-not ( $_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary] -or -not $_) )
        {
            Throw "DPDictionary must be a System.Management.Automation.RuntimeDefinedParameterDictionary object, or not exist"
        }
        $True
    })]
    $DPDictionary = $false
 
)
    #Create attribute object, add attributes, add to collection   
        $ParamAttr = New-Object System.Management.Automation.ParameterAttribute
        $ParamAttr.ParameterSetName = $ParameterSetName
        if($mandatory)
        {
            $ParamAttr.Mandatory = $True
        }
        if($Position -ne $null)
        {
            $ParamAttr.Position=$Position
        }
        if($ValueFromPipelineByPropertyName)
        {
            $ParamAttr.ValueFromPipelineByPropertyName = $True
        }
        if($HelpMessage)
        {
            $ParamAttr.HelpMessage = $HelpMessage
        }
 
        $AttributeCollection = New-Object 'Collections.ObjectModel.Collection[System.Attribute]'
        $AttributeCollection.Add($ParamAttr)
    
    #param validation set if specified
        if($ValidateSet)
        {
            $ParamOptions = New-Object System.Management.Automation.ValidateSetAttribute -ArgumentList $ValidateSet
            $AttributeCollection.Add($ParamOptions)
        }

    #Aliases if specified
        if($Alias.count -gt 0) {
            $ParamAlias = New-Object System.Management.Automation.AliasAttribute -ArgumentList $Alias
            $AttributeCollection.Add($ParamAlias)
        }

 
    #Create the dynamic parameter
        $Parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, $Type, $AttributeCollection)
    
    #Add the dynamic parameter to an existing dynamic parameter dictionary, or create the dictionary and add it
        if($DPDictionary)
        {
            $DPDictionary.Add($Name, $Parameter)
        }
        else
        {
            $Dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            $Dictionary.Add($Name, $Parameter)
            $Dictionary
        }
}

function Get-SQLServerList {
 $query = "SELECT Distinct Environment + ':' + ServerName as Server  FROM [DBAdmin].[dbo].[SqlServer] where Environment + ':' + ServerName is not null and Environment in ('DEV', 'DR', 'PROD','QUAL','TEST', 'INTG') and Active = 1  order by Server"
 $dbServer  = Invoke-Sqlcmd -ServerInstance SWVDCRVDBADB01 -Database Master -Query $query
 return $dbServer
}

function Get-SQLDatabaseList ([string]$dbServer) {
    #list of database on the server
    $query = "select name from sys.databases where name not in ('master','tempdb','model','msdb','ReportServer','ReportServerTempDB','DBAdmin')"          
    $dbName  = Invoke-Sqlcmd -ServerInstance ($dbServer) -Database Master -Query $query 
    return $dbName
}
function Get-SQLDatabaseRole ([string]$dbServer, [string]$dbName) {
   $query = "select distinct name from sys.database_principals where type_desc = 'DATABASE_ROLE'"   
   $dbRoles  = Invoke-Sqlcmd -ServerInstance $dbServer -Database $dbName -Query $query 
   return $dbRoles
}
function Get-SQLServerUsers ([string]$dbServer) {
    $query = "select distinct name from sys.server_principals where type_desc in ('WINDOWS_GROUP','SQL_LOGIN','WINDOWS_LOGIN') and is_disabled = 0 and name not in ('sa') order by name"   
    $userId  = Invoke-Sqlcmd -ServerInstance $dbServer -Database Master -Query $query 
    return $userId
}

function Clear-SQLDatabaseLogSpace($dbServer,$dbName) {
    $logicalName = (Get-SQLDatabaseLogicalFileName -dbServer $dbServer -dbName $dbName | ?{$_.PhysicalFileName -match 'ldf'}).LogicalFileName
    $query = "
        USE [$dbName]
        GO
        DBCC SHRINKFILE (N'$logicalName' , 0, TRUNCATEONLY)
        GO
    "
}
function Copy-SQLModules ([Parameter (Mandatory=$True)] $targetServer) {
    new-item "\\$targetServer\C$\Program Files\WindowsPowerShell\Modules\" -Name SQLUtility -ItemType Directory -Force -Verbose
    Copy-Item -Path \\SVR-SNDBX08\DBAScripts\Chita\Modules\SqlUtility.psm1 -Destination "\\$targetServer\C$\Program Files\WindowsPowerShell\Modules\SQLUtility\" -Force -Verbose
    Copy-Item -Path C:\Windows\System32\WindowsPowerShell\v1.0\Modules\SqlServerDsc -Destination "\\$targetServer\C$\Program Files\WindowsPowerShell\Modules\" -Force -Recurse -Verbose
    Copy-Item -Path 'C:\Program Files\WindowsPowerShell\Modules\SqlServer' -Destination "\\$targetServer\C$\Program Files\WindowsPowerShell\Modules\" -Force -Recurse -Verbose
    Copy-Item -Path 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\xFailOverCluster' -Destination "\\$targetServer\C$\Program Files\WindowsPowerShell\Modules\" -Recurse -Force -Verbose
    Copy-Item -Path 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\xDscDiagnostics' -Destination "\\$targetServer\C$\Program Files\WindowsPowerShell\Modules\" -Recurse -Force -Verbose
    Get-ChildItem -Path "\\$targetServer\C$\Program Files\WindowsPowerShell\Modules" -Recurse | Unblock-File -Verbose
}

function Get-SQLAdGroupInfo ([parameter(Mandatory=$True)][string]$adGroupName) {    
    #new PS Table
    $colList = New-Object System.Collections.ArrayList
    $colList = @(
        "DistinguishedName"
        "GivenName"
        "Surname"
        "UserPrincipalName"
        "GroupName"
    )
    $psTable = New-PSTable -tabName "GroupInfo" -colList $colList
    $count = 0
    Get-ADGroup $adGroupName | Get-ADGroupMember | % {
        if($_.objectClass -eq "user") {
            Get-ADUser -Identity $_ | % {
                $row = $psTable.NewRow()
                $row.DistinguishedName = $_.DistinguishedName
                $row.GivenName = $_.GivenName
                $row.Surname = $_.Surname
                $row.GroupName = "N/A"
                $psTable.Rows.Add($row)
                $count++
            }
        }
        else {
            $groupName = $_.name
            Get-ADGroup $_ | Get-ADGroupMember | % {Get-ADUser -Identity $_ | % {
                    $row = $psTable.NewRow()
                    $row.DistinguishedName = $_.DistinguishedName
                    $row.GivenName = $_.GivenName
                    $row.Surname = $_.Surname
                    $row.GroupName = $groupName
                    $psTable.Rows.Add($row)
                    $count++
                }
            } 
        }
    }
    return $psTable
}

function Install-TSM ([parameter(Mandatory=$True)][string]$dbServer,[switch]$isCluster,[string]$dbHAServer=$null) {

    $securePwdSQLSvc = ConvertTo-SecureString -String (Get-SqlPlainPassword -pwdFile SQLSvc) -AsPlainText -Force
    $svcCred = New-Object System.Management.Automation.PSCredential ("NFCU\SQLSvc", $securePwdSQLSvc)

    #Copy latest modules
    #Copy-SQLModules -targetServer $dbServer -Verbose
    
    #copy the TSM/TDP files.
    new-item "\\$($dbServer)\J$\Temp\TSM-TDP 8.1.4" -ItemType Directory -Verbose -Force
    Copy-item -path "\\svr-sndbx08\dbascripts\TSM-TDP 8.1.4\SP_CLIENT_8.1.4_WIN_ML.exe" -Destination "\\$($dbServer)\J$\Temp\TSM-TDP 8.1.4\" -Force -Verbose -ErrorAction Stop
    Copy-item -path "\\svr-sndbx08\dbascripts\TSM-TDP 8.1.4\SP_DBS_8.1.4_DP_MS_SQL_ML.exe" -Destination "\\$($dbServer)\J$\Temp\TSM-TDP 8.1.4\" -Force -Verbose -ErrorAction Stop

    #extra files 
    Invoke-Command -cn $dbServer -ScriptBlock {
        Invoke-Expression "& 'J:\Temp\TSM-TDP 8.1.4\SP_CLIENT_8.1.4_WIN_ML.exe' -Y -o'J:\Temp\TSM-TDP 8.1.4'" -Verbose 
    } -Verbose     
    Invoke-Command -cn $dbServer -ScriptBlock {
        Invoke-Expression "& 'J:\Temp\TSM-TDP 8.1.4\SP_DBS_8.1.4_DP_MS_SQL_ML.exe' -Y -o'J:\Temp\TSM-TDP 8.1.4' " -Verbose 
    } -Verbose    

    #Step1: Install TSM
    Invoke-Command -cn $dbServer -ScriptBlock {
        Invoke-Expression "& 'J:\Temp\TSM-TDP 8.1.4\TSMCLI_WIN\tsmcli\x64\client\Disk1\IBM Spectrum Protect Client.msi' /passive /qn /norestart" -Verbose
    } -Credential $svcCred -Verbose    
    Sleep -Seconds 10 

    Invoke-Command -cn $dbServer -ScriptBlock {
        Invoke-Expression "& 'J:\Temp\TSM-TDP 8.1.4\TSMSQL_WIN\fcm\x64\sql\8140\enu\IBM Spectrum Protect for Databases - MS SQL.msi' /passive /qn /norestart" -Verbose
    } -Credential $svcCred -Verbose      
    Sleep -Seconds 10

    Invoke-Command -cn $dbServer -ScriptBlock {
        Invoke-Expression "& 'J:\Temp\TSM-TDP 8.1.4\TSMSQL_WIN\fcm\x64\mmc\8140\enu\IBM Spectrum Protect for Databases - MS SQL - Management Console.msi' /passive /qn /norestart" -Verbose
    } -Credential $svcCred -Verbose       
    Sleep -Seconds 10    

    #confirm when it's installed
    #Get-SQLPackageInfo -dbServer $dbServer -Verbose -ErrorAction Stop | ? {$_.DisplayName -match 'IBM'} | Format-Table -Wrap
    Invoke-Command -cn $dbServer -ScriptBlock {
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | ? {$_.Publisher -match 'IBM'} | select DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize 
    } -Credential $svcCred -Verbose 

    #Step: Backup default TSM configuration files
    Invoke-Command -cn $dbServer -ScriptBlock {    
        new-item "C:\Program Files\Tivoli\TSM\TDPSql\bak" -ItemType Directory -Verbose
        Copy-Item -Path "C:\Program Files\Tivoli\TSM\TDPSql\*.*" -Include tdpsql.cfg, dsm.opt -Destination "C:\Program Files\Tivoli\TSM\TDPSql\bak\"  -Force -verbose
    } -Verbose
    #Step: Update TSM configuration

    #Step: Update TDP DSM file
    Invoke-Command -cn $dbServer -ScriptBlock {
         (Get-Content -Path "C:\Program Files\Tivoli\TSM\TDPSql\tdpsql.cfg").Replace("_WIN","_MSSQL").Replace("vss","Legacy") | Out-File -FilePath "C:\Program Files\Tivoli\TSM\TDPSql\tdpsql.cfg" -Force -Verbose
            <#
            Add-Content -Path "C:\Program Files\Tivoli\TSM\TDPSql\tdpsql.cfg" -Value "LASTPRUNEDate 04/05/2015 07:46:17"  -Force -Verbose
            Add-Content -Path "C:\Program Files\Tivoli\TSM\TDPSql\tdpsql.cfg" -Value "STRIPes		4"
            Add-Content -Path "C:\Program Files\Tivoli\TSM\TDPSql\tdpsql.cfg" -Value "SQLAUTHentication	INTegrated"
            Add-Content -Path "C:\Program Files\Tivoli\TSM\TDPSql\tdpsql.cfg" -Value "SQLSERVer	$Using:dbServer"
            Add-Content -Path "C:\Program Files\Tivoli\TSM\TDPSql\tdpsql.cfg" -Value "FromSQLSERVer	$Using:dbServer"
            Add-Content -Path "C:\Program Files\Tivoli\TSM\TDPSql\tdpsql.cfg" -Value "LOGFile tdpsql_MSSQLSERVER.log"
            #>
            if($isCluster) {
                Add-Content -Path "C:\Program Files\Tivoli\TSM\TDPSql\tdpsql.cfg" -Value "UseAlwaysOnNode YES"
                Add-Content -Path "C:\Program Files\Tivoli\TSM\TDPSql\tdpsql.cfg" -Value "AlwaysOnNode  $($Using:dbHAServer)_MSSQL"
            }
    }

    #check TDP info
    Invoke-Command -cn $dbServer -ScriptBlock {
        (Get-Content -Path "C:\Program Files\Tivoli\TSM\TDPSql\tdpsql.cfg")
    }
    Sleep -Seconds 10
    #Step: Update TDP DSM file
    Invoke-Command -cn $dbServer -ScriptBlock {
         (Get-Content -Path "C:\Program Files\Tivoli\TSM\TDPSql\dsm.opt").Replace("generate","prompt").Replace("_SQL","_MSSQL") | Out-File -FilePath "C:\Program Files\Tivoli\TSM\TDPSql\dsm.opt" -Force -Verbose
         Add-Content -Path "C:\Program Files\Tivoli\TSM\TDPSql\dsm.opt" -Value "errorlogname dsmerror_mssqlserver.log" -Force -Verbose
         if($isCluster) {
            Add-Content -Path "C:\Program Files\Tivoli\TSM\TDPSql\dsm.opt" -Value "ClusterNode yes" -Force -Verbose
         }
    }
    Invoke-Command -cn $dbServer -ScriptBlock {
         Get-Content -Path "C:\Program Files\Tivoli\TSM\TDPSql\dsm.opt" -Force -Verbose
    }
}

function Get-SQLPackageInfo([Parameter(Mandatory=$True)][string]$dbServer) {
$securePwdSQLserverSVC = ConvertTo-SecureString -String (Get-SqlPlainPassword -pwdFile SQLserverSVC) -AsPlainText -Force
$SQLserverSVCCred = New-Object System.Management.Automation.PSCredential ("NFCU\SQLserverSVC", $securePwdSQLserverSVC)

  Invoke-Command -ComputerName $dbServer -Credential $SQLserverSVCCred -ScriptBlock {
    $x86Path = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $installedItemsX86 = Get-ItemProperty -Path $x86Path | Select-Object -Property DisplayName,DisplayVersion, PSChildName
    
    $x64Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $installedItemsX64 = Get-ItemProperty -Path $x64Path | Select-Object -Property DisplayName,DisplayVersion, PSChildName

    $installedItems = $installedItemsX64
    $installedItems | Where-Object -FilterScript { $null -ne $_.DisplayName } | Sort-Object -Property DisplayName 
   } -Verbose
}
Function Get-SQLJobs
{
    param ([string]$server, [string]$JobName)
    # Load SMO assembly, and if we're running SQL 2008 DLLs load the SMOExtended and SQLWMIManagement libraries
    [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | out-null

    # Create object to connect to SQL Instance
    $srv = New-Object "Microsoft.SqlServer.Management.Smo.Server" $server

    # used to allow piping of more than one job name to function
    if($JobName)
    {
        foreach($j in $jobName)
        {
            $srv.JobServer.Jobs | where {$_.Name -match $JobName} 
        }
    }
    else #display all jobs for the instance
    {
        $srv.JobServer.Jobs 
} #end of Get-SQLJobStatus
}

function Get-SqlServerLastReboot([parameter(Mandatory=$True)][string[]]$ErrorServers) {
    $ErrorServers |foreach { 
    $ComputerName = $_ 
    if (Test-Connection -ComputerName $ComputerName -Count 1 -ErrorAction SilentlyContinue ) { 
        Write-Host -ForegroundColor Yellow "Reading Eventlogs on $ComputerName" 
        try { Get-WinEvent -computername $ComputerName -FilterHashtable @{logname="System";id="1074"} -MaxEvents 1  -ErrorAction Stop |select @{N='ServerName';E={"$ComputerName"}},TimeCreated,Id,LevelDisplayName,Message 
             } 
        catch [Exception] { 
                if ($_.Exception -match "No events were found that match the specified selection criteria") { 
                    Write-Host -ForegroundColor Red "No events found of selected event Search criteria on Server $ComputerName" 
                    } 
        } 
    } 
    Else { $ErrorServers += "$ComputerName" } 
    } 
}
function Get-SqlServerEventLogInfo {
[CmdletBinding()]
    Param(
        # Any other parameters can go here
        [string[]]$ErrorServers,
        [string]$eventId
    )
 
    DynamicParam {
            # Set the dynamic parameters' name
            $set = [System.Diagnostics.EventLog]::GetEventLogs() | select -ExpandProperty Log
            $dict = Get-DynamicParam -paramName EventLogType -validSet $set 
            return $dict
    }

    begin {
        # Bind the parameter to a friendly variable
        $EventLogType = $PsBoundParameters["EventLogType"]
    }

    process {
        # Your code goes here
        $ErrorServers |foreach { 
        $ComputerName = $_ 
        if (Test-Connection -ComputerName $ComputerName -Count 1 -ErrorAction SilentlyContinue ) { 
            Write-Host -ForegroundColor Yellow "Reading Eventlogs on $ComputerName"             
            try { 
                Get-WinEvent -computername $ComputerName -FilterHashtable @{logname="$EventLogType";id="$eventId"} -MaxEvents 10 -ErrorAction Stop |select @{N='ServerName';E={"$ComputerName"}},TimeCreated,Id,LevelDisplayName,Message 
                 } 
            catch [Exception] { 
                    if ($_.Exception -match "No events were found that match the specified selection criteria") { 
                            Write-Host -ForegroundColor Red "No events found of selected event Search criteria on Server $ComputerName" 
                        } 
            } 
        } 
        Else { $ErrorServers += "$ComputerName" } 
        } 
    }
}

Export-ModuleMember -Function 	Backup-RestoreSQLDatabase
Export-ModuleMember -Function 	Backup-TSMSQLDatabase
#Export-ModuleMember -Function 	Copy-SQLDatabase
Export-ModuleMember -Function 	Get-SQLBackupInfo
Export-ModuleMember -Function 	Get-SQLDatabaseBackupDir
Export-ModuleMember -Function 	Get-SQLDatabaseLogicalFileName
Export-ModuleMember -Function 	Get-SQLDataLogDefaultPath
Export-ModuleMember -Function 	Get-SQLServerDiskInfo
Export-ModuleMember -Function 	Get-SQLServerInfo
Export-ModuleMember -Function 	Join-SQLDatabaseToAvg
Export-ModuleMember -Function 	New-DatabaseToAVG
Export-ModuleMember -Function 	Remove-SQLDatabase
Export-ModuleMember -Function 	Restore-TSMSQLDatabase
Export-ModuleMember -Function 	Test-SQLDatabase 
Export-ModuleMember -Function 	Remove-SQLFiles
Export-ModuleMember -Function   Set-SQLServiceCrentials
Export-ModuleMember -Function   Get-SQLServerDotNetFeature
Export-ModuleMember -Function   Update-SQLUserPassword
Export-ModuleMember -Function   Restart-SQLService 
Export-ModuleMember -Function   Get-SQLDatabasePermissions
Export-ModuleMember -Function   Add-SQLMissingLogins
Export-ModuleMember -Function   Move-SQLDatabase
Export-ModuleMember -Function   Get-TSMSQLBackupInfo
Export-ModuleMember -Function   Get-SQLWhoIsActive
Export-ModuleMember -Function   Get-SQLAvgInfo
Export-ModuleMember -Function   Get-SQLDatbaseInfo
Export-ModuleMember -Function   Add-SQLDatabaseToAvg
Export-ModuleMember -Function   Move-SQLDatabaseToAVG
Export-ModuleMember -Function   Add-FolderPermission
Export-ModuleMember -Function   Add-SQLTDECertificate
Export-ModuleMember -Function   Add-SQLTDECertificateOnReplica
Export-ModuleMember -Function   Get-SQLFileUsage
Export-ModuleMember -Function   Update-SQLDatabaseEncryption
Export-ModuleMember -Function   New-SQLDbaAdminInfo
Export-ModuleMember -Function   Add-SqlSecurePasswords
Export-ModuleMember -Function   Get-SqlPlainPassword
Export-ModuleMember -Function   Get-SqlSecurePassword
Export-ModuleMember -Function   Install-SqlTDECertificate
Export-ModuleMember -Function   Get-SQLAvgDbInfo
Export-ModuleMember -Function   Enable-TDEOnUserDatabases
Export-ModuleMember -Function   New-SQLMasterKey
Export-ModuleMember -Function   Get-SQLRequestQueue
Export-ModuleMember -Function   New-PSTable
Export-ModuleMember -Function   Restore-TSMSQLBackupPIT
#Export-ModuleMember -Function   Copy-TSMSqlDatabase
Export-ModuleMember -Function   Get-SQLServerTDEInfo
Export-ModuleMember -Function   Get-SQLClusterInfo
Export-ModuleMember -Function   Get-SQLDatabaseRecoveryModel
Export-ModuleMember -Function   Update-SQLDatabaseRecoveryModel
Export-ModuleMember -Function   Get-DynamicParam
Export-ModuleMember -Function   New-DynamicParam
Export-ModuleMember -Function   Get-SQLServerList
Export-ModuleMember -Function   Get-SQLDatabaseList
Export-ModuleMember -Function   Get-SQLDatabaseRole
Export-ModuleMember -Function   Get-SQLServerUsers
Export-ModuleMember -Function   Clear-SQLDatabaseLogSpace
Export-ModuleMember -Function  Copy-SQLModules
Export-ModuleMember -Function  Get-SQLAdGroupInfo
Export-ModuleMember -Function  Get-SQLServerTDEdbInfo
Export-ModuleMember -Function  Install-TSM
Export-ModuleMember -Function  Get-SQLPackageInfo
Export-ModuleMember -Function  Get-SQLJobs
Export-ModuleMember -Function  Get-SqlServerLastReboot
Export-ModuleMember -Function  Get-SqlServerEventLogInfo
Export-ModuleMember -Function  Get-SQLReplicaInfo
Export-ModuleMember -Function  Get-SQLBackupHistory

