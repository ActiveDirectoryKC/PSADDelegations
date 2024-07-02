<#
    AD Delegations Module
    ## TODO: 
        Need description and details

    .VERSION
        0.11.2
            Added Set-PSActiveDirectoryAuditRule.ps1 to the module. 
        0.11.1
            - Fixed issue with OU/Container lookups. Doing a Filter to avoid errors with a second check against the config DN for the site-based stuff.
            - Fixed an issue with ExtendedRights lookup if you specify a GUID. It now attempts to resolve the GUID before moving on. 
        0.11.0
        - Logging does not launch with Module Import. It it bound as part of the main New- and Set- functions.
        - New-PSActiveDirectoryAccessRule now can lookup based on DistinguishedName for the object. 
        - Fixed DomainName parameter issues. 
        - Implemented SkipBackup on Set-PSActiveDirectoryAccessRule
        - Fixed issue with Show-PSActiveDirectoryObjectTypes not searching objects.
        

        KNOWN ISSUES
        - Logging Issues
            - Defaulting to default log no matter what.
            - Commented out the New-PSADDelegationLog in places. 
            - Need to streamline this with actual logging. 
        - Do we need to be concerned about connecting/disconnecting PSDrives for every environment for every perm?
        - Supplying an unqualified username that isn't in the Well-Known Prinicpals Table will error.
        - Direct splat calling from Add-PSActiveDirectoryAccessRule to New-PSActiveDirectoryAccessRule leads to errors. 
            - Enums do not translate well in the splatted arrays.
            - May be resolvable with conversion
        - Logging will need to be revamped as we move into how this works with other scripts. 
        - AclBackups location doesn't generate as it should sometimes. 
    TODO:
        0.11.2
            - Finish fully integrating Set-PSActiveDirectoryAuditRule
        0.11.0 Final Optimize
            - Review IdentityReference section along with Well-Known Principals
            - Review Logging Section
                - What needs done in-Module
            - Review the guidlist function
                - Is it needed?
                - Does it need exported?
            - Review ShouldContinue with logging
            - Code Review
            - Documentation
        
        FUTURE
            - Throw-PSError function
                - Gives cleaner error ouptut?
                - Store the relevent error type with the $ErrorMessage so we just have to run a Throw-PSError cmlet to read and throw the relevent error.
                - Built-In logging support

        Notes
        [System.Guid]::Empty = 00000000-0000-0000-0000-000000000000
            - [Guid]::Empty (all zeros) Object Type = Everything?
            - [Guid]::Empty (all zeros) Inherited Object Type = This Object Only
#>

using namespace System.Collections.Generic;
using namespace System.DirectoryServices;

#requires -Modules ActiveDirectory

# --- Variable Declarations
[string]$LogPath = $null # Logs for this instance. 
[string]$AclBackupPath = $null # Location of ACL backups.
[HashTable]$ObjectTypeGuidsMap = @{} # Stores the ObjectTypes from the schema
[HashTable]$ExtendedRightsMap = @{} # Stores the ExtendedRights from the config partition

#region Well-Known Principals Table
# A list of well-known principal names and their SIDs that may come up in ACEs. 
## THIS IS NOT COMPREHENSIVE: https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows#well-known-sids-all-versions-of-windows
$WellKnownPrincipals = @{
    "Everyone" = "S-1-1-0"
    "Local Authority" = "S-1-2"
    "Local" = "S-1-2-0"
    "Creater Owner" = "S-1-3-0"
    "NT Authority" = "S-1-5"
    "Authenticated Users" = "S-1-5-11"
    "Local System" = "S-1-5-18"
    "Local Service" = "S-1-5-19"
    "Network Service" = "S-1-5-20"
}
#endregion Well-Known Principals Table

#region ErrorMessages Section
<#
    This is a collection of potential error messages we want to use. 
    Ideally this would tie in more directly with the Error and Warning streams. However, I don't want to go through all the effort to hijack them for a little bit cleaner code.

    Every error message takes at least one argument which can be an empty string (or $null). This is to allow you to customize the error if you so desire. 

    Usage:
        [string]::Format($Errormessages.[ERROR_KEY], {0}, {1}, ...)

    Example
        [string]::Format($ErrorMessages.AD_OBJ_NOT_FOUND, $Item, $Domain, $CustomMessage)
#>
$ErrorMessages = @{
    "TOO_MANY_VALUES" = "Query '{0}' returned more values than expected. This operation only expected a single value. {1}"
    "INVALID_AD_OBTYPE" = "Cannot validate argument on parameter '{0}'. The argument `"{1}`" is not a valid object type. Run `"Show-PSActiveDirectoryObjectTypes`" to see list of object types. {2}"
    "INVALID_AD_OBTYPE_SEARCH" = "Cannot validate argument on parameter '{0}'. The search string `"{1}`" does not return any valid object types. Run `"Show-PSActiveDirectoryObjectTypes`" to see list of object types. {2}"
    "INVALID_AD_EXTENDEDRIGHT" = "Cannot validate argument on parameter '{0}'. The argument `"{1}`" is not a valid extended right. Run `"Show-PSActiveDirectoryExtendedRights`" to see list of extended rights. {2}"
    "INVALID_ARG_SET" = "Cannot select a valid method with existing argument set `"{0}`. {1}"
    "INVALID_TYPE" = "Supplied parameter is not the correct data type with type {0}. Please specify type of {1}. {2}"
    "INVALID_HASH_KEY" = "Unable to locate key '{0}' in the specified guid table. {1}"
    "INVALID_DOMAINNAME" = "Unable to resolve domain name '{0}' - Exiting. {1}"
    "INVALID_DOMAINCONTROLLER" = "Unable to locate a domain controller with the name '{0}' in {1} - Exiting. {2}"
    "PARAM_INVALID_EXTRIGHT" = "ExtendedRights permissions require both the 'ExtendedRight' parameter and the AD Right to be 'ExtendedRight'. {0}"
    "PARAM_INVALID_OBJSEARCH" = "Cannot use both 'SearchString' and 'ObjectName' parameters. Defaulting to ObjectName. {0}"
    "PARAM_INVALID_EXTRIGHT_EXTRA" = "The ExtendedRights parameter is only needed if assigning an extended right. Ignoring the ExtendedRight parameter. {0}"
    "AD_OBJ_NOT_FOUND" = "Lookup of '{0}' in the domain '{1}' failed. AD is unable to locate an object matching the name. {2}"
    "AD_PRINCIPAL_DOMAIN_MISMATCH" = "Principal domain name does not match supplied domain name '{0}'. Ignoring the principal domain information. {1}"
	"AD_PRINCIPAL_NAME_FORMAT_ERR" = "Principal '{0}' is in the wrong format. Please specify a Fully Qualified user name. {1}"
    "FAILED_AD_IDREF_TRANSLATE" = "Conversion of '{0}' to IdentityReference failed. AD is unable to locate an object matching the name. {1}"
    "FAILED_ADWS_CONNECT" = "Failed to create ADWS connection to '{0}' - Exiting. {1}"
    "FAILED_MAP_LOOKUP" = "Failed to create Object Types Map or Extended Rights Map. Exiting. {0}" 
}
#endregion

#region Logging
<#
    Eventually this may be rolled into a more controlled "Script Logging" module but for now we're doing it here.

    1. Can we read from a config for log path?
#>

function Confirm-PSADDelegationLog
{
    param(
        [string]$Path,
        [switch]$Directory
    )

    [System.IO.FileInfo]$NewLogFile = $null
    [System.IO.DirectoryInfo]$NewLogDir = $null

    if( !(Test-Path -Path $Path) ) # Test the whole path
    {
        if( !(Test-Path -Path (Split-Path -Path $Path -Parent)) )
        {
            Write-Warning "Unable to determine log path for module - $(Split-Path -Path $Path -Parent) - Logs being forwarded to null."
            return $null
        }
        else
        {
            if( !$Directory )
            {
                Try
                {
                    $NewLogFile = New-Item -Path (Split-Path -Path $Path -Parent) -Name (Split-Path -Path $Path -Leaf) -ItemType File -ErrorAction Stop -Verbose:$VerbosePreference
                }
                Catch
                {
                    throw "Unable to create log file at path '$Path'" 
                }
            }
            else
            {
                Try
                {
                    $NewLogDir = New-Item -Path (Split-Path -Path $Path -Parent) -Name (Split-Path -Path $Path -Leaf) -ItemType Directory -ErrorAction Stop -Verbose:$VerbosePreference
                }
                Catch
                {
                    throw "Unable to create directory at path '$Path'" 
                } 
            }
        }

        if( Test-Path -Path $Path )
        { 
            if( $NewLogFile )
            {
                Write-Information "Log file created at '$Path'"
                return $NewLogFile 
            }
            elseif( $NewLogDir )
            {
                Write-Information "Log directory created at '$Path'"
                return $NewLogDir
            }
            else
            {
                throw "Unknown Error - No log path or directory found and no errors thrown..."
            }
        }
    }
    else
    {
        return $Path
    }
}

function Clear-PSADDelegationLogs
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    [int]$MaxLogCount = 100
    [int]$MaxLogFolderSize = 1GB

    # Exclude the AclBackups and only grab the log files that match our name. 
    $DiscoveredLogs = (Get-ChildItem -Path (Split-Path -Path $script:LogPath -Parent) -Exclude "AclBackups" -Recurse).Where({ $PSItem.BaseName -like "$([System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.ScriptName))*" })

    while( $DiscoveredLogs.Count -ge $MaxLogCount )
    {
        $LogsToRemoveCount = $DiscoveredLogs.Count - $MaxLogCount

        $LogsToRemove = ($DiscoveredLogs | Sort-Object -Property LastWriteTime -Descending | Select-Object -First $LogsToRemoveCount )

        if( $Force -or $PSCmldet.ShouldContinue("Remove $LogsToRemoveCount logs from $($script:LogPath.FullName)", "Remove old log files") )
        {
            $LogsToRemove.FullName | Remove-Item -Verbose:$VerbosePreference
        }

        # Recalcualte
        $DiscoveredLogs = (Get-ChildItem -Path $script:LogPath -Exclude "AclBackups" -Recurse).Where({ $PSItem.BaseName -like "$([System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.ScriptName))*" })
    }

    $LogFolderSize = 0
    $DiscoveredLogs.Size | ForEach-Object { $LogFolderSize += $PSItem }

    while( $LogFolderSize -ge $MaxLogFolderSize )
    {
        $LogsToRemove = ($DiscoveredLogs | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1 )

        if( $Force -or $PSCmldet.ShouldContinue("Remove $LogsToRemoveCount logs from $($script:LogPath.FullName)", "Remove old log files") )
        {
            $LogsToRemoveCount.FullName | Remove-Item -Verbose:$VerbosePreference
        }

        $DiscoveredLogs = (Get-ChildItem -Path $script:LogPath -Exclude "AclBackups" -Recurse).Where({ $PSItem.BaseName -like "$([System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.ScriptName))*" })
        $DiscoveredLogs.Size | ForEach-Object { $LogFolderSize += $PSItem }
    }
}

function Clear-PSAclBackups
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    $MaxAclBackupCount = 100
    $BackupPath = "$(Split-Path -Path $LogPath -Parent)\AclBackups"

    "[INFO][$(Get-Date -Format O)] Counting ACL Backups" >> $LogPath

    $BackupDirectories = (Get-ChildItem -Path $BackupPath -Directory)
    foreach( $BackupDirectory in $BackupDirectories )
    {
        $Backups = (Get-ChildItem -Path $BackupDirectory.Fullname).Where({ ($PSItem.BaseName -like "$($BackupDirectory.BaseName)*") -and ($PSItem.Extension -eq '.bak') })

        while( $Backups.Count -gt $MaxAclBackupCount )
        {
            $AclBackupCountToRemove = ($Backups.Count - $MaxAclBackupCount)

            $AclBackupsToRemove = $Backups | Sort-Object -Property LastWriteTime -Descending | Select-Object -First $AclBackupCountToRemove

            if( $Force -or $PSCmdlet.ShouldContinue("Remove $AclBackupCountToRemove backups from $($BackupDirectory.FullName)","Remove old Acl Backups") )
            {
                "[INFO][$(Get-Date -Format O)] Removing $AclBackupCountToRemove from $($BackupDirectory.FullName)" >> $LogPath
                $AclBackupsToRemove.FullName | Remove-Item -Confirm:$false -Verbose:$VerbosePreference
            }
            else
            {
                "[SKIPPED][$(Get-Date -Format O)] No Backups were removed from $($BackupDirectory.FullName) - Prompt Skipped" >> $LogPath
            }
            # Recalculate
            $Backups = (Get-ChildItem -Path $BackupDirectory.Fullname).Where({ ($PSItem.BaseName -like "$($BackupDirectory.BaseName)*") -and ($PSItem.Extension -eq '.bak') })
        }
        "[INFO][$(Get-Date -Format O)] $($BackupDirectory.FullName) is now under $MaxAclBackupCount files" >> $LogPath
    }
}

function New-PSADDelegationLog
{
    $DefaultLogPath = "C:\Scripts\Logs\$([System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.ScriptName))_$(Get-Date -Format yyyyMMddHHmm).log"

    if( !$global:LogPath )
    {
        $script:LogPath = $DefaultLogPath
    }

    Try
    {
        # Try to get the actual item the logpath points to, if it is a directory, do stuff.
        if( (Get-Item -Path $script:LogPath -ErrorAction Stop) -is [System.IO.DirectoryInfo] )
        {
            $script:LogPath += "\$(Split-Path -Path $DefaultLogPath -Leaf)"
        }
    }
    Catch
    {
        # If we don't have a file extension, assume we mean a directory.
        if( !([System.IO.Path]::GetExtension($script:LogPath)) )
        {
            $script:LogPath += "\$(Split-Path -Path $DefaultLogPath -Leaf)"
        }
    }

    $CheckLog = Confirm-PSADDelegationLog -Path $script:LogPath
    Clear-PSADDelegationLogs

    $AclBackupPath = Confirm-PSADDelegationLog -Path "$(Split-Path -Path $script:LogPath -Parent)\AclBackups" -Directory
    Clear-PSAclBackups

    #region Log File Header
    $Header = ""
    $HeaderTop = "############# $( [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.ScriptName) ) ##############`n"
    $HeaderBottom = ""
    1..($HeaderTop.Length) | Foreach-Object {
        $HeaderBottom += "#" 
    }
    $HeaderBody = "Script Started by: $($env:UserDomain)\$($env:UserName)`nScript Path: $($MyInvocation.ScriptName)`n"
    $Header += $HeaderTop
    $Header += $HeaderBody
    $Header += $HeaderBottom
    $Header >> $LogPath
    #endregion Log File Header
}
#endregion Logging

#region function Request-PSGuidMaps
function Request-PSGuidMaps
{
    Try
    {
        (Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter "(schemaidguid=*)" -Properties lDAPDisplayName,schemaIDGUID).ForEach(
            {
                $ObjectTypeGuidsMap.Add( $PsItem.lDAPDisplayName, ([System.Guid]$PsItem.schemaidGUID).Guid )
            }
        )

        (Get-ADObject -SearchBase (Get-ADRootDSE).configurationNamingContext -LDAPFilter "(&(objectClass=controlAccessRight)(rightsGuid=*))" -Properties displayName,rightsGuid).ForEach(
            {
                $ExtendedRightsMap.Add( $PsItem.displayName, ([System.Guid]$PsItem.rightsGuid).Guid )
            }
        )
    }
    Catch
    {
        $ErrorString =  [string]::Format($ErrorMessages.FAILED_MAP_LOOKUP,[string]::Empty)
        "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
        ">>> ERROR INFO`n$($PSItem | Select-Object -Property *)`n<<< END ERROR INFO"
        Write-Error -Message $ErrorString -Category InvalidOperation
        throw [System.InvalidOperationException]::new($PSItem)
    }
}
#endregion function Request-PSGuidMaps

## Resolve GUID to String functions
#region function Resolve-GuidMapGuidToString

<#
    .SYNOPSIS
    Resolves a known guid to its corresponding string from ActiveDirectory.

    .DESCRIPTION
    Resolves a known guid to its corresponding string from ActiveDirectory.
    Uses supplied respository of guids and a specific guid to look for the correct guid to string in Active Directory.

    .PARAMETER GuidMapName
    Specify the name of the respository of guids to check the guid against. Valid values are ObjectTypeGuidsMap and ExtendedRightsMap.
    SchemaGuidMap is used to look up object types. ExtendedRightsMap is used to lookup extended rights for ACLs. 

    .PARAMETER Guid
    Specify the guid in either string or [System.Guid] format for lookup in Active Directory.
#>
function Resolve-GuidMapGuidToString
{
    param(
        [Parameter(Mandatory=$true,HelpMessage="Specify the name of the respository of guids to check the guid against.")]
        [ValidateSet("ObjectTypeGuidsMap","ExtendedRightsMap")]
        [string]$GuidMapName,

        [Parameter(Mandatory=$true,HelpMessage="Specify the guid in either string or [System.Guid] format for lookup in Active Directory.")]
        [object]$Guid
    )

    [HashTable]$GuidMap = @{}

    switch( $GuidMapName )
    {
        "ObjectTypeGuidsMap" { $GuidMap = $ObjectTypeGuidsMap }
        "ExtendedRightsMap" { $GuidMap = $ExtendedRightsMap }
    }

    # TODO: This may be moved elsewhere, it doesn't fit perfectly here.
    if( ($Guid -eq [System.Guid]::Empty) -or ($Guid -eq ([System.Guid]::Empty).ToString()) )
    {
        return [PSCUstomObject]@{ "Name" = "AllObjects"; "Value" = [System.Guid]::Empty.ToString()}
    }

    if( $Guid -is "System.Guid" )
    {
        return $GuidMap.GetEnumerator().Where({ $PSItem.Value -contains $Guid.Guid }).Name
    }
    elseif( $Guid -is "System.String" )
    {
        return $GuidMap.GetEnumerator().Where({ $PSItem.Value -contains $Guid }).Name
    }
    else
    {
        $ErrorString =  [string]::Format( $ErrorMessages.INVALID_TYPE, $Guid, [System.Guid].ToString() )
        "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
        throw [InvalidOperationException]::new( $ErrorString  )
    }
}
Export-ModuleMember -Function "Resolve-GuidMapGuidToString"
#endregion function Resolve-GuidMapGuidToString

#region function Resolve-ObjectTypeGuidToString
<#
.SYNOPSIS 
Resolves a object type guid from the Active Directory schema to its corresponding string.

.PARAMETER Guid
Specify the guid in either string or [System.Guid] format for lookup in Active Directory.
#>
function Resolve-ObjectTypeGuidToString
{
    param(
        [Parameter(Mandatory=$true,HelpMessage="Specify the guid in either string or [System.Guid] format for lookup in Active Directory.")]
        [object]$Guid
    )

    return Resolve-GuidMapGuidToString -GuidMapName "ObjectTypeGuidsMap" -Guid $Guid
}
Export-ModuleMember -Function "Resolve-ObjectTypeGuidToString"
#endregion function Resolve-ObjectTypeGuidToString

#region function Resolve-ExtendedRightsGuidToString
<#
.SYNOPSIS 
Resolves an extended rights guid from Active Directory to its corresponding string.

.PARAMETER Guid
Specify the guid in either string or [System.Guid] format for lookup in Active Directory.
#>
function Resolve-ExtendedRightsGuidToString
{
    param(
        [Parameter(Mandatory=$true,HelpMessage="Specify the guid in either string or [System.Guid] format for lookup in Active Directory.")]
        [object]$Guid
    )

    return Resolve-GuidMapGuidToString -GuidMapName "ExtendedRightsMap" -Guid $Guid
}
Export-ModuleMember -Function "Resolve-ExtendedRightsGuidToString"
#endregion function Convert-ExtendedRightsGuidToString

## Resolve String to Guid Functions
#region function Resolve-GuidMapStringToGuid
<#
    .SYNOPSIS
    Resolves a known guid to its corresponding string from ActiveDirectory.

    .DESCRIPTION
    Resolves a known guid to its corresponding string from ActiveDirectory.
    Uses supplied respository of guids and a specific guid to look for the correct guid to string in Active Directory.

    .PARAMETER GuidMapName
    Specify the name of the respository of guids to check the guid against. Valid values are ObjectTypeGuidsMap and ExtendedRightsMap.
    SchemaGuidMap is used to look up object types. ExtendedRightsMap is used to lookup extended rights for ACLs. 

    .PARAMETER ObjectName
    Specify the string value you wish to resolve to its guid value.
#>
function Resolve-GuidMapStringToGuid
{
    param(
        [Parameter(Mandatory=$true,HelpMessage="Specify the name of the respository of guids to check the guid against.")]
        [ValidateSet("ObjectTypeGuidsMap","ExtendedRightsMap")]
        [string]$GuidMapName,

        [Parameter(Mandatory=$true,HelpMessage="Specify the string value you wish to resolve to its guid value.")]
        [string]$ObjectName
    )

    [HashTable]$GuidMap = @{}

    switch( $GuidMapName )
    {
        "ObjectTypeGuidsMap" { $GuidMap = $ObjectTypeGuidsMap }
        "ExtendedRightsMap" { $GuidMap = $ExtendedRightsMap }
    }

    if( !$GuidMap.ContainsKey($ObjectName) )
    {
        $ErrorString =  [string]::Format($ErrorMessages.INVALID_HASH_KEY, $ObjectName, [string]::Empty)
        "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
        throw [System.Management.Automation.ItemNotFoundException]::new( $ErrorString )
    }
    else
    {
        return $GuidMap[$ObjectName]
    }
}
Export-ModuleMember -Function "Resolve-GuidMapStringToGuid"
#endregion function Resolve-GuidMapStringToGuid

#region function Resolve-ObjectTypeStringToGuid
<#
.SYNOPSIS 
Resolves a object name of an AD object to its corresponding guid from the AD Schema.

.PARAMETER Guid
Specify the name of the AD object to lookup.
#>
function Resolve-ObjectTypeStringToGuid
{
    param(
        [Parameter(Mandatory=$true,HelpMessage="Specify the name of the AD object to lookup.")]
        [string]$ObjectNameString
    )

    return Resolve-GuidMapStringToGuid -GuidMapName "ObjectTypeGuidsMap" -ObjectName $ObjectNameString
}
Export-ModuleMember -Function "Resolve-ObjectTypeStringToGuid"
#endregion function Resolve-ObjectTypeStringToGuid

#region function Resolve-ExtendedRightsStringToGuid
<#
.SYNOPSIS 
Resolves an extended right name to its corresponding guid from Active Directory.

.PARAMETER Guid
Specify the name of the AD object to lookup.
#>
function Resolve-ExtendedRightsStringToGuid
{
    param(
        [Parameter(Mandatory=$true,HelpMessage="Specify the extended right name to lookup in Active Directory.")]
        [string]$ExtendedRightName
    )

    return Resolve-GuidMapStringToGuid -GuidMapName "ExtendedRightsMap" -ObjectName $ExtendedRightName
}
Export-ModuleMember -Function "Resolve-ExtendedRightsStringToGuid"
#endregion function Resolve-ExtendedRightsStringToGuid

## Show Functions
#region function Show-PSActiveDirectoryObjectTypes
<#
.SYNOPSIS
Lists the different object types available in Active Directory along with their corresponding guid.

.DESCRIPTION
Lists the different object types available in Active Directory along with their corresponding guid. 
No parameters will display a list of all object types. 

.PARAMETER ObjectName
Specify the name of the object to lookup.

.PARAMETER SearchString
Specify a string to search against in the Active Directory Schema. 
#>
function Show-PSActiveDirectoryObjectTypes
{
    Param(
        [Parameter(Mandatory=$false,HelpMessage="Specify the name of the object.")]
        [ValidateNotNull()]
        [string]$ObjectName,

        [Parameter(Mandatory=$false,HelpMessage="Specify a string to search against in the Active Directory Schema.")]
        [ValidateNotNull()]
        [string]$SearchString
    )

    if( $PSBoundParameters.ContainsKey("SearchString") -and $PSBoundParameters.ContainsKey("ObjectName") )
    {
        $ErrorMessage = [string]::Format($ErrorMessages.PARAM_INVALID_OBJSEARCH, [string]::Empty)
        "[WARN][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath

        Write-Warning -Message $ErrorMessage
    }

    if( $PSBoundParameters.ContainsKey("ObjectName") )
    {
        if( $script:ObjectTypeGuidsMap.ContainsKey($ObjectName) )
        {
            return $script:ObjectTypeGuidsMap.GetEnumerator().Where({ $PSItem.Key -eq $ObjectName })
        }
        else
        {
            $ErrorString =  [string]::Format($ErrorMessages."INVALID_AD_OBTYPE","ObjectName",$ObjectName, [string]::Empty)
            "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
            throw [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException]::New( $ErrorString )
        }
    }
    elseif( $PSBoundParameters.ContainsKey("SearchString") )
    {
        $FoundObjectGuidKeys = $script:ObjectTypeGuidsMap.Keys -like "*$SearchString*"

        if( $FoundObjectGuidKeys.Count -lt 1 )
        {
            $ErrorString =  [string]::Format($ErrorMessages."INVALID_AD_OBTYPE_SEARCH","SearchString",$SearchString, [string]::Empty)
            "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
            throw [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException]::New( $ErrorString )
        }
        else
        {
            $ReturnGuidTable = @{}

            foreach( $FoundObjectGuidKey in $FoundObjectGuidKeys )
            {
                $ReturnGuidTable.Add($FoundObjectGuidKey,$script:ObjectTypeGuidsMap.$FoundObjectGuidKey)
            }

            return $ReturnGuidTable
        }
    }
    else
    {
        return $script:ObjectTypeGuidsMap
    }
}
Export-ModuleMember -Function "Show-PSActiveDirectoryObjectTypes"
#endregion function Show-PSActiveDirectoryObjectTypes

#region function Show-PSActiveDirectoryExtendedRights
<#
    .SYNOPSIS
    Lists the different Extended Rights available in Active Directory along with their corresponding guid.

    .DESCRIPTION
    Lists the different object types available in Active Directory along with their corresponding guid. 
    No parameters will display a list of all object types. 

    .PARAMETER ExtendedRight
    Specify the extended right to be looked up.

    .NOTES
    Extended Rights correspond to domain-wide rights that can be granted in Active Directory. 
    These are in addition to the traditional access rights (CreateChild, DeleteChild, GenericRead, etc.). 
    and correspond to specific services. 

    In an ACE the ActiveDirectoryRights enum will be listed as ExtendedRight which then will require an 
    object type that exists in the extended rights table. This table is stored in the Configuration partition.

    Extended rights should be used sparingly and only when specifically needed. They can grant incredible control 
    and access within an Active Directory. 

    Extended Rights Reference Page: https://docs.microsoft.com/en-us/windows/win32/adschema/extended-rights
    Extended Rights Security: https://adsecurity.org/?p=3658
#>
function Show-PSActiveDirectoryExtendedRights
{
    Param(
        [Parameter(Mandatory=$false,HelpMessage="Specify the extended right to be looked up.")]
        [ValidateNotNull()]
        [string]$ExtendedRight
    )

    if( $PSBoundParameters.ContainsKey("ExtendedRight") )
    {
        return $ExtendedRightsMap.GetEnumerator().Where({ $PSItem.Name -eq $ExtendedRight })
    }
    else
    {
        return $script:ExtendedRightsMap
    }
}
Export-ModuleMember -Function "Show-PSActiveDirectoryExtendedRights"
#endregion Show-PSActiveDirectoryExtendedRights

## ACL Functions
#region function New-PSActiveDirectoryAccessRule
<#
    .SYNOPSIS 
    Creates an Active Directory Access rule.

    .DESCRIPTION
    Creates an Active Directory Access rule.
    Does not apply the access rule. Access rules are the core component of an AD DACL and define all the information about an Active Directory right. 

    .PARAMETER Principal
    Specify the principal that the access rule should apply to. UserPrincipalName of samAccountName will all work.
    The unqualified account name will resolve but it will default to local accounts if they match a domain account (e.g. Administrator).

    .PARAMETER ADRight
    Specify the permission being granted. Specifically this is an Active Directory Right permission. 
    https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=dotnet-plat-ext-5.0

    .PARAMETER AccessControlType
    Specify the either Allow or Deny.
    https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.accesscontroltype?view=dotnet-plat-ext-5.0

    .PARAMETER InheritanceType
    Specify the level of inheritance the access rule will have on subordinate objects (e.g. Children, Descendents, All, etc.).
    https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurityinheritance?view=dotnet-plat-ext-5.0

    .PARAMETER TargetObjectType
    Specify the type of object the access rule applies to. These objects must be present in the Active Directory schema. Defaults to all. 
    Use the Show-PSActiveDirectoryObjectTypes cmdlet to see a list of types or search for an object based on a given keyword. 

    .PARAMETER ExtendedRight
    Specify the extended right to apply. These must be present in the Active Directory Extended Rights list in the Configuration partition. 
    Use the Show-PSActiveDirectoryExtendedRights cmdlet to see a list of extended rights. 

    .PARAMETER InheritedObjectType
    Specify the type of object this rule applies to. These objects must be present in the Active Directory schema. Defaults to all object types. 
    Dependes on the InheritanceType to determine how this is applied. 

    .PARAMETER Server
    Specify the domain controller to perform this action against.

    .PARAMETER DomainName
    Specify the fully qualified domain name of the domain to target.
#>
function New-PSActiveDirectoryAccessRule
{
    [CmdletBinding()]
    Param(

        [Parameter(Mandatory=$true,HelpMessage="Specify the principal that the access rule should apply to. UserPrincipalName of samAccountName will all work.")]
        [ValidateNotNull()]
        [string]$Principal,

        [Parameter(Mandatory=$true,HelpMessage="Specify the permission being granted.")]
        # Reference Link: https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=dotnet-plat-ext-5.0
        [ActiveDirectoryRights]$ADRight,

        [Parameter(Mandatory=$true,HelpMessage="Specify the either Allow or Deny.")]
        # Reference Link: https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.accesscontroltype?view=dotnet-plat-ext-5.0
        [System.Security.AccessControl.AccessControlType]$AccessControlType,

        [Parameter(Mandatory=$true,HelpMessage="Specify the level of inheritance the access rule will have on subordinate objects (e.g. Children, Descendents, All, etc.).")]
        # Reference Link: https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurityinheritance?view=dotnet-plat-ext-5.0
        [ActiveDirectorySecurityInheritance]$InheritanceType,

        [Parameter(Mandatory=$false,HelpMessage="Specify the type of object the access rule applies to. Defaults to all.")]
        [ValidateNotNull()]
        [string]$TargetObjectType,

        [Parameter(Mandatory=$false,HelpMessage="Specify the extended right to apply.")]
        [ValidateNotNull()]
        [string]$ExtendedRight,

        [Parameter(Mandatory=$false,HelpMessage="Specify the type of object this rule applies to. Defaults to this object only.")]
        [ValidateNotNull()]
        [string]$InheritedObjectType,

        [Parameter(Mandatory=$false,HelpMessage="Specify the fully qualified domain name of the domain to target.")]
        [string]$DomainName,

        [Parameter(Mandatory=$false,HelpMessage="Specify the domain controller to perform this action against.")]
        [ValidateNotNull()]
        [string]$Server
    )

    Begin
    {
        # --- Declare Variables ---
        [System.Security.Principal.SecurityIdentifier]$PrincipalSid = $null
        [string]$RegexDN = "^(?:(?<cn>CN=(?<name>[^,]*)),)?(?:(?<path>(?:(?:CN|OU)=[^,]+,?)+),)?(?<domain>(?:DC=[^,]+,?)+)$" # Matches DistinguishedNames

        # --- Parameter Logging
        "[INFO][$(Get-Date -Format O)] Started function 'Set-PSActiveDirectoryAccessRule'" >> $LogPath
        "[INFO][$(Get-Date -Format O)] Supplied parameters" >> $LogPath
        "PSBoundParameters:`n $(Out-String -InputObject $PSBoundParameters)`n Passed Arguments:`n$(Out-String -InputObject $args)" >> $LogPath

        # --- Initialize Logging
        #New-PSADDelegationLog

        # --- Parameter Validation ---
        if( $PSBoundParameters.ContainsKey("TargetObjectType") )
        {
            # Validate TargetObject and InputObjectType
            if( !$script:ObjectTypeGuidsMap.ContainsKey( $TargetObjectType ) )
            {
                if( !$script:ObjectTypeGuidsMap.ContainsValue( $TargetObjectType ) )
                {
                    $ErrorString =  [string]::Format($ErrorMessages.INVALID_AD_OBTYPE,"TargetObjectType",$TargetObjectType)
                    "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
                    throw [System.ArgumentException]::new( $ErrorString )
                }
                else # If a guid was provided
                {
                    ## TODO: We don't need to actually do anything with this data. Leaving this here for logging
                    $null = Resolve-ObjectTypeGuidToString -Guid $TargetObjectType # Guid to String
                }
            }
            else
            {
                $TargetObjectType = $script:ObjectTypeGuidsMap[$TargetObjectType] # String to GUID
            }
        }
        else
        {
            $TargetObjectType = [System.Guid]::Empty.ToString() # All Zero's GUID is this object only. 
        }

        if( !$PSBoundParameters.ContainsKey("InheritedObjectType") )
        {
            $InheritedObjectType = [System.Guid]::Empty.ToString() # All Zero's GUID is this object only
        }
        else
        {
            if( !$script:ObjectTypeGuidsMap.ContainsKey( $InheritedObjectType ) )
            {
                
                if( !$script:ObjectTypeGuidsMap.ContainsValue( $InheritedObjectType ) )
                {
                    $ErrorString =  [string]::Format($ErrorMessages.INVALID_AD_OBTYPE,"InheritedObjectType",$InheritedObjectType)
                    "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
                    throw [System.ArgumentException]::new( $ErrorString )
                }
                else # If a guid was provided
                {
                    ## TODO: We don't need to actually do anything with this data. Leaving this here for logging
                    $null = Resolve-ObjectTypeGuidToString -Guid $InheritedObjectType # Guid to String
                }
            }
            else
            {
                $InheritedObjectType = $script:ObjectTypeGuidsMap[$InheritedObjectType] # String to Guid
            }
        }

        # If Extended right comes in as a GUID, convert it to a value.
        if( $script:ExtendedRightsMap.ContainsValue($ExtendedRight) )
        {
            $ExtendedRight = Resolve-ExtendedRightsGuidToString -Guid $ExtendedRight
        }

        # Validate ExtendedRight value if specified
        if( ($ADRight -eq [ActiveDirectoryRights]::ExtendedRight) -and  (!$script:ExtendedRightsMap.ContainsKey($ExtendedRight)) )
        {
            $ErrorString =  [string]::Format($ErrorMessages.INVALID_AD_EXTENDEDRIGHT,"ExtendedRight",$ExtendedRight, [string]::Empty)
            "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
            throw [System.ArgumentException]::new( $ErrorString )
        }
        elseif( (!$ExtendedRight) -and ($ADRight -eq [ActiveDirectoryRights]::ExtendedRight) )
        {
            $ErrorString =  [string]::Format($ErrorMessages.PARAM_INVALID_EXTRIGHT, [string]::Empty)
            "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
            throw [System.ArgumentException]::new( $ErrorString )

        }
        elseif ( $PSBoundParameters.ContainsKey("ExtendedRight") -and $ADRight -ne [ActiveDirectoryRights]::ExtendedRight )
        {
            $ErrorMessage = [string]::Format($ErrorMessages.PARAM_INVALID_EXTRIGHT_EXTRA, [string]::Empty)
            "[WARN][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
            
            Write-Warning -Message $ErrorMessage
        }

        # DomainName Parameter
        if( !$PSBoundParameters.ContainsKey("DomainName") )
        {
            $DomainName = (Get-ADDomain -Current LocalComputer).DNSRoot # Default to current domain.
        }
        else
        {
            Try
            {
                $null = Resolve-DnsName -Name $DomainName -ErrorAction Stop
            }
            Catch
            {
                $ErrorMessage = [string]::Format($ErrorMessages.INVALID_DOMAINNAME, $DomainName, [string]::Empty)
                "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
                ">>> ERROR INFO`n$($PSItem | Select-Object -Property *)`n<<< END ERROR INFO"
                
                Write-Error -Message $ErrorMessage -Category ConnectionError
                throw $PSItem
            }
        }
        "[INFO][$(Get-Date -Format O)] Selected domain of '$DomainName'" >> $LogPath

        # Server Parameter
        if( !$PSBoundParameters.ContainsKey("Server") )
        {
            # Attempt to DC Locate a DC
            $Server = (Get-ADDomainController -Discover -DomainName $DomainName).HostName[0] # We get an array, grab the first item.
        }
        else
        {
            Try
            {
                $null = Get-ADDomainController -Identity $Server -Server $DomainName
                "[INFO][$(Get-Date -Format O)] Successfully created a connection with '$Server' in $DomainName" >> $LogPath
            }
            Catch
            {
                $ErrorMessage = [string]::Format($ErrorMessages.INVALID_DOMAINCONTROLLER, $Server, $DomainName, [string]::Empty)
                "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
                ">>> ERROR INFO`n$($PSItem | Select-Object -Property *)`n<<< END ERROR INFO"

                Write-Error -Message $ErrorMessage -Category ConnectionError
                throw $PSItem
            }
        }
        "[INFO][$(Get-Date -Format O)] Selected server of '$Server'" >> $LogPath
    }

    Process
    {
        #region Convert the $Principal to $PrincipalSid
        ## TODO: FIgure out how to prevent the SID from resolving to the local machine SID for local stuff?

        # First, try blindly to convert the Principal to a SID, if a SID was provided this moves things along and we don't need to do extra. 
        Try
        {
            $PrincipalSid = [System.Security.Principal.SecurityIdentifier]::new($Principal)
        }
        Catch
        {
            # Catch intentionally left blank, we just want to try that and ignore the error we get. We deal with it more constructively later. 
        }

        if( !$PrincipalSid )
        {
            if( $Principal -match "@" ) # UPN
            {
                $PrincipalName = ($Principal.split("@"))[0] # Spilt at the @ and give us the first value

                if( $Principal.split("@")[1] -ne $DomainName )
                {
                    $ErrorMessage = [String]::Format($ErrorMessages.AD_PRINCIPAL_DOMAIN_MISMATCH,$DomainName, [string]::Empty)
                    "[WARN][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath

                    Write-Warning -Message $ErrorMessage
                }
            }
            elseif( $Principal -match "\\" ) # NT
            {
                $PrincipalName = ($Principal.split("\"))[1] # Spilt at the @ and give us the second value

                if( $DomainName -notlike "*$($Principal.split("\")[0])*" )
                {
                    $ErrorMessage = [String]::Format($ErrorMessages.AD_PRINCIPAL_DOMAIN_MISMATCH,$DomainName, [string]::Empty)
                    "[WARN][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath

                    Write-Warning -Message $ErrorMessage
                }
            }
            elseif( $Principal -match $RegexDN ) # DistinguishedName
            {
                $PrincipalDomain = ($Principal -split "DC=",2)[1] -replace ",DC=","." # Trim off the principal information for the Domain Information

                if( $DomainName -ne $PrincipalDomain )
                {
                    $ErrorMessage = [String]::Format($ErrorMessages.AD_OBJ_NOT_FOUND, $Principal, $DomainName, [string]::Empty)
                    "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath

                    throw [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException]::new($ErrorMessage)
                }

                $PrincipalName = $Principal
            }
            else
            {
                # Covers some common ACE Entries (Everyone, NT Authority, etc.).
                if( $WellKnownPrincipals.Keys -contains $Principal )
                {
                    $PrincipalName = $Principal
                }
                else
                {
                    $ErrorMessage = [String]::Format($ErrorMessages.AD_PRINCIPAL_NAME_FORMAT_ERR,{0}, [string]::Empty)
                    throw [System.InvalidOperationException]::new( $ErrorMessage )
                }
            }

            "[INFO][$(Get-Date -Format O)] Successfully identified a principal '$PrincipalName'" >> $LogPath

            # By now we should have a PrincipalName
            Try
            {
                if( $WellKnownPrincipals.Keys -contains $PrincipalName )
                {
                    $ObjectSid = [System.Security.Principal.NTAccount]::new($Principal).Translate([System.Security.Principal.SecurityIdentifier])
                }
                else
                {
                    # Look up based on samAccountName (resolved from NT Name or UPN)
                    $ObjectSid = (Get-ADObject -Filter "Name -eq '$PrincipalName'" -Properties objectSid -Server $Server).objectSid.Value

                    if( !$ObjectSid ) # Used to lookup based on DN
                    {
                        $ObjectSid = (Get-ADObject -Filter "DistinguishedName -eq '$PrincipalName'" -Properties objectSid -Server $Server).objectSid.Value
                    }
                }

                "[INFO][$(Get-Date -Format O)] Successfully converted '$PrincipalName' to its SID '$ObjectSID'" >> $LogPath
            }
            Catch
            {
                $ErrorMessage = [string]::Format($ErrorMessages.AD_OBJ_NOT_FOUND, $Principal, $DomainName, [string]::Empty)
                "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
                ">>> ERROR INFO`n$($PSItem | Select-Object -Property *)`n<<< END ERROR INFO"

                Write-Error -Message $ErrorMessage -Category ObjectNotFound
                throw $PSITem
            }

            # Convert the binary SID object to an IdentityReference
            Try
            {
                $PrincipalSid = [System.Security.Principal.SecurityIdentifier]::new($ObjectSid) 
                "[INFO][$(Get-Date -Format O)] Attemping to convert '$ObjectSid' to a Security Identifier" >> $LogPath
            }
            Catch
            {
                $ErrorMessage = [String]::Format($ErrorMessages.FAILED_AD_IDREF_TRANSLATE, $Principal, [string]::Empty)
                "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
                ">>> ERROR INFO`n$($PSItem | Select-Object -Property *)`n<<< END ERROR INFO"

                Write-Error -Message $ErrorMessage -Category InvalidOperation
                throw $PSITem
            }
        }

        # Just in case stuff "worked" but it didn't. 
        if( !$PrincipalSid )
        {
            $ErrorString =  [string]::Format($ErrorMessages.AD_OBJ_NOT_FOUND, $Principal, $DomainName, [string]::Empty)
            "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
            throw [System.Management.Automation.ItemNotFoundException]::new( $ErrorString )
            ## TODO: Logging: $(($Error | Select-Object -First 2).GetEnumerator().Where({ $PSItem.CategoryInfo -like "*Get-ADObject*" }).Exception -join ",")
        }
        "[INFO][$(Get-Date -Format O)] Successfuly converted '$ObjectSid' to a Security Identifier '$ObjectSID'" >> $LogPath
        #endregion

        # We handle ExtendedRights and traditional rights differently
        if( $PSBoundParameters.ADRight -eq [ActiveDirectoryRights]::ExtendedRight )
        {
            # ObjectType is the ExtendedRight
            # Lookup ExtendedRight from ExtendedRight table. 
            if( !$InheritedObjectType )
            {
                $AccessRule = [ActiveDirectoryAccessRule]::new($PrincipalSid,$ADRight,$AccessControlType,$ExtendedRightsMap.$ExtendedRight,$InheritanceType)
            }
            else
            {
                $AccessRule = [ActiveDirectoryAccessRule]::new($PrincipalSid,$ADRight,$AccessControlType,$ExtendedRightsMap.$ExtendedRight,$InheritanceType,$InheritedObjectType)
            }
        }
        else # Traditional Rights
        {
            if( $TargetObjectType -and $InheritedObjectType )
            {
                $AccessRule = [ActiveDirectoryAccessRule]::new($PrincipalSid,$ADRight,$AccessControlType,$TargetObjectType,$InheritanceType,$InheritedObjectType)
            }
            elseif( $TargetObjectType )
            {
                $AccessRule = [ActiveDirectoryAccessRule]::new($PrincipalSid,$ADRight,$AccessControlType,$TargetObjectType,$InheritanceType)
            }
            elseif( $InheritedObjectType )
            {
                $AccessRule = [ActiveDirectoryAccessRule]::new($PrincipalSid,$ADRight,$AccessControlType,$InheritanceType,$InheritedObjectType)
            }
            else
            {
                $ErrorString =  [string]::Format($ErrorMessages.INVALID_ARG_SET,$PSBoundParameters.Keys -join ",")
                "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
                throw [System.ArgumentException]::new( $ErrorString )
            }
        }
        "[INFO][$(Get-Date -Format O)] Successfuly created an access rule for '$PrincipalName'" >> $LogPath
        [string]::Format( "Access rule attributes:`n $(Out-String -InputObject $AccessRule)" ) >> $LogPath
        return $AccessRule
    }
}
Export-ModuleMember -Function "New-PSActiveDirectoryAccessRule"
#endregion function New-PSActiveDirectoryAccessRule

#region function Set-PSActiveDirectoryAccessRule

<#
    .SYNOPSIS
    Adds the Active Directory right to the ACL of the target container in Active Directory. 

    .DESCRIPTION
    Adds the Active Directory right to the ACL of the target container in Active Directory. 
    Requires an Active Directory Access Rule to be created with the New-PSActiveDirectoryAccessRule. 

    .PARAMETER TargetContainer
    Specify the container or organizational unit to apply the access rule.
    Supports the full Distinguished Name of the OU or looking up the OU name. However, DN is preferred. 

    .PARAMETER Server
    Specify the domain controller to perform this action against.

    .PARAMETER DomainName
    Specify the fully qualified domain name of the domain to target.

    .PARAMETER AccessRule
    Specify access rule object to be applied to the TargetContainer.

    .PARAMETER DomainCredential
    Specify the credentials for the domain supplied by DomainName.

    .PARAMETER SkipBackup
    Skip creating backups of existing ACLs before applying the new ACE.

    .PARAMETER Passthru
    Returns the ActiveDirectoryAccessRule object back to the console.

    .PARAMETER Force
    Bypasses the confirmation before applying the AccessRule.
#>
function Set-PSActiveDirectoryAccessRule
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        [Parameter(Mandatory=$true,HelpMessage="Specify the container or organizational unit to apply the access rule.")]
        [ValidateNotNull()]
        [Alias("TargetOU","TargetObject")]
        [string]$TargetContainer,

        [Parameter(Mandatory=$false,HelpMessage="Specify the domain controller to perform this action against.")]
        [ValidateNotNull()]
        [string]$Server,

        [Parameter(Mandatory=$false,HelpMessage="Specify the fully qualified domain name of the domain to target.")]
        [string]$DomainName,

        [PSCredential]$DomainCredential,

        [Parameter(Mandatory=$true,HelpMessage="Specify access rule object to be applied to the TargetContainer.")]
        [ActiveDirectoryAccessRule]$AccessRule,

        [Parameter(Mandatory=$false,HelpMessage="Skip creating backups of existing ACLs before applying the new ACE.")]
        [switch]$SkipBackup,
        
        [Parameter(Mandatory=$false,HelpMessage="Returns the ActiveDirectoryAccessRule object back to the console.")]
        [switch]$Passthru,

        [Parameter(Mandatory=$false,HelpMessage="Bypasses the confirmation before applying the AccessRule.")]
        [switch]$Force
    )

    Begin
    {
        # Variables
        [string]$RegexDN = "^(?:(?<cn>CN=(?<name>[^,]*)),)?(?:(?<path>(?:(?:CN|OU)=[^,]+,?)+),)?(?<domain>(?:DC=[^,]+,?)+)$" # Matches DistinguishedNames
        [Microsoft.ActiveDirectory.Management.ADObject]$TargetContainerObj = $null
        [string]$TargetContainerDN = $null
        [string]$TargetPSDrive = $null
        [bool]$SkipRemovePSDrive = $false

        # --- Initialize Logging
        #New-PSADDelegationLog

        "[INFO][$(Get-Date -Format O)] Started function 'Set-PSActiveDirectoryAccessRule'" >> $LogPath
        "[INFO][$(Get-Date -Format O)] Supplied parameters" >> $LogPath
        "PSBoundParameters:`n $(Out-String -InputObject $PSBoundParameters)`n Passed Arguments:`n$(Out-String -InputObject $args)" >> $LogPath

        # DomainName Parameter
        if( !$PSBoundParameters.ContainsKey("DomainName") )
        {
            $DomainName = (Get-ADDomain -Current LocalComputer).DNSRoot # Default to current domain.
        }
        else
        {
            Try
            {
                $null = Resolve-DnsName -Name $DomainName -ErrorAction Stop
            }
            Catch
            {
                $ErrorMessage = [String]::Format($ErrorMessages.INVALID_DOMAINNAME, $DomainName, [string]::Empty)
                "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
                ">>> ERROR INFO`n$($PSItem | Select-Object -Property *)`n<<< END ERROR INFO"

                Write-Error -Message $ErrorMessage -Category ConnectionError
                throw $PSItem
            }
        }
        "[INFO][$(Get-Date -Format O)] Selected domain of '$DomainName'" >> $LogPath

        # Server Parameter
        if( !$PSBoundParameters.ContainsKey("Server") )
        {
            # Attempt to DC Locate a DC
            $Server = (Get-ADDomainController -Discover -DomainName $DomainName).HostName[0] # We get an array, grab the first item.
        }
        else
        {
            Try
            {
                $null = Get-ADDomainController -Identity $Server -Server $DomainName
            }
            Catch
            {
                $ErrorMessage = [String]::Format($ErrorMessages.INVALID_DOMAINCONTROLLER, $Server, $DomainName, [string]::Empty)
                "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
                ">>> ERROR INFO`n$($PSItem | Select-Object -Property *)`n<<< END ERROR INFO"

                Write-Error -Message $ErrorMessage -Category ConnectionError
                throw $PSItem
            }
        }
        "[INFO][$(Get-Date -Format O)] Selected server of '$Server'" >> $LogPath

        #region Verify Container
        if( $TargetContainer -match $RegexDN ) # Will match a distinguished name. 
        {
            $TargetContainerObj = Get-ADObject -Filter "DistinguishedName -eq '$TargetContainer'" -Properties DistinguishedName -Server $Server -ErrorAction Ignore

            # If the object lies in a different partition than the default, we need to include a search scope. 
            if( !$TargetContainerObj )
            {
                # Look up the ConfigDN
                $TargetConfigDN = (Get-ADRootDSE -Server $Server).configurationNamingContext
                $TargetContainerObj = Get-ADObject -Filter "DistinguishedName -eq '$TargetContainer'" -SearchBase $TargetConfigDN -Properties DistinguishedName -Server $Server -ErrorAction Ignore
            }
        }
        else # If it doesn't match a DistinguishedName, we do some looking up. 
        {
            $TargetContainerObjLdapFilter = "(&(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=domainDNS))(name=$TargetContainer))"
            $TargetContainerObj = Get-ADObject -LDAPFilter $TargetContainerObjLdapFilter -Properties DistinguishedName -Server $Server -ErrorAction Stop
            if( $TargetContainerObj -is "System.Array")
            {
                throw [System.InvalidOperationException]::new( [string]::Format($ErrorMessages.TOO_MANY_VALUES,$TargetContainer) )
            }
        }

        if( !$TargetContainerObj )
        {
            $ErrorMessage = [String]::Format($ErrorMessages.AD_OBJ_NOT_FOUND, $TargetContainer, $DomainName, [string]::Empty)
            "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
            throw [System.Management.Automation.ItemNotFoundException]::new( $ErrorMessage )
            ## TODO: Logging : $(($Error | Select-Object -First 2).GetEnumerator().Where({ $PSItem.CategoryInfo -like "*Get-ADObject*" }).Exception -join ",")
        }
        #endregion Verify Container

        $TargetContainerDN = $TargetContainerObj.DistinguishedName
        "[INFO][$(Get-Date -Format O)] Successfully resolved container as '$TargetContainerDN' in $DomainName" >> $LogPath

        # Other Parameters are passed directly to New-PSActiveDirectoryAccessRule
    }

    Process
    {
        if( $DomainName -ne (Get-ADDomain -Current LocalComputer).DNSRoot )
        {
            $RemoteDomain = Get-ADDomain -Identity $DomainName -Server $Server
            $RemoteDomainNBN = $RemoteDomain.NetBiosName

            # If there is an existing PSDrive, we want to perserve it.
            if( $TargetPSDrive = Get-PSDrive -Name $RemoteDomainNBN -ErrorAction Ignore )
            {
                $SkipRemovePSDrive = $true 
                "[INFO][$(Get-Date -Format O)] Using existing PSDrive for $RemoteDomainNBN" >> $LogPath
            }
            else
            {
                Try
                {
                    # Because of how AD handles Get-Acl and Set-Acl we need to create hard connections using the PSDrive system.
                    if( $DomainCredential )
                    {
                        $OldProgressPreference = $ProgressPreference # Hide the progress bar
                        $ProgressPreference = 'SilentlyContinue'
                        $null = New-PSDrive -Name $RemoteDomainNBN -PSProvider ActiveDirectory -Root "" -Server $Server -Credential $DomainCredential
                        $ProgressPreference = $OldProgressPreference
                    }
                    else
                    {
                        $OldProgressPreference = $ProgressPreference # Hide the progress bar
                        $ProgressPreference = 'SilentlyContinue'
                        $null = New-PSDrive -Name $RemoteDomainNBN -PSProvider ActiveDirectory -Root "" -Server $Server 
                        $ProgressPreference = $OldProgressPreference
                    }

                    $TargetPSDrive = $RemoteDomainNBN
                    "[INFO][$(Get-Date -Format O)] Using PSDrive identified by $RemoteDomainNBN" >> $LogPath
                }
                Catch
                {
                    $ErrorMessage = [String]::Format($ErrorMessages.FAILED_ADWS_CONNECT,$DomainName, [string]::Empty)
                    "[ERROR][$(Get-Date -Format O)] $ErrorMessage" >> $LogPath
                    ">>> ERROR INFO`n$($PSItem | Select-Object -Property *)`n<<< END ERROR INFO"

                    Write-Error -Message $ErrorMessage -Category ConnectionError
                    throw $PSItem
                }
            }
        }
        else
        {
            $TargetPSDrive = "AD"
            "[INFO][$(Get-Date -Format O)] Using default PSDrive for Active Directory" >> $LogPath
        }

        $AclBackupPath = Confirm-PSADDelegationLog -Path "$AclBackupPath\$RemoteDomainNBN" -Directory
        $AclBackupFile = "$AclBackupPath\$($TargetPSDrive)_$($TargetContainerObj.Name)_$(Get-Date -Format yyyyMMdd_HHmmss).bak"
        $TargetACL = Get-Acl -Path "$($TargetPSDrive):\$TargetContainerObj"
        
        if( (!$PSBoundParameters.ContainsKey("SkipBackup")) -and $LogPath ) # We only want to store the backup if we aren't skipping backups and if we have a valid log location.
        {
            $null = Export-Clixml -Path $AclBackupFile -InputObject ($TargetAcl | Select-Object -Property *)
        }
        else
        {
            if( $SkipBackup )
            {
                Write-Verbose "SkipBackup switch provided. Not backing up ACLs before applying new."
            }
            else
            {
                Write-Verbose "No valid log path available. Not backing up ACLs before applying new." 
            }
        }

        "################# ORIGINIAL ACL DATA #################`nPath to Restore File: $AclBackupFile`n" >> $LogPath
        "Command to Restore ACL Object: Import-Clixml -Path $AclBackupFile`n" >> $LogPath
        "$(Out-String -InputObject (Get-Acl C:\ | Select-Object -Property *))`n###################################################" >> $LogPath

        $TargetAcl.AddAccessRule( $AccessRule )
        if( $Force -or $PSCmdlet.ShouldContinue( "Apply an Active Directory Access Rule to '$TargetContainerObj' in $DomainName", "Apply an Active Directory Access Rule in $DomainName" ) )
        {
            $NewAccessRuleObj = Set-ACL -Path "$($TargetPSDrive):\$TargetContainerObj" -AclObject $TargetACL -Passthru -ErrorAction Stop -Whatif:$WhatIfPreference -Verbose:$VerbosePreference

            if( $Passthru )
            {
                return $NewAccessRuleObj
            }
            else
            {
                # Use Write-Output over Write-Host because it is standard. However, make it purty.
                $OldFG = $Host.UI.RawUI.ForegroundColor
                $Host.UI.RawUI.ForegroundColor = "Cyan"
                $SuccessMessage = "Successfully Applied the AccessRule to '$TargetContainerObj' in $DomainName"
                "[SUCCESS][$(Get-Date -Format O)] $SuccessMessage" >> $LogPath
                Write-Output -InputObject $SuccessMessage
                $Host.UI.RawUI.ForegroundColor = $OldFG
            }
        }
        else
        {
            $OldFG = $Host.UI.RawUI.ForegroundColor
            $Host.UI.RawUI.ForegroundColor = "Yellow"
            $SkippedMessage = "Did not apply the AccessRule to '$TargetContainerObj' in $DomainName. Confirmation skipped"
            "[SKIPPED][$(Get-Date -Format O)] $SuccessMessage" >> $LogPath
            Write-Output -InputObject $SkippedMessage
            $Host.UI.RawUI.ForegroundColor = $OldFG
        }
    }
    End
    {
        # Clean up any PSDrives we created.
        if( ($TargetPSDrive -ne "AD") -and (!$SkipRemovePSDrive) )
        {
            if( (Get-Location).Path -like "$TargetPSDrive*" )
            {
                Set-Location C:
            }

            Remove-PSDrive -Name $TargetPSDrive -PSProvider ActiveDirectory -Verbose:$VerbosePreference
            "[INFO][$(Get-Date -Format O)] Removed PSDrive $TargetPSDrive" >> $LogPath
        }
        "[COMPLETE][$(Get-Date -Format O)] Completed Set-PSActiveDirectoryAccessRule" >> $LogPath
    }
}
Export-ModuleMember -Function "Set-PSActiveDirectoryAccessRule"
#endregion function Set-PSActiveDirectoryAccessRule

#region function Set-PSActiveDirectoryAuditRule
<#
.SYNOPSIS 
Creates an Active Directory Audit rule and applies it. 

.DESCRIPTION
Creates an Active Directory Audit rule and applies it to the supplied target object or container. 

.PARAMETER TargetDN
[string] Specify the distinguished name of the target container/OU.
ParameterSet: All

.PARAMETER AuditFlags
[System.Security.AccessControl.AuditFlags] Specify which type of auditing is needed: Success, Failure, or Both.
AuditFlags is a System.Flags value so the values can be added together. For both success and failure auditing, you can specify one of the following values as input.
- 3
- [System.Security.AccessControl.AuditFlags]"Success"+"Failure"
- [System.Security.AccessControl.AuditFlags]::Success + System.Security.AccessControl.AuditFlags]::Failure
ParameterSet: All
Reference: https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.auditflags

.PARAMETER AuditPrincipal
[string] Specify which principal you want to audit. Defaults to Everyone.
ParameterSet: All

.PARAMETER InheritanceType
[System.DirectoryServices.ActiveDirectorySecurityInheritance] Specify what kind of inheritance you want on this entry.
ParameterSet: All

.PARAMETER ObjectType
[string] Specify which object types you want to target with the SACL.
ParameterSet: All

.PARAMETER InheritObjectType
[string] Specify which child object types you want to inherit the SACL.
ParameterSet: All

.PARAMETER TargetPermissions
[System.DirectoryServices.ActiveDirectoryRights] Specify which permissions you want to audit. Defaults to Generic All (Full Control).
ParameterSet: All

.EXAMPLE
PS> Set-PSActiveDirectoryAuditRule -TargetDN DC=CONTOSO,DC=COM -AuditFlags Success
Applies Generic All (Full Control) success auditing for the Everyone principal on the domain root of CONTOSO.COM 

.EXAMPLE
PS> Set-PSActiveDirectoryAuditRule -TargetDN DC=CONTOSO,DC=COM -AuditFlags 3
Applies Generic All (Full Control) success and failure auditing for the Everyone principal on the domain root of CONTOSO.COM 

.EXAMPLE
PS> Set-PSActiveDirectoryAuditRule -TargetDN DC=CONTOSO,DC=COM -AuditFlags Success -InheritanceType All
Applies Generic All (Full Control) success for the Everyone principal on the domain root of CONTOSO.COM with inheritance set to "This object and all descendent objects". 

.EXAMPLE
PS> $Permissions = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty + [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
PS> Set-PSActiveDirectoryAuditRule -TargetDN DC=CONTOSO,DC=COM -AuditFlags Success -InheritanceType Descendents -InheritedObjectType groupPolicyContainer
Applies Generic All (Full Control) success for the Everyone principal on the domain root of CONTOSO.COM with inheritance set to "Descendent groupPOliycContainers".

.NOTES
#>
function Set-PSActiveDirectoryAuditRule
{
    param(
        [Parameter(Mandatory=$true,HelpMessage="Specify the distinguished name of the target container/OU.")]
        [string]$TargetDN,

        [Parameter(Mandatory=$false,HelpMessage="Specify which principal you want to audit. Defaults to Everyone.")]
        [string]$AuditPrincipal = "Everyone",

        [Parameter(Mandatory=$false,HelpMessage="Specify which permissions you want to audit. Defaults to Generic All (Full Control).")]
        [System.DirectoryServices.ActiveDirectoryRights]$TargetPermissions = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,

        [Parameter(Mandatory=$true,HelpMessage="Specify which type of auditing is needed: Success, Failure, or Both.")]
        [System.Security.AccessControl.AuditFlags]$AuditFlags,

        [Parameter(Mandatory=$false,HelpMessage="Specify what kind of inheritance you want on this entry.")]
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType,

        [Parameter(Mandatory=$false,HelpMessage="Specify which object types you want to target with the SACL.")]
        [string]$ObjectType,

        [Parameter(Mandatory=$false,HelpMessage="Specify which child object types you want to inherit the SACL.")]
        [string]$InheritedObjectType

    )

    Begin
    {
        # Variables
        $ObjectGuid = $null
        $InheritedObjectGuid = $null
        $OriginalACL = $null
        $NewACL = $null
        $AuditPrincipalSid = $null

        # Domain Variables
        $DomainObj = Get-ADDomain -Current LocalComputer
        $DomainName = $DomainObj.DnsRoot
        $DomainController = (Get-ADDomainController -Discover -DomainName $DomainName -AvoidSelf).Hostname[0] # Returns array, choose the first element.
    }

    Process
    {
        # Verify the ObjectDN and grab the original ACL from it. 
        try
        {
            if( (Get-ADObject -Filter "DistinguishedName -eq '$TargetDN'" -Server $DomainController -ErrorAction Stop) )
            {
                $OriginalACL = Get-Acl -Path "AD:\$TargetDN" -Audit
                $NewACL = $OriginalACL # Copy Old
            }
            else
            {
                throw "Unable to locate the item defined by '$TargetDN' in the domain - Exiting"
            }
        }
        catch
        {
            Write-Error -Message "Unable to ACL on the object specified by the object distinguishedName '$TargetDN' - $($PSitem.Exception.Message)"
            throw $PSitem
        }

        #region Convert Object Names to GUIDs
        # Only care if the ObjectType parameter was specified. If it was, convert it to the necessary guid. 
        if( $PSBoundParameters.ContainsKey("ObjectType") )
        {
            # Check the type against the GUIDMap. 
            if( !($ObjectTypeGuidsMap.ContainsKey($ObjectType)) )
            {
                Write-Error -Message "Failed to set SACL on object '$ObjectType' - Type Not Found - $($PSItem.Exception.Message)"
                throw $PSitem
            }
            else
            {
                $ObjectGuid = $ObjectTypeGuidsMap.$ObjectType
            }
        }

        # Only care about InheritedObjectType if it was specified. If it was, convert it to the necessary guid.
        if( $PSBoundParameters.ContainsKey("InheritedObjectType") )
        {
            # Check the type against the GUIDMap. 
            if( !($ObjectTypeGuidsMap.ContainsKey($InheritedObjectType)) )
            {
                Write-Error -Message "Failed to set SACL on object '$InheritedObjectType' - Type Not Found - $($PSItem.Exception.Message)"
            }
            else
            {
                $InheritedObjectGuid = $ObjectTypeGuidsMap.$InheritedObjectType
            }
        }
        #endregion Convert Object Names to GUIDs

        #region Convert Principals to their References        
        # Convert Any Principals to their IdentityReference
        if( $AuditPrincipal -eq "Everyone" )
        {
            $AuditPrincipalSid = [System.Security.Principal.NTAccount]"Everyone" # Convert Everyone to an IdentityReference
        }
        else
        {
            try
            {
                $_PrincipalADObject = (Get-ADObject -LDAPFilter "(&(|(objectClass=user)(objectClass=group))(cn=$AuditPrincipal))" -Properties objectSID -Server $DomainController)
            }
            catch
            {
                Write-Error -Message "Unable to locate a principal in the domain matching '$AuditPrincipal' - $($PSItem.Exception.Message)"
                throw $PSItem
            }

            if( $_PrincipalADObject -is [System.Collections.ICollection] )
            {
                Write-Warning -Message "Found multiple principals matching '$AuditPrincipal' - $($_PrincipalADObject.sAMAccountName -join ",")"
                Write-Warning -Message "Choosing first principal in list: $($_PrincipalADObject.sAMAccountName[0])"
            }
            else
            {
                $AuditPrincipalSid = $_PrincipalADObject.objectSID
            }
        }
        #endregion Convert Objects/Principals to their References

        # If ObjectType and InheritObjectType are specified, we use a different constructor. 
        if( $PSBoundParameters.ContainsKey("ObjectType") -and $PSBoundParameters.ContainsKey("InheritedObjectType") )
        {
            $AuditRule = [System.DirectoryServices.ActiveDirectoryAuditRule]($AuditPrincipalSid,$TargetPermissions,$AuditFlags,$ObjectGuid,$InheritanceType,$InheritedObjectGuid)
        }
        else # Standard Constructors
        {
            # If inheritance is NOT specified. 
            if( !($PSBoundParameters.ContainsKey("InheritanceType")) )
            {
                $AuditRule = [System.DirectoryServices.ActiveDirectoryAuditRule]::new($AuditPrincipalSid,$TargetPermissions,$AuditFlags)
            }
            else # If it is.
            {
                $AuditRule = [System.DirectoryServices.ActiveDirectoryAuditRule]::new($AuditPrincipalSid,$TargetPermissions,$AuditFlags,$InheritanceType)
            }
        }

        # Construct a New ACL
        try
        {
            if( $NewACL )
            {
                $NewACL.AddAuditRule($AuditRule)
                Set-ACL -Path "AD:\$TargetDN" -AclObject $NewACL -ErrorAction Stop
                Write-Information -MessageData "Successfully configured the SACL on '$TargetDN'"
            }
            else
            {
                throw "ACL data is blank - This shouldn't happen."
            }
        }
        catch 
        {
            Write-Error -Message "Failed to create new SACL entry on '$TargetDN' - $($PSItem.Exception.Message)"
            throw $PSItem
        }
    }
}
Export-ModuleMember -Function "Set-PSActiveDirectoryAuditRule"
#endregion function Set-PSActiveDirectoryAuditRule

# --- Variable Exports (for Module)
Request-PSGuidMaps
Export-ModuleMember -Variable "ObjectTypeGuidsMap"
Export-ModuleMember -Variable "ExtendedRightsMap"