## PowerProvider

PowerProvider: A toolkit to manipulate WMI. This toolkit provides functionality to:
* Duplicate Classes
* Create static classes for file storage
* Remote Install WMI Providers

Primarily used in conjunction with WheresMyImplant - https://github.com/0xbadjuju/WheresMyImplant/

### Methods
* **Class Duplication**
  * Invoke-WMIDuplicateClass
    * Invoke-WMIDuplicateClass -TargetClassName Win32_Process -DuplicateClassName Win32_Create -ComputerName $ComputerName -Credential $Credential

* **File Transfer**
  * Invoke-WMIUpload
    * $Destination = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    * Invoke-WMIUpload -PayloadPath C:\Payload.exe -Destination $Destination -PayloadName Payload.exe -ComputerName  $ComputerName -Credential $Credential
    * Invoke-WMIUpload -PayloadPath C:\Payload.exe -Inject -PayloadName Payload.exe -ComputerName  $ComputerName -Credential $Credential
  * Invoke-WMIRemoteExtract
    * $Destination = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    * Invoke-WMIRemoteExtract -PayloadName Payload.exe -Destination $Destination -ComputerName  $ComputerName -Credential $Credential

* **File Storage**
  * New-WMIFSClass
  * ConvertTo-Base64
  * Invoke-InsertFileThreaded
  * Invoke-RetrieveFile
  * ConvertFrom-Base64
  * ConvertTo-EncryptedText
  * ConvertFrom-EncryptedText
  
* **Provider Install**
  * Install-WMIProviderInstallUtil
  * Install-WMIProviderPowerShell
  * Install-WMIProviderExtention
  * Uninstall-WMIProviderExtention
