# WINLog
Windows log preservation.

#### Description:

The purpose of this script is to preserve and collect notable Windows logs. Once dropped onto the target system, the script will utilise a series of internal commands to query information from the host and retrieve data, which it stores in a temporary folder. Once all data has been collected, all files are hashed with the MD5 algorithm and the hash values are retained in a log file. Finally, the collection is archived into a ZIP file and the temporary store is deleted. The ZIP file can then be retrieved by the analyst for subsequent analysis offline. The script should be used during fast-time collection and preservation of log files during a cyber security incident. Frequent progress updates are provided in English and German languages via the terminal, whilst the script is active. A log of the terminal activities is also created and retained in the archive collection.

#### Artefacts Supported:

- Windows Event Logs
- USB Device Connection Logs
- Windows Update Logs
- Powershell Console History Logs
- Firewall Logs
- Internet Information Services (IIS) Logs
- Exchange Logs
- User Access Logging (UAL)

#### Usage:

Step 1: Copy script to target host.

Step 2: Execute script with Administrator privileges:

```
.\WINLog.ps1
```

If issues are encountered relating to PowerShell policies, instead of using 'Set-ExecutionPolicy' to change the policy, utilise a batch script to bypass and execute:

```
powershell.exe -ExecutionPolicy Bypass -File C:\<path_to_script>\WINLog.ps1
```

Step 3: Download resultant (*.zip) archive file via your preferred method.

Step 4: Delete script and archive file from host:

```
Remove-Item -Path C:\<path_to_script>\WINLog.ps1
```
```
Remove-Item -Path C:\<path_to_archive>\WINLog_<hostname>_<date>_<time>.zip
```

#### Requirements:

- Script must be run with local Administrator privileges.
- Ensure local PowerShell policies permit execution. You can check the current PowerShell policy via 'Get-ExecutionPolicy'.
- PowerShell, robocopy and systeminfo are leveraged.
