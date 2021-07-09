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

#### Usage:

```
.\WINLog.ps1
```

#### Requirements:

- Script must be run with local Administrator priveleges.
- Ensure local PowerShell policies permit execution.
- PowerShell, robocopy and systeminfo is leveraged.
