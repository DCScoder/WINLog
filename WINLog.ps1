###################################################################################
#
#    Script:    WINLog.ps1
#    Version:   1.2
#    Author:    Dan Saunders
#    Contact:   dcscoder@gmail.com
#    Purpose:   Windows Log Preservation (PowerShell)
#    Usage:     .\WINLog.ps1
#
#    This program is free software: you can redistribute it and / or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <https://www.gnu.org/licenses/>.
#
###################################################################################

$Script = "WINLog_"
$Version = "v1.2"

########## Startup ##########

Write-Host "

          ___      ____      ___ ________  ____    __  __
          \  \    /    \    /  /|__    __||    \  |  ||  |
           \  \  /  /\  \  /  /    |  |   |     \ |  ||  |      ______   ________
            \  \/  /  \  \/  /   __|  |__ |  |\  \|  ||  |____ /  __  \ /  ___   \
             \____/    \____/   |________||__| \_____||_______|\______/ \_____   |
                                                                         _____|  |
                                                                        |________/


	Script / Skript: WINLog.ps1 - $Version - Author / Autor: Dan Saunders dcscoder@gmail.com`n`n"

Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Please Note:

Hi $env:USERNAME, script running on $env:ComputerName, please do not touch!

Bitte beachten Sie:

Hallo $env:USERNAME, skript lauft auf $env:ComputerName, bitte nicht beruhren!

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor yellow -BackgroundColor black

# Check Privileges
$Admin=[Security.Principal.WindowsIdentity]::GetCurrent()
if ((New-Object Security.Principal.WindowsPrincipal $Admin).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $False)
{
    Write-Host "`n"
    Write-Warning "You have insufficient permissions. Run this script with local Administrator privileges."
    Write-Warning "Sie haben unzureichende Berechtigungen. Führen Sie dieses Skript mit lokalen Administratorrechten aus."
    Write-Host "`n"
    exit
}

########## Admin ##########

# Destination
$Destination = $PSScriptRoot
# System Date/Time
$Timestamp = ((Get-Date).ToString('_yyyyMMdd_HHmmss'))
# Computer Name
$Endpoint = $env:ComputerName
# Triage
$Name = $Script+$Endpoint+$Timestamp
$Triage = $Name
New-Item $Destination\$Triage -ItemType Directory | Out-Null
# Stream Events
Start-Transcript $Destination\$Triage\WINLog.log -Append | Out-Null

# Exchange Install path
function Get-ExchangeInstallPath {
    $Path = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
    if ($Null -eq $Path) {
        $Path = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v14\Setup -ErrorAction SilentlyContinue).MsiInstallPath
    }

    return $Path
}

$ExchangePath = Get-ExchangeInstallPath

########## Logs ##########

# Script Progress
$Activity1 = "Task / Aufgabe (1 / 2)"
$Id1 = 1
$Task1 = "Gather configuration information / Sammeln von Konfigurationsinformationen."
Write-Progress -Id $Id1 -Activity $Activity1 -Status $Task1

# Directory Structure
New-Item $Destination\$Triage\Configuration -ItemType Directory | Out-Null
New-Item $Destination\$Triage\Users -ItemType Directory | Out-Null
# Operating System Information
systeminfo | Out-File $Destination\$Triage\Configuration\System_Information.txt
# User Folders
Get-ChildItem -Path C:\Users -Directory -Force | Select-Object -ExpandProperty Name | Out-File $Destination\$Triage\Users\User_Folders.txt
$UserFolders = Get-Content $Destination\$Triage\Users\User_Folders.txt

########## Logs ##########

# Script Progress
$Activity2 = "Task / Aufgabe (2 / 2)"
$Id2 = 2
$Task2 = "Gather log information / Sammeln von Protokollinformationen."
Write-Progress -Id $Id2 -Activity $Activity2 -Status $Task2

# Directory Structure
New-Item $Destination\$Triage\Logs\winevt -ItemType Directory | Out-Null
New-Item $Destination\$Triage\Logs\USB -ItemType Directory | Out-Null
New-Item $Destination\$Triage\Logs\ETW -ItemType Directory | Out-Null
New-Item $Destination\$Triage\Logs\PowerShell -ItemType Directory | Out-Null
# Windows Event Logs
Copy-Item C:\Windows\System32\winevt\Logs\*.evtx $Destination\$Triage\Logs\winevt
# USB Device Connections
Copy-Item C:\Windows\inf\setupapi.dev.log $Destination\$Triage\Logs\USB
# Windows Update Log
Copy-Item C:\Windows\Logs\WindowsUpdate\*.etl $Destination\$Triage\Logs\ETW
# PowerShell History
$UserFolders = Get-Content $Destination\$Triage\Users\User_Folders.txt
foreach ($UserFolder in $UserFolders)
{
        robocopy "C:\Users\$UserFolder\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine" "$Destination\$Triage\Logs\PowerShell\ConsoleHost_history-$UserFolder" ConsoleHost_history.txt /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\Logs\PowerShell\ConsoleHost_history-$UserFolder.txt | Out-Null
    }
# Firewall Logs
if (Test-Path C:\Windows\System32\LogFiles\Firewall)
{
    New-Item $Destination\$Triage\Logs\Firewall -ItemType Directory | Out-Null
    robocopy "C:\Windows\System32\LogFiles\Firewall" "$Destination\$Triage\Logs\Firewall\" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\Logs\Firewall\Firewall.txt | Out-Null
}
# Internet Information Services
if (Test-Path C:\inetpub\logs\LogFiles)
{
    New-Item $Destination\$Triage\Logs\IIS -ItemType Directory | Out-Null
    robocopy "C:\inetpub\logs\LogFiles" "$Destination\$Triage\Logs\IIS\" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\Logs\IIS\IIS_Folders.txt | Out-Null
}
# Exchange Logging
if (Test-Path "$ExchangePath\Logging\")
{
    New-Item $Destination\$Triage\Logs\Exchange -ItemType Directory | Out-Null
    robocopy "$ExchangePath\Logging" "$Destination\$Triage\Logs\Exchange\" /E /copyall /ZB /TS /r:4 /w:15 /FP /NP /log+:$Destination\$Triage\Logs\Exchange\Exchange_Folders.txt | Out-Null
}
# User Access Logging
if (Test-Path C:\Windows\System32\LogFiles\Sum)
{
    New-Item $Destination\$Triage\Logs\UAL -ItemType Directory | Out-Null
    robocopy "C:\Windows\System32\LogFiles\Sum" "$Destination\$Triage\Logs\Sum\" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\Logs\UAL\UAL.txt | Out-Null
}

Stop-Transcript | Out-Null

# Hashing
Get-ChildItem $Destination\$Triage -Recurse | Where-Object {!$_.psiscontainer } | Get-FileHash -ErrorAction 0 -Algorithm MD5 | Format-List | Out-File $Destination\$Triage\Hashes.txt

# Compress Archive
Get-ChildItem -Path $Destination\$Triage | Compress-Archive -DestinationPath $Destination\$Triage.zip -CompressionLevel Fastest

# Delete Folder
Get-ChildItem -Path "$Destination\$Triage\\*" -Recurse | Remove-Item -Force -Recurse
Remove-Item "$Destination\$Triage"

Write-Host "`nScript completed! / Skript abgeschlossen!" -ForegroundColor green -BackgroundColor black