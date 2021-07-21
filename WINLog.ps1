###################################################################################
#
#    Script:    WINLog.ps1
#    Version:   1.1
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

$script = "WINLog_"
$version = "v1.1"

########## Startup ##########

Write-Host "

          ___      ____      ___ ________  ____    __  __
          \  \    /    \    /  /|__    __||    \  |  ||  |
           \  \  /  /\  \  /  /    |  |   |     \ |  ||  |      ______   ________
            \  \/  /  \  \/  /   __|  |__ |  |\  \|  ||  |____ /  __  \ /  ___   \
             \____/    \____/   |________||__| \_____||_______|\______/ \_____   |
                                                                         _____|  |
                                                                        |________/


Script / Skript: WINLog.ps1 - $version - Author / Autor: Dan Saunders dcscoder@gmail.com`n`n"

Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Please Note:

Hi $env:USERNAME, script running on $env:ComputerName, please do not touch!

Bitte beachten Sie:

Hallo $env:USERNAME, skript läuft auf $env:ComputerName, bitte nicht berühren!

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor yellow -BackgroundColor black

# Check Priveleges
$admin=[Security.Principal.WindowsIdentity]::GetCurrent()
If ((New-Object Security.Principal.WindowsPrincipal $Admin).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $FALSE)
{
    Write-Host "`n"
    Write-Warning "You have insufficient permissions. Run this script with local Administrator priveleges."
    Write-Warning "Sie haben unzureichende Berechtigungen. Führen Sie dieses Skript mit lokalen Administratorrechten aus."
    Write-Host "`n"
    exit
}

########## Admin ##########

# Destination
$dst = $PSScriptRoot
# System Date/Time
$ts = ((Get-Date).ToString('_yyyyMMdd_HHmmss'))
# Computer Name
$edp = $env:ComputerName
# Triage
$name = $script+$edp+$ts
$tri = $name
New-Item $dst\$tri -ItemType Directory | Out-Null
# Stream Events
Start-Transcript $dst\$tri\WINLog.log -Append | Out-Null

# Exchange Install path
function Get-ExchangeInstallPath {
    $p = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
    if ($null -eq $p) {
        $p = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v14\Setup -ErrorAction SilentlyContinue).MsiInstallPath
    }

    return $p
}

$exchangePath = Get-ExchangeInstallPath

########## General ##########

# Script Progress
$Activity1 = "Task / Aufgabe (1 / 2)"
$Id1 = 1
$Task1 = "Gather configuration information / Sammeln von Konfigurationsinformationen."
Write-Progress -Id $Id1 -Activity $Activity1 -Status $Task1

# Directory Structure
New-Item $dst\$tri\Configuration -ItemType Directory | Out-Null
New-Item $dst\$tri\Users -ItemType Directory | Out-Null
# Operating System Information
systeminfo | Out-File $dst\$tri\Configuration\OS_Information.txt
# User Folders
Get-ChildItem -Path C:\Users -Directory -Force | Select-Object -ExpandProperty Name | Out-File $dst\$tri\Users\User_Folders.txt
$UserFolders = Get-Content $dst\$tri\Users\User_Folders.txt

########## Logs ##########

# Script Progress
$Activity2 = "Task / Aufgabe (2 / 2)"
$Id2 = 2
$Task2 = "Gather log information / Sammeln von Protokollinformationen."
Write-Progress -Id $Id2 -Activity $Activity2 -Status $Task2

# Directory Structure
New-Item $dst\$tri\Logs\winevt -ItemType Directory | Out-Null
New-Item $dst\$tri\Logs\USB -ItemType Directory | Out-Null
New-Item $dst\$tri\Logs\ETW -ItemType Directory | Out-Null
New-Item $dst\$tri\Logs\PowerShell -ItemType Directory | Out-Null
# Windows Event Logs
Copy-Item C:\Windows\System32\winevt\Logs\*.evtx $dst\$tri\Logs\winevt
# USB Device Connections
Copy-Item C:\Windows\inf\setupapi.dev.log $dst\$tri\Logs\USB
# Windows Update Log
Copy-Item C:\Windows\Logs\WindowsUpdate\*.etl $dst\$tri\Logs\ETW
# PowerShell History
$UserFolders = Get-Content $dst\$tri\Users\User_Folders.txt
ForEach ($UserFolder in $UserFolders)
{
        robocopy "C:\Users\$UserFolder\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine" $dst\$tri\Logs\PowerShell\ConsoleHost_history-$UserFolder ConsoleHost_history.txt /ZB /TS /r:4 /w:3 /FP /NP /log+:$dst\$tri\Logs\PowerShell\ConsoleHost_history-$UserFolder.txt | Out-Null
    }
# Firewall Logs
if (Test-Path C:\Windows\System32\LogFiles\Firewall)
{
    New-Item $dst\$tri\Logs\Firewall -ItemType Directory | Out-Null
    robocopy "C:\Windows\System32\LogFiles\Firewall" "$dst\$tri\Logs\Firewall\" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$dst\$tri\Logs\Firewall\Firewall.txt | Out-Null
}
# Internet Information Services
if (Test-Path C:\inetpub\logs\LogFiles)
{
    New-Item $dst\$tri\Logs\IIS -ItemType Directory | Out-Null
    robocopy "C:\inetpub\logs\LogFiles" "$dst\$tri\Logs\IIS\" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$dst\$tri\Logs\IIS\IIS_ID_Folders.txt | Out-Null
}
# Exchange Logging
if (Test-Path "$exchangePath\Logging\")
{
    New-Item $dst\$tri\Logs\Exchange -ItemType Directory | Out-Null
    robocopy "$exchangePath\Logging" "$dst\$tri\Logs\Exchange\" /E /copyall /ZB /TS /r:4 /w:15 /FP /NP /log+:$dst\$tri\Logs\Exchange\Exchange_ID_Folders.txt | Out-Null
}

Stop-Transcript | Out-Null

# Hashing
Get-ChildItem $dst\$tri -Recurse | Where-Object {!$_.psiscontainer } | Get-FileHash -ea 0 -Algorithm MD5 | Format-List  | Out-File $dst\$tri\Hashes.txt

# Compress Archive
Get-ChildItem -Path $dst\$tri | Compress-Archive -DestinationPath $dst\$tri.zip -CompressionLevel Fastest

# Delete Folder
Get-ChildItem -Path "$dst\$tri\\*" -Recurse | Remove-Item -Force -Recurse
Remove-Item "$dst\$tri"

Write-Host "`nScript completed! / Skript abgeschlossen!" -ForegroundColor yellow -BackgroundColor black