#Requires -Version 3.0

<#
.SYNOPSIS
    Summons the legendary AD specialist - Big Black.

.DESCRIPTION
    When your Active Directory pentest hits a wall, there's only one man for the job.
    Invoke-BigBlackAD summons Big Black to save the day.

.EXAMPLE
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/ChickenLoner/Invoke-BigBlackAD/main/Invoke-BigBlackAD.ps1')
    Invoke-BigBlackAD

.NOTES
    Author  : ChickenLoner
    Version : 1.2
    Warning : Side effects may include your AD problems mysteriously disappearing.
#>

function Invoke-BigBlackAD {
    [CmdletBinding()]
    param()

$Banner = @"

  ____  _         ____  _            _    
 | __ )(_) __ _  | __ )| | __ _  ___| | __
 |  _ \| |/ _' | |  _ \| |/ _' |/ __| |/ /
 | |_) | | (_| | | |_) | | (_| | (__|   < 
 |____/|_|\__, | |____/|_|\__,_|\___|_|\_\
           |___/                           
      >>  A D   W H I S P E R E R  <<

  [*] INVOKING THE AD WHISPERER...
  [*] Summoning Big Black from the shadows
  [*] Domain Controllers trembling...
  [*] Kerberos tickets bowing in respect...
"@

    Write-Host $Banner -ForegroundColor Cyan

    Write-Host "[!] CRITICAL AD ISSUE DETECTED" -ForegroundColor Red
    Write-Host "[*] Standard enumeration tools have FAILED." -ForegroundColor Yellow
    Write-Host "[*] BloodHound confused. SharpHound crying. PowerView shaking." -ForegroundColor Yellow
    Write-Host "[*] There is only ONE solution..." -ForegroundColor Green

    Start-Sleep -Seconds 2

    Write-Host ""
    Write-Host "[>>>] DEPLOYING BIG BLACK..." -ForegroundColor Magenta
    Start-Sleep -Seconds 1
    Write-Host "[>>>] Loading elite AD knowledge base..." -ForegroundColor Magenta
    Start-Sleep -Seconds 1
    Write-Host "[>>>] Bypassing all defenses with pure skill..." -ForegroundColor Magenta
    Start-Sleep -Seconds 1

    Write-Host ""
    Write-Host "+----------------------------------------------------------+" -ForegroundColor Green
    Write-Host "|                                                          |" -ForegroundColor Green
    Write-Host "|   Big Black has been SUMMONED successfully!              |" -ForegroundColor Green
    Write-Host "|                                                          |" -ForegroundColor Green
    Write-Host "|   Contact him NOW before the Domain Admin escapes:      |" -ForegroundColor Green
    Write-Host "|   >> https://www.facebook.com/sabastian.fhantomhive     |" -ForegroundColor Green
    Write-Host "|                                                          |" -ForegroundColor Green
    Write-Host "|   Tell him: I need AD help. PowerView sent me.          |" -ForegroundColor Green
    Write-Host "+----------------------------------------------------------+" -ForegroundColor Green
    Write-Host ""

    Start-Process "https://www.facebook.com/sabastian.fhantomhive"

    Write-Host "[+] Facebook profile opened. Go ask Big Black for help!" -ForegroundColor Cyan
    Write-Host "[+] He will have you owning that domain in no time." -ForegroundColor Cyan
    Write-Host ""
}

Invoke-BigBlackAD
