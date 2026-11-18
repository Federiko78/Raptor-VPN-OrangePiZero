<#
 Raptor VPN - raggiungere la scheda con il suo IP di recupero (169.254.X.Y) da un PC Windows.

 Uso (PowerShell come AMMINISTRATORE, PC collegato alla STESSA rete LAN della scheda):
     powershell -ExecutionPolicy Bypass -File recupero_windows.ps1 169.254.77.12

 Aggiunge una rotta temporanea "diretta" verso quell'unico indirizzo sulla scheda di rete che
 usa il tuo PC per uscire, apre il pannello nel browser e, quando premi INVIO, toglie la rotta.
 Non modifica l'indirizzo del PC, ne' il DHCP. Funziona solo sulla stessa LAN: non da Internet.
#>
param([Parameter(Mandatory = $true)][string]$Ip)

$ErrorActionPreference = 'Stop'

if ($Ip -notmatch '^169\.254\.([1-9]\d?|1\d\d|2[0-4]\d|25[0-4])\.([1-9]\d?|1\d\d|2[0-4]\d|25[0-4])$') {
    throw "Indirizzo non valido: usare 169.254.X.Y con X e Y da 1 a 254."
}
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Aprire PowerShell come amministratore (serve per aggiungere la rotta)." }

# Scheda di rete attiva con gateway: quella collegata alla LAN dove sta la scheda Raptor.
$cfg = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
if (-not $cfg) { throw "Nessuna scheda di rete attiva con gateway: collegare il PC alla LAN della scheda." }
$index = $cfg.InterfaceIndex
Write-Host ("Uso la scheda di rete: {0} (indice {1})" -f $cfg.InterfaceAlias, $index)

& route.exe add $Ip mask 255.255.255.255 0.0.0.0 if $index | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Impossibile aggiungere la rotta verso $Ip." }
try {
    Write-Host "Rotta aggiunta. Controllo che la scheda risponda..."
    $open = Test-NetConnection -ComputerName $Ip -Port 8443 -WarningAction SilentlyContinue
    if ($open.TcpTestSucceeded) {
        Write-Host "Risponde. Apro https://${Ip}:8443 (accetta l'avviso del certificato; serve la password)."
        Start-Process "https://${Ip}:8443"
    } else {
        Write-Host "Nessuna risposta su ${Ip}:8443. Controlli: stesso switch/LAN? cavo collegato? scheda accesa da piu' di 1 minuto?"
    }
    Read-Host "Premi INVIO per rimuovere la rotta"
} finally {
    & route.exe delete $Ip | Out-Null
    Write-Host "Rotta rimossa."
}
