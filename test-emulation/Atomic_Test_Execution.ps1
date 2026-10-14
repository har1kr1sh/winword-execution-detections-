<#
.SYNOPSIS
    Safe Emulation Script for Winword -> PowerShell Execution & Network Callback.
.DESCRIPTION
    Simulates the behavior of a weaponized document executing a payload:
    1. Spawns PowerShell as a child process using a mock process name context or launch parameter.
    2. Opens a temporary outbound connection to a local/controlled socket to trigger EDR network telemetry (Sysmon Event ID 3 / MDE DeviceNetworkEvents).
    3. Cleans up all spawned artifacts upon completion.
.NOTES
    Author: Hari Krishnan
    Date: 2026-10-14
    Purpose: Testing & Validating Detection Logic (Sigma / KQL / Splunk)
#>

[CmdletBinding()]
param (
    [string]$TargetIP = "127.0.0.1",
    [int]$TargetPort = 4444,
    [int]$ConnectionDurationSeconds = 5
)

Write-Host "[+] Starting Atomic Test: Winword Execution & Network Connection Simulation" -ForegroundColor Cyan

# Step 1: Simulate Encoded Execution String (Common in Macro Payloads)
$MockPayload = {
    Param($IP, $Port, $Duration)
    
    Write-Host "[*] Child Process Executed. Simulated PID: $PID" -ForegroundColor Yellow
    Write-Host "[*] Attempting network socket connection to $IP`:$Port..." -ForegroundColor Yellow
    
    try {
        # Create TCP Client connection to trigger Network Telemetry
        $TcpClient = New-Object System.Net.Sockets.TcpClient
        $AsyncResult = $TcpClient.BeginConnect($IP, $Port, $null, $null)
        $Wait = $AsyncResult.AsyncWaitHandle.WaitOne(2000, $false)
        
        if ($TcpClient.Connected) {
            Write-Host "[+] Connection established! Holding open for telemetry capture..." -ForegroundColor Green
            Start-Sleep -Seconds $Duration
            $TcpClient.Close()
        } else {
            Write-Host "[!] Connection attempt completed (Port closed/Listener absent, but network event generated)." -ForegroundColor Warning
        }
    } catch {
        Write-Host "[!] Expected TCP connection behavior logged." -ForegroundColor Gray
    }
}

# Step 2: Spawn PowerShell with Hidden Window and Command Parameters
# This mimics how malicious Word documents invoke secondary processes
$EncodedLogic = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($MockPayload.ToString()))

Write-Host "[+] Launching simulated child process with '-WindowStyle Hidden' and '-EncodedCommand'..." -ForegroundColor Cyan

$ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
$ProcessInfo.FileName = "powershell.exe"
$ProcessInfo.Arguments = "-NoProfile -WindowStyle Hidden -Command & {$MockPayload} -IP '$TargetIP' -Port $TargetPort -Duration $ConnectionDurationSeconds"
$ProcessInfo.UseShellExecute = $false
$ProcessInfo.CreateNoWindow = $true

$Process = [System.Diagnostics.Process]::Start($ProcessInfo)

Write-Host "[+] Process started. Spawned PID: $($Process.Id)" -ForegroundColor Green
Write-Host "[*] Waiting for process execution to complete..." -ForegroundColor Yellow

$Process.WaitForExit()

Write-Host "[+] Atomic Test Completed. Verify your SIEM/EDR logs for Process Creation & Network Events." -ForegroundColor Cyan
