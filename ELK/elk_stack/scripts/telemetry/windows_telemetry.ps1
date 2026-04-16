#!/usr/bin/env powershell

# Windows Cybersecurity MVP Telemetry Script
# Focuses on key security indicators for Windows systems

param(
    [string]$Host = "localhost",
    [int]$Port = 514
)

$hostname = $env:COMPUTERNAME

function Send-Syslog {
    param(
        [string]$Program,
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "MMM dd HH:mm:ss"
    # Using facility 13 (security), severity 6 (info) - priority 110
    $syslogMsg = "<110>$timestamp $hostname $Program`: $Message"
    
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($syslogMsg)
        $udpClient.Send($bytes, $bytes.Length, $Host, $Port) | Out-Null
        $udpClient.Close()
        Write-Host "Security telemetry: $Program - $Message"
    }
    catch {
        Write-Error "Failed to send syslog message: $_"
    }
}

Write-Host "Collecting Windows cybersecurity telemetry..."

# 1. Failed Login Attempts (last hour)
try {
    $failedLogins = (Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue | Measure-Object).Count
    Send-Syslog "auth-monitor" "Failed login attempts last hour: $failedLogins"
}
catch {
    Send-Syslog "auth-monitor" "Failed login attempts last hour: Unable to query (insufficient permissions)"
}

# 2. Active Network Connections
try {
    $activeConnections = (Get-NetTCPConnection -State Established | Measure-Object).Count
    Send-Syslog "network-monitor" "Active TCP connections: $activeConnections"
}
catch {
    $activeConnections = (netstat -an | Select-String "ESTABLISHED" | Measure-Object).Count
    Send-Syslog "network-monitor" "Active TCP connections: $activeConnections"
}

# 3. Processes with Network Activity
try {
    $networkProcesses = (Get-NetTCPConnection | Group-Object OwningProcess | Measure-Object).Count
    Send-Syslog "process-monitor" "Processes with network activity: $networkProcesses"
}
catch {
    # Fallback using netstat
    $networkProcesses = (netstat -ano | Select-String "ESTABLISHED|LISTENING" | ForEach-Object { ($_ -split '\s+')[-1] } | Sort-Object -Unique | Measure-Object).Count
    Send-Syslog "process-monitor" "Processes with network activity: $networkProcesses"
}

# 4. New Files in Temp Directory (last hour)
try {
    $tempFiles = (Get-ChildItem -Path $env:TEMP -Recurse -File | Where-Object { $_.CreationTime -gt (Get-Date).AddHours(-1) } | Measure-Object).Count
    Send-Syslog "file-monitor" "New files in temp last hour: $tempFiles"
}
catch {
    Send-Syslog "file-monitor" "New files in temp last hour: Unable to scan temp directory"
}

# 5. CPU Usage (average over last few seconds)
try {
    $cpuUsage = [math]::Round((Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 3 | Select-Object -ExpandProperty CounterSamples | Measure-Object -Property CookedValue -Average).Average, 2)
    Send-Syslog "load-monitor" "Average CPU usage: $cpuUsage%"
}
catch {
    # Fallback using WMI
    $cpuUsage = [math]::Round((Get-WmiObject -Class Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 2)
    Send-Syslog "load-monitor" "Average CPU usage: $cpuUsage%"
}

Write-Host "Windows cybersecurity telemetry sent to ELK stack"