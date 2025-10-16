<#
.SYNOPSIS
Parses and filters Windows Firewall logs from a remote computer, displaying relevant entries in a grid view.

.DESCRIPTION
This script connects to a specified remote computer and reads either the current or archived domain firewall log file.
It filters the log entries based on the resolved or provided IP address and optionally excludes specified destination ports.
The filtered results are displayed in an interactive Out-GridView window for analysis.

.PARAMETER ComputerName
The name of the remote computer whose firewall logs will be accessed. This is a required parameter.

.PARAMETER PortsToExclude
An optional array of destination ports to exclude from the output. Useful for filtering out common or known traffic, or traffic already subject to firewall rules.

.PARAMETER IPAddress
An optional IP address of the destination computer to filter log entries. If not provided, the script will resolve the IP address from the ComputerName using DNS.

.PARAMETER OldLogs
Switch to indicate whether to use the archived firewall log file (domainfw.log.old) instead of the current one.

.EXAMPLE
.\Get-FirewallLogs.ps1 -ComputerName "App01.contoso.com" -PortsToExclude 80,443

This example reads the current firewall log from App01 and displays entries excluding ports 80 and 443 for web traffic.

.EXAMPLE
.\Get-FirewallLogs.ps1 -ComputerName "Db01.contoso.com"

This example reads the current firewall log from Db01 and displays all entries related to the resolved IP address.

.EXAMPLE
.\Get-FirewallLogs.ps1 -ComputerName "TermSrv.contoso.com" -PortsToExclude 3389 -IpAddress 192.168.1.1 -OldLogs

This example reads the archived firewall log from TermSrv and displays entries reaching the 192.168.1.1 interface
(for example, if there are multiple network interfaces you can specify this one), excluding port 3389 for RDP.

.NOTES
Author: Aomar Bahloul
Created: October 2025  
Version: 1.0.0  

VERSION HISTORY
1.0.0 - Initial release with support for IP filtering, port exclusion, and log source selection.

#>


Param(
[Parameter(Mandatory)] [String] $ComputerName,
[Array] $PortsToExclude,
[String] $IPAddress,
[Switch] $OldLogs
)

# Set path to either current or previous log file
if ($OldLogs){
    $LogFilePath  = "\\$ComputerName\c$\Windows\System32\LogFiles\firewall\domainfw.log.old"
}
else {
    $LogFilePath  = "\\$ComputerName\c$\Windows\System32\LogFiles\firewall\domainfw.log"
}

# CSV header fields, to be used later when converting each line of the tailed log from CSV
$headerFields = @("date","time","action","protocol","src-ip","dst-ip","src-port","dst-port","size","tcpflags","tcpsyn","tcpack","tcpwin","icmptype","icmpcode","info","path")

# Read in the firewall log
$firewallLogs = Get-Content $LogFilePath | ConvertFrom-Csv -Header $headerFields -Delimiter  ' '

# Output logs into a gridview
# Filter by IP if specified, otherwise nslookup the IP first. Also, filter out ports if desired.
if ($IPAddress){

}
else {
    $IPAddress = (Resolve-DnsName $ComputerName).IpAddress
}
if($PortsToExclude){
        $firewallLogs | Where-Object {$_.path -eq "RECEIVE"} | Where-Object {$_.'dst-ip' -eq $IPAddress} | Where-Object {$_.'dst-port' -NotIn $PortsToExclude} | Out-GridView
    }
else {
        $firewallLogs | Where-Object {$_.path -eq "RECEIVE"} | Where-Object {$_.'dst-ip' -eq $IPAddress}| Out-GridView
    }