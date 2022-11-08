# Incident Runbook

## Table of Contents
- [1. Introduction](https://github.com/redar0n/incident-runbook/blob/main/incident-runbook.md#1-introduction)
- [2. Detection](https://github.com/redar0n/incident-runbook/blob/main/incident-runbook.md#2-detection)
- [3. Containment](https://github.com/redar0n/incident-runbook/blob/main/incident-runbook.md#3-containment)
	- [3.1 Basic commands](https://github.com/redar0n/incident-runbook/blob/main/incident-runbook.md#31basic-commands) 
	- [3.2 Status Meeting #1](https://github.com/redar0n/incident-runbook/blob/main/incident-runbook.md#32status-meeting-1) 
- [4. Analysis](https://github.com/redar0n/incident-runbook/blob/main/incident-runbook.md#4-analysis) 
	- [4.1 Status Meeting #2](https://github.com/redar0n/incident-runbook/blob/main/incident-runbook.md#41status-meeting-2) 
- [5. Remediation](https://github.com/redar0n/incident-runbook/blob/main/incident-runbook.md#5-remediation)
	- [5.1 Basic commands](https://github.com/redar0n/incident-runbook/blob/main/incident-runbook.md#51basic-commands) 
- [6. Closing](https://github.com/redar0n/incident-runbook/blob/main/incident-runbook.md#6-closing) 


## 1. Introduction
| Value | Description |
| --- | --- |
| Value | Description |
| Title | Incident Runbook |
| Date | Nov 2022 |
| created by | 0xsyr0 |
| modified by | redar0n |


## 2. Detection
Get the Detection Phase done within the first 10 Minutes of the Incident!
| Task | Status (Open / Done) |
| --- | --- |
| Start a Teams / Slack Channel for the Incident Response team (Incident-$number) | |
| Setup a Teams / Slack meeting and provide the meeting link within the channel | |
| Start the status meeting and write down all relevant information in the channel | |
| What happened? | |
| How did it happen? | |
| What was / is exposed? | |
| Who leads the Incident Response Team? | |
| Is a customer affected or is it internal? | |
| If it internal, which team is affected / required for support | |
| Who is responsible for customer communication? | |
| Keep the Teams / Slack channel up to date and always in loop | |
| Status meetings interval: 2-4 hours | |



## 3. Containment
### 3.1	Basic commands
Endpoint Security | XDR
```c
// commands
Search for all logged Actions on Endpoint
File Search for "Hash Value"
Live Terminal
```
Firewall
```c
// commands
Traffic Logs
URL Filtering
VPN End to Site connections
VPN Side to Site connections
```
Active Directory
```c
View Users Details
View Group Details
Last Password Change
```
Azure Active Directory
```c
// Source 
Azure Portal / Microsoft Security Center / Azure Active Directory / Conditional Access
Check last Logins 
MFA Status
Check Conditional Access Status
```

Asset Database
```c
Last users
OS Information
IP Range
Endpoint Security Status
installed Software
Disks / File Shares
```

Linux
```c
// current users logged in
$ w
// login history
$ last
// last commands used by user
$ tail -n 200 ~/.bash_history | more
// last commands used by user
$ cat ~/.bash_history | more
// changed files in the last 2 days
$ sudo find /etc /var -mtime -2
// current connections
$ ss -tulpn | grep ESTA
// list open files
$ lsof -i
// process information
$ strace -d -p <PID>
// process list
$ ps -auxf
// check authentication log
$ tail -n 300 /var/log/auth.log
// check authentication log for ssh
$ tail -n 300 /var/log/auth.log | grep sshd
// list kernel structure
$ ls /proc/*/exe -la
// list kernel structure
$ sudo ls /proc/*/exe -la
// common attack directory
$ ls /tmp -la
// common attack directory
$ ls /dev/shm -la
// common attack directory
$ ls /var/tmp -la
// check crontab
$ crontab -e
// list systemd timers
$ systemctl list-timers
```

Windows
```c
// Basic network discovery
C:\> net view /all
// Basic network discovery
C:\> net view \\<HOST NAME>
// Get users logged on
C:\> psloggedon \\computername

DHCP
// Enable DHCP server logging
C:\> REG ADD HKLM\System\CurrentControlSet\Services\DhcpServer\Parameters /v ActivityLogFlag /t REG_DWORD /d 1
// Default Location on Windows 2003/2008/2012
C:\> %windir%\System32\Dhcp

DNS
// Enable DNS Logging
C:\> DNSCmd <DNS SERVER NAME> /config /logLevel 0x8100F331
// Set log location
C:\> DNSCmd <DNS SERVER NAME> /config /LogFilePath <PATH TO LOG FILE>
// Set size of log file
C:\> DNSCmd <DNS SERVER NAME> /config /logfilemaxsize 0xffffffff
// Default Location on Windows Server 2003
C:\> %SystemRoot%\System32\Dns
// Default Location on Windows Server 2008
C:\> %SystemRoot%\System32\Winevt\Logs\DNS Server.evtx
// Default Location on Windows Server 2012 R2 / 2016 / 2019 / 2022
C:\> %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-DNSServer%4Analytical.etl

NETBIOS
// Basic nbtstat scan
C:\> nbtstat -A <IP ADDRESS>
// Cached NetBIOS info on localhost
C:\> nbtstat -c

Services
// Get a list of services and disable or stop
C:\> sc query 
C:\> sc config "<SERVICE NAME>" start=disabled 
C:\> sc stop "<SERVICE NAME>" 
C:\> wmic service where name='<SERVICE NAME>' callChangeStartmode Disabled
 
Scheduled Tasks
// Get scheduled Tasks
Get-ScheduledTask
// Get scheduled Task by Name
 Get-ScheduledTask -TaskName <'Taskname'>
// Tasks ready to run
Get-ScheduledTask | where state -EQ 'ready'

Microsoft Baseline Security Analyser (MBSA)
// Basic scan of a target IP address
C:\> mbsacli.exe /target <TARGET IP ADDRESS> /n os+iis+sql+password
// Basic scan of a target IP range
C:\> mbsacli.exe /r <IP ADDRESS RANGE> /n os+iis+sql+password
// Basic scan of a target domain
C:\> mbsacli.exe /d <TARGET DOMAIN> /n os+iis+sql+password
 
Active Directory Inventory
// List all OUs
C:\> dsquery ou DC=<DOMAIN>,DC=<DOMAIN EXTENSION>
// List of workstations in the domain
C:\> netdom query WORKSTATION
// List of servers in the domain
C:\> netdom query SERVER
// List of domain controllers
C:\> netdom query DC
// List of organisational units under which the specified user can create a machine object
C:\> netdom query OU
// List of primary domain controller
C:\> netdom query PDC
// List the domain trusts
C:\> netdom query TRUST
// Query the domain for the current list of FSMO owners
C:\> netdom query FSMO
// List all computers from Active Directory
C:\> dsquery COMPUTER "OU=servers,DC=<DOMAIN NAME>,DC=<DOMAIN EXTENSION>" -o run -limit 0 > C:\machines.txt
// List user accounts inactive longer than 3 weeks
C:\> dsquery user domain root -inactive 3
// Find anything (or user) create on date in UTC using timestamp format YYYYMMDDHHMMSS.sZ
C:\> dsquery * -filter "(whenCreated>=20211129083045.0Z)"
C:\> dsquery * -filter "(&(whenCreated>=20211129083045.0Z)(objectClass=user))"
Alternative option:
C:\> ldifde -d ou=<OU NAME>,dc=<DOMAIN NAME>,dc=<DOMAIN EXTENSION> -l whencreated, whenchanged -p onelevel -r "(ObjectCategory=user)" -f <OUTPUT FILENAME>
// The last logon timestamp format in UTC YYYYMMDDHHMMSS
C:\> dsquery * dc=<DOMAIN NAME>,dc=<DOMAIN EXTENSION> - filter "(&(objectCategory=Person)(objectClass=User)(whenCreated>=20211129083045.0Z))"
Alternative option:
C:\> adfind -csv -b dc=<DOMAIN NAME>,dc=<DOMAIN EXTENSION> -f "(&(objectCategory=Person)(objectClass=User)(whenCreated>=20211129083045.0Z))"
// Using PowerShell, dump new Active Directory accounts in last 90 days
PS C:\> import-module activedirectory
PS C:\> Get-QADUser -CreatedAfter (Get-Date).AddDays(-90)
PS C:\> Get-ADUser -Filter * -Properties whenCreated | Where-Object {$_.whenCreated -ge ((Get-Date).AddDays(-90)).Date}

local Firewall
// Show all rules
C:\> netsh advfirewall firewall show rule name=all 
// Set firewall on/off
C:\> netsh advfirewall set currentprofile state on 
C:\> netsh advfirewall set currentprofile firewallpolicy blockinboundalways,allowoutbound 
C:\> netsh advfirewall set publicprofile state on 
C:\> netsh advfirewall set privateprofile state on 
C:\> netsh advfirewall set domainprofile state on 
C:\> netsh advfirewall set allprofile state on 
C:\> netsh advfirewall set allprof ile state off 
// Set firewall rules examples
C:\> netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80 23 
C:\> netsh advfirewall firewall add rule name="My Application" dir=in action=allow program="C:\MyApp\MyApp.exe" enable=yes 
C:\> netsh advfirewall firewall add rule name="My Application" dir=in action=allow program="C:\MyApp\MyApp.exe" enable=yes remoteip=157.60.0.1,172.16.0.0/16,LocalSubnet profile=domain 
C:\> netsh advfirewall firewall add rule name="My Application" dir=in action=allow program="C:\MyApp\MyApp.exe" enable=yes remoteip=157.60.0.1,172.16.0.0/16,LocalSubnet profile=domain 
C:\> netsh advfirewall firewall add rule name="My Application" dir=in action=allow program="C:\MyApp\MyApp.exe" enable=yes remoteip=157.60.0.1,172.16.0.0/16,LocalSubnet profile=private
C:\> netsh advfirewall firewall delete rule name=rule name program="C:\MyApp\MyApp.exe"
C:\> netsh advfirewall firewall delete rule name=rule name protocol=udp localport=500
C:\> netsh advfirewall firewall set rule group="remotedesktop" new enable=Yes profile=domain
C:\> netsh advfirewall firewall set rule group="remotedesktop" new enable=No profile=public
// Setup togging location
C:\> netsh advfirewall set currentprofile logging 
C:\<LOCATION>\<FILE NAME> 
// Windows firewall tog location and settings
C:\> more %systemroot%\system32\LogFiles\Firewall\pfirewall.log
C:\> netsh advfirewall set allprofile logging maxfilesize 4096 
C:\> netsh advfirewall set allprofile logging droppedconnections enable 
C:\> netsh advfirewall set allprofile logging allowedconnections enable 
// Display firewall logs
PS C:\> Get-Content $env:systemroot\system32\LogFiles\Firewall\firewall.log
```


| Task | Status (Open / Done) |
| --- | --- |
| Clarify if there are other systems which could be potentially infected or got compromised too	| |
| Get emergency access to the system | |
| Taking VM Snapshots | |
| Isolate the system(s) on network layer | |
| Do we have log files stored on a remote syslog system? | |
| Do we have Endpoint Security log files? | |
| Which software runs on the infected system? | |
| Are there any known vulnerabilities which can lead an attacker to privilege escalation? | |
| Save log files on the infected systems | |
| Create memory dumps | |
| Are there malicious like looking processes | |
| Extract malicious processes | |
| Acquire a copy of malicious file(s) for analysis | |
| Monitor Endpoint Security Logs | |
| Monitor Scheduled Task | |
| Monitor Reg Key creation / modification | |
| Monitor Command Line / Powershell | |
| Monitor Firewall Logs | |
| Monitor Connections | |
| Monitor client email | |
| Monitor RDP sessions on external accessible RDP client system | |
| Monitor user name variations | |
| Review edge router log files | |
| Review VPN log files | |
| Review DNS log files | |
| Review AV log files | |
| Review account and policy abuse log files | |
| Review host firewall log files | |


### 3.2	Status Meeting #1
In the case of major incidents, it makes sense to hold regular meetings. To ensure that tasks can be processed, an interval of 2-4 hours is recommended.


## 4. Analysis
| Task | Status (Open / Done) | Yes / No / Unknown / N/A | comment |
| --- | --- | --- | --- |


#### Malware Presence on the System
| Task | Status (Open / Done) | Yes / No / Unknown / N/A |
| --- | --- | --- |
| Upload infected files on services like virustotal / intezer | | |
| Exfiltrate data from malicious files to get intel about Malware behavior (payloads [strings, binwalk, autopsy, foremost etc.] / IOCs / TTPs ) | | |
| Runs in memory only? | | |
| Runs out of registry? | | |
| Artifacts on disk? | | |
| Disk file presence hidden, stored in unallocated, free/slack space or encrypted? | | |
| Files are packed and likely encrypted? | | |
| Suspicious DLLs or services? | | |
| Stays alive working in file pairs? | | |
#### Malware Activities
| Task | Status (Open / Done) | Yes / No / Unknown / N/A |
| --- | --- | --- |
| Downloads new code/functionality? | | |
| Leverages pivot system(s) and network paths? | | |
| Ability to detect and utilise authenticated we proxies? | | |
| Morphs on system(s)? | | |
| Contains misleading/distracting features depending on the environment it detects? | | |
#### Malware Capabilities
| Task | Status (Open / Done) | Yes / No / Unknown / N/A |
| --- | --- | --- |
| Ability to traverse all known operating systems? | | |
| Ability to conduct most Windows based Active Directory commands? | | |
| Ability to upload and download files/payloads? | | |
| Can use built-in services or purpose build malware for needed services? | | |
| Has several persistent features, making the malware highly resilient to AV defences? | | |
| Ability to brute force? | | |
| Ability to DoS/DDoS? | | |
| Ability to steal and/or pass the hash? | | |
| Ability to conduct credential harvesting? | | |
| Privilege Escalation capability? | | |
| Ransomware or like capability? | | |
| Self-Destruct mode, including destructive methods? | | |
| Anti memory forensics? | | |
| Is sandbox ware and virtual machine aware? | | |
| C2 techniques: DNS, HTTP, HTTPS, steganography, cloud, TOR, online code, etc.? | | |
| One time install/detonation? | | |
| Communicates in no predictable patterns including short and longterm sleep techniques? | | |
| Make use of compromised CA, on order to hide communications? | | |
| Time zone and IP Geo aware? | | |
| Makes use of well-established commercial compromised websites for C2, Dropbox, Gmail, etc. | | |


### 4.1	Status Meeting #2
In the case of major incidents, it makes sense to hold regular meetings. To ensure that tasks can be processed, an interval of 2-4 hours is recommended.


## 5. Remediation

### 5.1	Basic commands

Endpoint Security | XDR
```c
// commands
Isolate Endpoint
Block Files
Search for actions on Endpoint
initiated live terminal connection
remove malicous files
```

Firewall
```c
//commands
Block IPs
Block Ports
Block applications
Report malicous sites to Firewall manufacturer
```
Active Directory
```c
disable Users
disable Groups
change Password
```

Azure Active Directory
```c
// Source 
Azure Portal / Azure Active Directory
Reset Password
Revoke active Sessions (Permission "Authentication Administrator" needed)
```

Linux
```c
// iptables log incoming traffic
$ sudo iptables -A INPUT -p tcp -m state --state NEW -j LOG --log-prefix "IPTables New-Connection: " -i <interface>
 
// iptables handling
$ service iptables stop
$ service iptables start
$ service iptables restart
$ service iptables save
$ iptables-save > /root/custom-ip-tables-rules
$ iptables-restore < /root/custom-ip-tables-rules
// shows all IPv4 rules
$ iptables -S
// shows all IPv6 rules
$ ip6tables -S

// allows all incoming traffic
$ iptables -P INPUT ACCEPT
// allows all outgoing traffic
$ iptables -P OUTPUT ACCEPT
// allows all forwarded traffic
$ iptables -P FORWARD ACCEPT
// drop all incoming traffic
$ iptables -P INPUT DROP
// drop all outgoing traffic
$ iptables -P OUTPUT DROP
// drop all forwarded traffic
$ iptables -P FORWARD DROP
// rejects all incoming traffic
$ iptables -P INPUT REJECT
// rejects all outgoing traffic
$ iptables -P OUTPUT REJECT
// rejects all forwarded traffic
$ iptables -P FORWARD REJECT
 
// flush the selected chain
$ iptable -F
// delete chain
$ iptables -X
// flushes all the rules for the table nat
$ iptables -t nat -F
// deletes the table nat
$ iptables -t nat -X
// flushes all the rules for the table mangle
$ iptables -t mangle -F
// deletes the table mangle
$ iptables -t mangle -X
// deletes a specific PREROUTING NAT Rule based on the line number
$ iptables -t nat -D PREROUTING <line number>
// deletes a specific POSTROUTING NAT Rule based on the line number
$ iptables -t nat -D POSTROUTING <line number>

// display the whole iptables command for reusage
$ iptables -save
// shows all rules screen by screen
$ iptables -nvL | more
// inspect firewall with line numbers
$ iptables -n -L -v --line-numbers
// clears the packet counter for all rules
$ iptables -Z
// clears the packet counter for the INPUT chain
$ iptables -Z INPUT
// clears the packet counter for line 13 of the INPUT chain
$ iptables -Z INPUT <line number>
// display INPUT or OUTPUT chain rules
$ iptables -L INPUT -n -v
// display INPUT or OUTPUT chain rules
$ iptables -L OUTPUT -n -v --line-numbers
 
// deletes a specific iptables line number of the input chain
$ iptables -D INPUT <line number>
// insert a rule between two lines
$ iptables -I INPUT <line number> -s <IP address> -j DROP
// allow outgoing traffic
$ iptables -A INPUT -m state --state NEW,ESTABLISHED -j ACCEPT
// block a specific IP address
$ iptables -A INPUT -s <IP address> -j DROP
// drop a whole network an a specific interface
$ iptables -A INPUT -i <interface> -s <network> -j DROP
// block incoming port requests
$ iptables -A INPUT -p tcp --dport <port> -j DROP
// block incoming port for a specific IP address
$ iptables -A INPUT -p tcp -s <IP address> --dport <port> -j DROP
// block outgoing traffic for a whole network (don't use DNS!)
$ iptables -A OUTPUT -p tcp -d <network> -j DROP
// log traffic with a specific prefix
$ iptables -A INPUT -i <interface> -s <network> -j LOG --log-prefix "IP_SPOOF A: "
// blocking ICMP Ping requests
$ iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
// blocking ICMP Ping requests on a specific interface
$ iptables -A INPUT -i <interface> -p icmp --icmp-type echo-request -j DROP
// allows traffic only from a specific MAC address and port
$ iptables -A INPUT -p tcp --destination-port <port> -m mac --mac-source <MAC address> -j ACCEPT
// openes port range
$ iptables -A INPUT -m state --state NEW -m tcp -p tcp --dport <port>:<port> -j ACCEPT
// openes IP address range on a specific port
$ iptables -A INPUT -p tcp --destination-port <port> -m iprange --src-range <IP address>-<IP address> -j ACCEPT
// redirects port A to port B
$ iptables -t nat -I PREROUTING --src 0/0 --dst <dst IP address> -p tcp --dport <port> -j REDIRECT --to-ports <port>
// restricts the number of parallel connection for a specific port
$ iptables -A INPUT -p tcp --syn --dport <port> -m connlimit --connlimit-above 3 -j REJECT
```

Windows
```c
Active Directory - Group Policy Object
// Get and force new policies
C:\> gpupdate /force
C:\> gpupdate /sync
// Audit Success and Failure for user
C:\> auditpol /set /user:<USER> /category:"Detailed Tracking" /include /success:enable /failure:enable
// Create an Organization Unit to move suspected or infected users and machines
C:\> dsadd OU <QUARANTINE BAD OU> 
// Move an active directory user object into NEW GROUP
PS C:\> Move-ADObject 'CN=<USER NAME>,CN=<OLD USER GROUP>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>' - TargetPath 'OU=<NEW USER GROUP>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>'
Alternative option:
C:\> dsmove "CN=<USER NAME>,OU=<OLD USER OU>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>" -newparent OU=<NEW USER GROUP>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>
 
Stand Alone System without Active Directory
// Disallow running a .exe file
C:\> reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisallowRun /t REG_DWORD /d "00000001" /f
C:\> reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v badfile.exe /t REG_SZ /d <BAD FILE NAME>.exe /f 
// Disable Remote Desktop
C:\> reg add "HKLM\SYSTEM\CurrentControlSet\Control\Termina lServer" /f /v fDenyTSConnections /t REG_DWORD /d 1
// Send NTLMv2 response only/refuse LM and NTLM (Windows 7 default) 
C:\> reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
// Restrict Anonymous Access
C:\> reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f 
// Do not allow anonymous enumeration of SAM accounts and shares
C:\> reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f 
// Disable IPV6
C:\> reg add HKLM\SYSTEM\CurrentControlSet\services\TCPIP6\Parameters /v DisabledComponents /t REG_DWORD /d 255 /f
// Disable sticky keys
C:\> reg add "HKCU\ControlPanel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f 
// Disable Toggle Keys
C:\> reg add "HKCU\ControlPanel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f 
// Disable Filter Keys
C:\> reg add "HKCU\ControlPanel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f 
// Disable On-screen Keyboard
C:\> reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI /f /v ShowTabletKeyboard /t REG_DWORD /d 0
// Disable Administrative Shares - Workstations
C:\> reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /f /v AutoShareWks /t REG_DWORD /d 0
// Disable Administrative Shares - Severs
C:\> reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /f /v AutoShareServer /t REG_DWORD /d 0
// Remove Creation of Hashes Used to Pass the Hash Attack (Requires password reset and reboot to purge 
old hashes)
C:\> reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /f /v NoLMHash /t REG_DWORD /d 1
// To Disable Registry Editor (High Risk) 
C:\> reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableRegistryTools /t REG_DWORD /d 1 /f 
// Disable IE Password Cache
C:\> reg add HKCU\Software\Microsoft\Windows\CurrentVersion\InternetSettings /v DisablePasswordCaching /t REG_DWORD /d 1 /f
// Disable CMD prompt
C:\> reg add HKCU\Software\Policies\Microsoft\Windows\System /v DisableCMD /t REG_DWORD /d 1 /f 
// Disable Admin credentials cache on host when using RDP 
C:\> reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
// Do not process the run once list
C:\> reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 
C:\> reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 
// Require User Access Control (UAC) Permission
C:\> reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f 
// Change password at next logon
PS C:\> Set-ADAccountPassword <USER> -NewPassword $newpwd -Reset -PassThru I Set-ADuser - ChangePasswordAtLogon $True
// Change password at next logon for OU Group
PS C:\> Get-ADuser -filter "department -eq '<OU GROUP>' -AND enabled -eq 'True 111 I Set-AD user - ChangePasswordAtLogon $True 
// Enabled Firewall logging
C:\> netsh firewall set logging droppedpackets connections = enable
```


| Task | Status (Open / Done) |
| --- | --- |
| Which AV or malware tools can detect and remove the malicious threat?	| |
| Is there a baseline system to review for changes? | |
| How does malware/attacker exit the network? | |
| Are malicious internal/external sites/connections still active?	| |
| Malware listening on any ports? | |
| Malware method of original infection, and/or weakness? | |
| Packet capture of malware trying to infect other systems? | |
| Check those potentially infected systems | |
| Isolate any other infected or potentially infected system  (Endpoint Security)| |
| Isolate potentially infected network areas (Firewall)| |
| If the system is not rooted, create outgoing firewall rules to block communication | |
| List all infected systems | |
| Packet capture of of malware trying to communicate out of the network? | |
| Checking DNS entries on the infected systems | |
| Enumerate possible malicious / C2 URLs and IPs | |
| Do any malicious scripts run on the infected systems? | |
| Check update services on the infected systems | |
| How many systems are still unknown, clear, suspicious or infected at this point? | |
| Active Directory OU isolation of suspected systems | |
| Active Directory user account restrictions and resets | |
| Active Directory policies to prohibit threats from running and/or access | |
| Administrative AD Password Changes | |
| Local Administrative Password Changes | |
| User AD Password Changes | |
| Local User Password Changes | |
| Service Account Password Changes | |
| What Active Directory GPO policies are set? | |
| What is the network architecture and how would Malware traverse? | |
| Are there additional IDS/IPS segments that need coverage to prevent/detect outbreaks? | |
| Enable DNS blocking (null route malware site(s)) | |
| Enable web filtering | |
| Put AV or malware tools in place to remove the threat | |
| Try multiple AV tools | |
| Endpoint Security - Scan Endpoint | |
| Scan for in Memory Execution (Thor Light Scanner / ...) | |


## 6. Closing
| Task | Status (Open / Done) |
| --- | --- |
| Setup a closing call in Teams / Slack	| |
| Pinpoint the timeline and relevant information we got so far | |
| Clarify if there are any open tasks or issues | |
| If yes, create follow-up tickets and link them to the incident ticket in ticketsystem | |
| Perform the lessons learned within the Incident Response team | |
| Is the customer informed? | |
| Are all systems up and running again? | |
| What's the range of the impact? | |
| Re-enable all services and access like firewall, DNS, etc. | |
| Cleanup all tools and emergency accounts on the systems | |
| Finalise the Post Mortem Analysis | |
| Attach relevant files to the Post Mortem Analysis | |
| Close the Teams / Slack channel | |
