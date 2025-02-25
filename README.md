# Sentinel-rules </br>
Failed Login Attempts (Brute Force Detection)</br>
SecurityEvent</br>
| where EventID == 4625</br>
| summarize count() by Account, IpAddress, bin(TimeGenerated, 5m)</br>
| where count_ > 5</br>
Detects multiple failed logins from the same IP within 5 minutes.</br>

Successful Logins from Unusual Locations</br>
SecurityEvent</br>
| where EventID == 4624</br>
| summarize by Account, IpAddress, Computer</br>
| join kind=leftanti (SignInLogs | summarize by Account, IpAddress)</br>
Flags successful logins from previously unseen locations.</br>

Privileged Account Logins</br>
SecurityEvent</br>
| where EventID == 4672</br>
| summarize count() by Account, Computer, TimeGenerated</br>
Tracks logins with admin privileges.</br>

Multiple Account Lockouts</br>
SecurityEvent</br>
| where EventID == 4740</br>
| summarize count() by Account</br>
| where count_ > 3</br>
Identifies repeated account lockouts.</br>

File Integrity Monitoring (FIM) – Suspicious File Changes</br>
SecurityEvent</br>
| where EventID in (4663, 4656)</br>
| summarize count() by ObjectName, AccessMask, Account</br>
| where count_ > 10</br>
Monitors frequent file changes or deletions.</br>

Port Scanning Activity</br>
AzureDiagnostics</br>
| where Category == "AzureFirewallNetworkRule"</br>
| summarize unique_ports=dcount(DestinationPortNumber) by SourceIp, bin(TimeGenerated, 10m)</br>
| where unique_ports > 20</br>
Detects IPs scanning multiple ports within 10 minutes.</br>

Command and Control (C2) Beaconing</br>
SecurityEvent</br>
| where EventID == 5156</br>
| summarize count() by IpAddress, ProcessName, bin(TimeGenerated, 5m)</br>
| where count_ > 50</br>
Flags repetitive outbound connections that could indicate beaconing.</br>

DNS Tunneling</br>
DnsEvents</br>
| extend QueryLength = strlen(Query)</br>
| where QueryLength > 50</br>
Identifies long DNS queries (potential data exfiltration).</br>

Unusual Process Execution</br>
SecurityEvent</br>
| where EventID == 4688</br>
| summarize count() by NewProcessName, CommandLine</br>
| where count_ < 5</br>
Detects rare or suspicious process executions.</br>

Data Exfiltration (Large File Transfers)</br>
AzureDiagnostics</br>
| where Category == "AzureFirewallNetworkRule"</br>
| summarize TotalBytesTransferred = sum(SentBytes) by SourceIp, DestinationIp, bin(TimeGenerated, 10m)</br>
| where TotalBytesTransferred > 10000000</br>
