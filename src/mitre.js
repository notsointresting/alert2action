/**
 * MITRE ATT&CK Technique Mapper
 * Maps alert keywords and behaviors to MITRE ATT&CK techniques
 */

// Comprehensive MITRE ATT&CK technique database with investigation guidance
const MITRE_TECHNIQUES = {
    // ===== RECONNAISSANCE (TA0043) =====
    'T1595': {
        id: 'T1595',
        name: 'Active Scanning',
        tactic: 'Reconnaissance',
        description: 'Adversaries actively scan victim infrastructure to gather information',
        keywords: ['port scan', 'network scan', 'vulnerability scan', 'service enumeration', 'nmap', 'masscan', 'reconnaissance'],
        logsToCheck: [
            'Firewall logs (denied connections)',
            'IDS/IPS alerts',
            'Web server access logs',
            'Network flow data'
        ],
        commands: {
            windows: [
                'Get-WinEvent -LogName "Security" | Where-Object {$_.Id -eq 5156 -and $_.Message -match "Inbound"}',
                'netsh advfirewall firewall show rule name=all | findstr "Block"'
            ],
            linux: [
                'cat /var/log/syslog | grep -i "blocked\\|denied"',
                'iptables -L -n -v | grep DROP',
                'grep -i "refused\\|scan" /var/log/messages'
            ]
        },
        containment: [
            'Block scanning source IP at firewall',
            'Enable rate limiting on border devices',
            'Review exposed services and reduce attack surface',
            'Consider honey pots for threat intelligence'
        ],
        falsePositives: [
            'Legitimate security scanners (Nessus, Qualys)',
            'IT inventory/asset discovery tools',
            'Network monitoring systems',
            'Authorized penetration testing'
        ]
    },

    // ===== INITIAL ACCESS (TA0001) =====
    'T1566': {
        id: 'T1566',
        name: 'Phishing',
        tactic: 'Initial Access',
        description: 'Adversaries send phishing messages to gain access to victim systems',
        keywords: ['phishing', 'spam', 'email', 'attachment', 'link', 'macro'],
        logsToCheck: [
            'Email gateway logs',
            'Email server logs (Exchange, O365)',
            'Web proxy logs for clicked links',
            'Endpoint process logs for Office applications'
        ],
        commands: {
            windows: [
                'Get-MessageTrace -SenderAddress <email> | Get-MessageTraceDetail',
                'Search-UnifiedAuditLog -Operations FileDownloaded,FileAccessed',
                'Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Id -eq 1 -and $_.Message -match "OUTLOOK|WINWORD"}'
            ],
            linux: [
                'grep -r "From:.*@suspicious" /var/log/mail.log',
                'ausearch -c "thunderbird" -ts today'
            ]
        },
        containment: [
            'Block sender email address/domain at email gateway',
            'Quarantine suspicious emails organization-wide',
            'Block malicious URLs at proxy/firewall',
            'Reset credentials for affected users'
        ],
        falsePositives: [
            'Legitimate marketing emails flagged by heuristics',
            'Internal phishing simulations/security awareness training',
            'Automated notification emails with external links'
        ]
    },

    'T1190': {
        id: 'T1190',
        name: 'Exploit Public-Facing Application',
        tactic: 'Initial Access',
        description: 'Adversaries exploit vulnerabilities in internet-facing applications',
        keywords: ['exploit', 'vulnerability', 'cve', 'web attack', 'injection', 'rce'],
        logsToCheck: [
            'Web application firewall (WAF) logs',
            'Web server access logs (IIS, Apache, Nginx)',
            'Application error logs',
            'IDS/IPS alerts'
        ],
        commands: {
            windows: [
                'Get-WinEvent -LogName "Microsoft-IIS-Logging/Logs" | Select-Object -First 100',
                'Get-Content C:\\inetpub\\logs\\LogFiles\\W3SVC1\\*.log | Select-String "4[0-9]{2}|5[0-9]{2}"'
            ],
            linux: [
                'cat /var/log/apache2/access.log | grep -E "(SELECT|UNION|INSERT|DROP|/etc/passwd)"',
                'journalctl -u nginx --since "1 hour ago"'
            ]
        },
        containment: [
            'Apply emergency patches to affected applications',
            'Enable WAF blocking rules',
            'Rate limit suspicious source IPs',
            'Consider taking application offline if actively exploited'
        ],
        falsePositives: [
            'Security scanners and penetration testing',
            'Legitimate but malformed requests',
            'Web crawlers triggering error pages'
        ]
    },

    'T1078': {
        id: 'T1078',
        name: 'Valid Accounts',
        tactic: 'Initial Access',
        description: 'Adversaries use legitimate credentials to gain access',
        keywords: ['valid account', 'compromised credential', 'stolen credential', 'account takeover'],
        logsToCheck: [
            'Authentication logs (Windows Security, Linux auth.log)',
            'VPN logs',
            'Cloud identity provider logs (Azure AD, Okta)',
            'SSO logs'
        ],
        commands: {
            windows: [
                'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624,4625} -MaxEvents 100 | Where-Object {$_.Properties[8].Value -eq 10}',
                'Get-ADUser -Filter * -Properties LastLogonDate,PasswordLastSet | Where-Object {$_.Enabled -eq $true}'
            ],
            linux: [
                'lastlog',
                'grep "Accepted\\|Failed" /var/log/auth.log | tail -100',
                'cat /var/log/secure | grep -i "accepted password"'
            ]
        },
        containment: [
            'Reset compromised account passwords immediately',
            'Revoke all active sessions/tokens',
            'Enable MFA if not already configured',
            'Review recent activity from compromised account'
        ],
        falsePositives: [
            'Legitimate travel or remote work from new locations',
            'VPN IP address changes',
            'Service account automation'
        ]
    },

    // ===== EXECUTION (TA0002) =====
    'T1059': {
        id: 'T1059',
        name: 'Command and Scripting Interpreter',
        tactic: 'Execution',
        description: 'Adversaries abuse command and script interpreters to execute commands',
        keywords: ['powershell', 'cmd', 'script', 'wscript', 'cscript', 'bash', 'python', 'execution', 'command line'],
        logsToCheck: [
            'PowerShell ScriptBlock logs (Event ID 4104)',
            'Windows Sysmon logs (Event ID 1)',
            'Process creation logs',
            'Command line audit logs'
        ],
        commands: {
            windows: [
                'Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -eq 4104}',
                'Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Id -eq 1 -and ($_.Message -match "powershell|cmd|wscript")}',
                'wevtutil qe Security /q:"*[System[(EventID=4688)]]" /f:text /c:50'
            ],
            linux: [
                'cat /var/log/auth.log | grep -E "(bash|python|perl|ruby)"',
                'history | grep -E "(wget|curl|nc|ncat)"',
                'ausearch -c bash --raw | aureport --summary'
            ]
        },
        containment: [
            'Kill malicious processes',
            'Isolate affected endpoint from network',
            'Block script execution via AppLocker/WDAC',
            'Review and remove any persistence mechanisms'
        ],
        falsePositives: [
            'Administrative scripts and automation',
            'IT management tools',
            'Developer activity',
            'Software installation scripts'
        ]
    },

    'T1059.001': {
        id: 'T1059.001',
        name: 'PowerShell',
        tactic: 'Execution',
        description: 'Adversaries abuse PowerShell for execution and automation',
        keywords: ['powershell', 'encoded', 'base64', 'invoke-expression', 'iex', 'bypass', 'downloadstring'],
        logsToCheck: [
            'PowerShell ScriptBlock logs (Event ID 4104)',
            'PowerShell Module logs (Event ID 4103)',
            'Windows Sysmon Event ID 1',
            'Windows Security Event ID 4688'
        ],
        commands: {
            windows: [
                'Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 | Where-Object {$_.Id -eq 4104} | Format-List',
                'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=1} | Where-Object {$_.Message -match "powershell.*-enc|-encoded|downloadstring|invoke-expression"}',
                'Get-Process powershell,pwsh -ErrorAction SilentlyContinue | Select-Object Id,Name,CommandLine'
            ],
            linux: [
                'ps aux | grep -i pwsh'
            ]
        },
        containment: [
            'Terminate suspicious PowerShell processes',
            'Enable Constrained Language Mode',
            'Block encoded command execution via GPO',
            'Capture process memory for forensics before termination'
        ],
        falsePositives: [
            'System Center Configuration Manager (SCCM)',
            'Azure automation scripts',
            'IT admin troubleshooting',
            'Legitimate base64 operations'
        ]
    },

    // ===== PERSISTENCE (TA0003) =====
    'T1053': {
        id: 'T1053',
        name: 'Scheduled Task/Job',
        tactic: 'Persistence',
        description: 'Adversaries abuse task scheduling to maintain persistence',
        keywords: ['scheduled task', 'cron', 'at job', 'task scheduler', 'persistence'],
        logsToCheck: [
            'Windows Task Scheduler logs (Event ID 106, 140, 141)',
            'Windows Security logs (Event ID 4698, 4699, 4700)',
            'Linux cron logs',
            'Sysmon Event ID 1 for schtasks.exe'
        ],
        commands: {
            windows: [
                'Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object TaskName,TaskPath,State',
                'schtasks /query /v /fo csv | ConvertFrom-Csv | Where-Object {$_."Next Run Time" -ne "N/A"}',
                'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4698} -MaxEvents 50'
            ],
            linux: [
                'crontab -l',
                'cat /etc/crontab',
                'ls -la /etc/cron.d/',
                'systemctl list-timers --all'
            ]
        },
        containment: [
            'Delete malicious scheduled tasks',
            'Audit all scheduled tasks across affected systems',
            'Restrict task scheduler permissions',
            'Monitor for task recreation'
        ],
        falsePositives: [
            'System maintenance tasks',
            'Backup schedules',
            'Patch management automation',
            'Monitoring agent tasks'
        ]
    },

    'T1547': {
        id: 'T1547',
        name: 'Boot or Logon Autostart Execution',
        tactic: 'Persistence',
        description: 'Adversaries configure system settings to run programs at startup',
        keywords: ['autorun', 'startup', 'registry', 'run key', 'boot', 'logon'],
        logsToCheck: [
            'Sysmon Event ID 12, 13, 14 (Registry)',
            'Windows Security Event ID 4657',
            'Autoruns output',
            'Startup folder contents'
        ],
        commands: {
            windows: [
                'Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"',
                'Get-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"',
                'Get-ChildItem "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"',
                'autorunsc.exe -accepteula -a * -c -h -s -v -vt'
            ],
            linux: [
                'ls -la /etc/init.d/',
                'systemctl list-unit-files --type=service --state=enabled',
                'cat ~/.bashrc ~/.profile | grep -v "^#"'
            ]
        },
        containment: [
            'Remove malicious registry entries',
            'Delete startup folder items',
            'Disable malicious services',
            'Re-image endpoint if heavily compromised'
        ],
        falsePositives: [
            'Legitimate software updaters',
            'Antivirus startup entries',
            'Corporate management agents',
            'User-installed applications'
        ]
    },

    // ===== PRIVILEGE ESCALATION (TA0004) =====
    'T1548.002': {
        id: 'T1548.002',
        name: 'Bypass User Account Control',
        tactic: 'Privilege Escalation',
        description: 'Adversaries bypass UAC to elevate privileges without prompting the user',
        keywords: ['uac bypass', 'privilege escalation', 'elevation', 'system', 'admin', 'token_elevation', 'integrity_level', 'auto-elevated', 'silentcleanup'],
        logsToCheck: [
            'Sysmon Event ID 1 (Process Creation with elevated token)',
            'Windows Security Event ID 4688 (Process Creation)',
            'Windows Security Event ID 4648 (Explicit Credential Use)',
            'UAC Event ID 1 in Application Log'
        ],
        commands: {
            windows: [
                'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4688} | Where-Object {$_.Message -match "TokenElevationType.*%%1937"}',
                'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=1} | Where-Object {$_.Message -match "IntegrityLevel.*System|High"}',
                'Get-ScheduledTask | Where-Object {$_.Principal.RunLevel -eq "Highest"} | Select-Object TaskName,TaskPath',
                'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA'
            ],
            linux: [
                'cat /var/log/auth.log | grep -i "sudo\\|su "',
                'ausearch -m USER_AUTH -ts today'
            ]
        },
        containment: [
            'IMMEDIATELY isolate endpoint - active compromise',
            'Terminate elevated processes spawned by attack',
            'Review and remove any malicious scheduled tasks',
            'Check for persistence mechanisms (services, registry)',
            'Force password reset for affected user',
            'Enable UAC highest setting and investigate bypass method'
        ],
        falsePositives: [
            'Legitimate auto-elevation by installers',
            'Administrative tools with manifest requesting elevation',
            'Windows Update and maintenance tasks',
            'Enterprise software deployment'
        ]
    },

    'T1134': {
        id: 'T1134',
        name: 'Access Token Manipulation',
        tactic: 'Privilege Escalation',
        description: 'Adversaries manipulate access tokens to operate under different security contexts',
        keywords: ['token', 'impersonation', 'privilege', 'system', 'token_elevation', 'logon_type', 'security context'],
        logsToCheck: [
            'Windows Security Event ID 4624 (Logon with token info)',
            'Windows Security Event ID 4672 (Special Privileges Assigned)',
            'Sysmon Event ID 10 (Process Access)',
            'Windows Security Event ID 4673 (Privileged Service Called)'
        ],
        commands: {
            windows: [
                'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4672} -MaxEvents 50 | Format-List',
                'whoami /priv',
                'Get-Process | Where-Object {$_.SessionId -eq 0} | Select-Object Name,Id,SessionId',
                'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624} | Where-Object {$_.Properties[8].Value -eq 9}'
            ],
            linux: [
                'ps aux | grep -E "^root.*pts"',
                'cat /var/log/auth.log | grep -i "session opened for user root"'
            ]
        },
        containment: [
            'Terminate processes using stolen/manipulated tokens',
            'Isolate affected system',
            'Force logoff all sessions on compromised host',
            'Reset credentials for impersonated accounts',
            'Review all SYSTEM-level processes for malicious activity'
        ],
        falsePositives: [
            'Service accounts running as SYSTEM',
            'Scheduled tasks running with elevated privileges',
            'Windows services performing impersonation',
            'Remote management tools'
        ]
    },

    // ===== CREDENTIAL ACCESS (TA0006) =====
    'T1003': {
        id: 'T1003',
        name: 'OS Credential Dumping',
        tactic: 'Credential Access',
        description: 'Adversaries attempt to dump credentials from the operating system',
        keywords: ['credential dump', 'mimikatz', 'lsass', 'hash', 'password dump', 'sam', 'ntds'],
        logsToCheck: [
            'Sysmon Event ID 10 (Process Access to LSASS)',
            'Windows Security Event ID 4656, 4663',
            'Windows Defender alerts',
            'EDR process access alerts'
        ],
        commands: {
            windows: [
                'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=10} | Where-Object {$_.Message -match "lsass.exe"}',
                'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4656} | Where-Object {$_.Message -match "lsass"}',
                'Get-Process lsass | Select-Object Id,Name,Handles,CPU'
            ],
            linux: [
                'cat /var/log/auth.log | grep -i "shadow\\|passwd"',
                'ausearch -sc open -f /etc/shadow'
            ]
        },
        containment: [
            'Isolate endpoint immediately',
            'Force password reset for ALL users who logged into compromised system',
            'Rotate Kerberos KRBTGT account (domain-wide compromise)',
            'Enable Credential Guard if not configured'
        ],
        falsePositives: [
            'Antivirus scanning LSASS',
            'Windows Defender ATP collecting telemetry',
            'Legitimate security tools'
        ]
    },

    // ===== DEFENSE EVASION (TA0005) =====
    'T1055': {
        id: 'T1055',
        name: 'Process Injection',
        tactic: 'Defense Evasion',
        description: 'Adversaries inject code into processes to evade defenses',
        keywords: ['process injection', 'dll injection', 'hollowing', 'code injection', 'remote thread'],
        logsToCheck: [
            'Sysmon Event ID 8 (CreateRemoteThread)',
            'Sysmon Event ID 10 (Process Access)',
            'Windows Security Event ID 4688',
            'EDR process injection alerts'
        ],
        commands: {
            windows: [
                'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=8} | Select-Object -First 20',
                'Get-Process | Where-Object {$_.Modules.Count -gt 100} | Select-Object Name,Id',
                'malfind (Volatility plugin on memory dump)'
            ],
            linux: [
                'cat /proc/[pid]/maps | grep rwx',
                'grep -r "LD_PRELOAD" /proc/*/environ 2>/dev/null'
            ]
        },
        containment: [
            'Isolate affected endpoint',
            'Capture memory dump before terminating processes',
            'Identify injected code and parent process',
            'Block malicious process hashes'
        ],
        falsePositives: [
            'Antivirus real-time scanning',
            'Application compatibility shims',
            'Debugging tools',
            'Some legitimate software hooks'
        ]
    },

    'T1070': {
        id: 'T1070',
        name: 'Indicator Removal',
        tactic: 'Defense Evasion',
        description: 'Adversaries delete or modify artifacts to hide their activity',
        keywords: ['log clearing', 'indicator removal', 'timestomp', 'file deletion', 'event log', 'audit'],
        logsToCheck: [
            'Windows Security Event ID 1102 (Audit Log Cleared)',
            'Windows Security Event ID 104 (System Log Cleared)',
            'Sysmon Event ID 23 (File Delete)',
            'File integrity monitoring alerts'
        ],
        commands: {
            windows: [
                'Get-WinEvent -FilterHashtable @{LogName="Security";Id=1102} -MaxEvents 10',
                'Get-WinEvent -FilterHashtable @{LogName="System";Id=104} -MaxEvents 10',
                'wevtutil el | ForEach-Object {wevtutil gli $_} | Where-Object {$_ -match "numberOfLogRecords: 0"}'
            ],
            linux: [
                'ls -la /var/log/ | grep "^-.*0"',
                'stat /var/log/auth.log',
                'ausearch -m DEL -ts today'
            ]
        },
        containment: [
            'Preserve remaining logs immediately',
            'Enable centralized logging if not configured',
            'Check for backup log copies',
            'Review shadow copies for deleted evidence'
        ],
        falsePositives: [
            'Log rotation',
            'System administrators clearing old logs',
            'Storage cleanup scripts'
        ]
    },

    // ===== DISCOVERY (TA0007) =====
    'T1087': {
        id: 'T1087',
        name: 'Account Discovery',
        tactic: 'Discovery',
        description: 'Adversaries enumerate accounts to understand the environment',
        keywords: ['account discovery', 'user enumeration', 'net user', 'domain users', 'whoami'],
        logsToCheck: [
            'Windows Security Event ID 4798, 4799',
            'Sysmon Event ID 1 (net.exe usage)',
            'LDAP query logs',
            'Active Directory audit logs'
        ],
        commands: {
            windows: [
                'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=1} | Where-Object {$_.Message -match "net user|net group|dsquery"}',
                'Get-ADUser -Filter * -Properties LastLogonDate | Where-Object {$_.LastLogonDate -gt (Get-Date).AddDays(-7)}',
                'Get-WinEvent -LogName "Security" | Where-Object {$_.Id -in @(4798,4799)}'
            ],
            linux: [
                'grep -E "getent|ldapsearch|cat.*passwd" /var/log/auth.log',
                'ausearch -c getent -ts today'
            ]
        },
        containment: [
            'Review if enumeration was from compromised account',
            'Limit LDAP query permissions',
            'Enable detailed AD auditing',
            'Monitor for subsequent lateral movement'
        ],
        falsePositives: [
            'IT admin account audits',
            'HR onboarding scripts',
            'Directory sync tools',
            'Help desk user lookups'
        ]
    },

    // ===== EXFILTRATION (TA0010) =====
    'T1041': {
        id: 'T1041',
        name: 'Exfiltration Over C2 Channel',
        tactic: 'Exfiltration',
        description: 'Adversaries exfiltrate data over existing command and control channels',
        keywords: ['exfiltration', 'data theft', 'data transfer', 'large transfer', 'upload', 'data exfil'],
        logsToCheck: [
            'Proxy/Firewall logs (large outbound transfers)',
            'DLP alerts',
            'Cloud access security broker (CASB) logs',
            'Network flow data'
        ],
        commands: {
            windows: [
                'Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Sort-Object -Property OwningProcess | Select-Object -First 20',
                'Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Id -eq 3 -and $_.Message -match "Destination.*:443|:80"}'
            ],
            linux: [
                'ss -tunapl | sort -nk5 | tail -20',
                'nethogs -v 3',
                'iftop -t -s 10'
            ]
        },
        containment: [
            'Block C2 communication immediately',
            'Identify and preserve exfiltrated data scope',
            'Check DLP logs for data classification',
            'Notify legal/compliance for breach assessment',
            'Preserve network captures for forensics'
        ],
        falsePositives: [
            'Large legitimate file uploads (backups)',
            'Video conferencing',
            'Cloud sync services',
            'Software updates'
        ]
    },

    // ===== LATERAL MOVEMENT (TA0008) =====
    'T1021': {
        id: 'T1021',
        name: 'Remote Services',
        tactic: 'Lateral Movement',
        description: 'Adversaries use remote services to move laterally within network',
        keywords: ['lateral', 'remote', 'psexec', 'wmi', 'smb', 'rdp', 'ssh', 'winrm'],
        logsToCheck: [
            'Windows Security Event ID 4624 (logon type 3, 10)',
            'Windows Security Event ID 4648 (explicit credentials)',
            'SMB logs',
            'RDP connection logs',
            'SSH auth logs'
        ],
        commands: {
            windows: [
                'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624} | Where-Object {$_.Properties[8].Value -in @(3,10)} | Select-Object -First 50',
                'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";Id=1149}',
                'qwinsta /server:<hostname>'
            ],
            linux: [
                'grep "Accepted" /var/log/auth.log | tail -50',
                'last -50',
                'who'
            ]
        },
        containment: [
            'Block lateral movement paths at network level',
            'Disable administrative shares if not needed',
            'Segment network to limit lateral movement',
            'Force re-authentication on sensitive systems'
        ],
        falsePositives: [
            'Normal admin remote management',
            'File server access',
            'Patch management systems',
            'Jump server usage'
        ]
    },

    // ===== COMMAND AND CONTROL (TA0011) =====
    'T1071': {
        id: 'T1071',
        name: 'Application Layer Protocol',
        tactic: 'Command and Control',
        description: 'Adversaries communicate using application layer protocols',
        keywords: ['c2', 'command and control', 'beacon', 'callback', 'http', 'https', 'dns'],
        logsToCheck: [
            'Proxy/Firewall logs',
            'DNS query logs',
            'Network flow data',
            'EDR network telemetry'
        ],
        commands: {
            windows: [
                'Get-NetTCPConnection | Where-Object {$_.State -eq "Established" -and $_.RemotePort -in @(80,443,8080)}',
                'Get-DnsClientCache | Where-Object {$_.Entry -notmatch "microsoft|windows|office"}',
                'netstat -ano | findstr ESTABLISHED'
            ],
            linux: [
                'netstat -tunapl | grep ESTABLISHED',
                'ss -tunapl',
                'cat /var/log/syslog | grep -i dns'
            ]
        },
        containment: [
            'Block C2 IP addresses/domains at firewall',
            'Sinkhole malicious domains',
            'Isolate infected endpoints',
            'Hunt for additional infected hosts communicating to same C2'
        ],
        falsePositives: [
            'CDN traffic',
            'Cloud service connections',
            'Software update services',
            'Legitimate API calls'
        ]
    },

    // ===== IMPACT (TA0040) =====
    'T1486': {
        id: 'T1486',
        name: 'Data Encrypted for Impact',
        tactic: 'Impact',
        description: 'Adversaries encrypt data to render it inaccessible (ransomware)',
        keywords: ['ransomware', 'encrypt', 'ransom', 'locked files', 'cryptolocker', 'bitcoin'],
        logsToCheck: [
            'File system audit logs',
            'Sysmon Event ID 11 (File Create)',
            'Volume Shadow Copy deletion logs',
            'Backup system logs'
        ],
        commands: {
            windows: [
                'vssadmin list shadows',
                'Get-ChildItem -Path C:\\ -Recurse -Include "*.encrypted","*.locked","README*.txt","DECRYPT*.txt" -ErrorAction SilentlyContinue | Select-Object -First 20',
                'Get-WinEvent -FilterHashtable @{LogName="Application";Id=8194} -MaxEvents 10'
            ],
            linux: [
                'find / -name "*.encrypted" -o -name "*README*ransom*" 2>/dev/null | head -20',
                'df -h'
            ]
        },
        containment: [
            'IMMEDIATELY isolate affected systems from network',
            'Do NOT shut down - preserve memory for forensics',
            'Stop ransomware process if still running',
            'Identify patient zero and encryption timestamp',
            'Assess backup availability and integrity'
        ],
        falsePositives: [
            'Legitimate encryption software (BitLocker, VeraCrypt)',
            'File archiving with password protection',
            'DRM-protected content'
        ]
    },

    // ===== BRUTE FORCE (Special) =====
    'T1110': {
        id: 'T1110',
        name: 'Brute Force',
        tactic: 'Credential Access',
        description: 'Adversaries use brute force techniques to obtain credentials',
        keywords: ['brute force', 'password spray', 'credential stuffing', 'failed login', 'authentication failure', 'multiple failed'],
        logsToCheck: [
            'Windows Security Event ID 4625 (Failed logon)',
            'Windows Security Event ID 4771 (Kerberos pre-auth failed)',
            'Azure AD Sign-in logs',
            'Linux /var/log/auth.log'
        ],
        commands: {
            windows: [
                'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4625} -MaxEvents 100 | Group-Object {$_.Properties[5].Value} | Sort-Object Count -Descending',
                'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4625} | Group-Object {$_.Properties[19].Value} | Sort-Object Count -Descending | Select-Object -First 10',
                'net accounts'
            ],
            linux: [
                'grep "Failed password" /var/log/auth.log | awk \'{print $(NF-3)}\' | sort | uniq -c | sort -rn | head -10',
                'lastb | head -50',
                'fail2ban-client status sshd'
            ]
        },
        containment: [
            'Block attacking IP addresses',
            'Lock affected user accounts temporarily',
            'Enable account lockout policies',
            'Implement MFA for targeted accounts',
            'Consider geo-blocking if attacks from specific regions'
        ],
        falsePositives: [
            'Users forgetting passwords',
            'Password manager sync issues',
            'Cached credentials after password change',
            'Service accounts with expired passwords'
        ]
    }
};

/**
 * Map alert to MITRE ATT&CK techniques based on keywords and context
 */
function mapToMitre(parsedAlert) {
    const matches = [];
    const keywords = parsedAlert.keywords || [];
    const allText = [
        parsedAlert.title,
        parsedAlert.description,
        parsedAlert.category,
        parsedAlert.processCommandLine
    ].filter(Boolean).join(' ').toLowerCase();

    for (const [techId, technique] of Object.entries(MITRE_TECHNIQUES)) {
        let score = 0;
        const matchedKeywords = [];

        // Check each technique's keywords
        for (const keyword of technique.keywords) {
            if (keywords.includes(keyword) || allText.includes(keyword)) {
                score += 10;
                matchedKeywords.push(keyword);
            }
        }

        // Boost score for specific indicators
        if (techId === 'T1110' && (allText.includes('failed') && allText.includes('login'))) {
            score += 20;
        }
        if (techId === 'T1059.001' && parsedAlert.processName?.toLowerCase().includes('powershell')) {
            score += 30;
        }
        if (techId === 'T1003' && allText.includes('lsass')) {
            score += 30;
        }
        if (techId === 'T1566' && (allText.includes('email') || allText.includes('attachment'))) {
            score += 15;
        }

        // T1053 (Scheduled Task) - require actual evidence of scheduled tasks
        if (techId === 'T1053') {
            const hasSchtasks = parsedAlert.processName?.toLowerCase().includes('schtasks');
            const hasTaskName = allText.includes('task') && (allText.includes('create') || allText.includes('schedule'));
            const hasTaskEvidence = parsedAlert.rawData?.persistence?.method?.toLowerCase().includes('task');
            if (hasSchtasks || hasTaskEvidence) {
                score += 25; // Strong evidence
            } else if (!hasTaskName && score < 15) {
                score = 0; // Remove weak matches to avoid false positives
            }
        }

        // T1548.002 (UAC Bypass) - boost for privilege escalation context
        if (techId === 'T1548.002') {
            if (allText.includes('uac') || allText.includes('bypass')) {
                score += 25;
            }
            if (parsedAlert.rawData?.privilege_escalation?.attempted) {
                score += 30;
            }
        }

        // T1134 (Token Manipulation) - boost for token/privilege context  
        if (techId === 'T1134') {
            if (allText.includes('token') || allText.includes('impersonation')) {
                score += 20;
            }
            if (parsedAlert.rawData?.privilege_change?.new_integrity_level === 'System') {
                score += 30;
            }
        }

        if (score > 0) {
            matches.push({
                technique: technique,
                score: score,
                matchedKeywords: matchedKeywords,
                confidence: score >= 30 ? 'high' : score >= 15 ? 'medium' : 'low'
            });
        }
    }

    // Sort by score descending
    matches.sort((a, b) => b.score - a.score);

    // Return top 3 matches
    return matches.slice(0, 3);
}

/**
 * Get a technique by ID
 */
function getTechnique(techId) {
    return MITRE_TECHNIQUES[techId] || null;
}

/**
 * Get all techniques
 */
function getAllTechniques() {
    return MITRE_TECHNIQUES;
}

module.exports = { mapToMitre, getTechnique, getAllTechniques };
