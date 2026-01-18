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
    },

    // ===== COLLECTION (TA0009) =====
    'T1560': {
        id: 'T1560',
        name: 'Archive Collected Data',
        tactic: 'Collection',
        description: 'Adversaries archive collected data for exfiltration',
        keywords: ['archive', 'zip', 'rar', '7z', 'compress', 'staging'],
        logsToCheck: ['File creation logs', 'Process creation logs', 'EDR file activity'],
        commands: {
            windows: ['Get-ChildItem -Path C:\\ -Recurse -Include "*.zip","*.rar","*.7z" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 20'],
            linux: ['find / -name "*.zip" -o -name "*.tar.gz" -mtime -1 2>/dev/null']
        },
        containment: ['Quarantine archive files', 'Block archive creation tools', 'Monitor staging directories'],
        falsePositives: ['Legitimate backups', 'Software distribution', 'User file compression']
    },

    'T1119': {
        id: 'T1119',
        name: 'Automated Collection',
        tactic: 'Collection',
        description: 'Adversaries use automated techniques to collect data',
        keywords: ['automated collection', 'data harvesting', 'bulk', 'scraping'],
        logsToCheck: ['File access logs', 'Database query logs', 'Network traffic'],
        commands: {
            windows: ['Get-WinEvent -FilterHashtable @{LogName="Security";Id=4663} -MaxEvents 100'],
            linux: ['ausearch -m OPEN -ts today | head -50']
        },
        containment: ['Rate limit data access', 'Enable DLP', 'Monitor bulk file operations'],
        falsePositives: ['Backup software', 'Indexing services', 'Legitimate data exports']
    },

    'T1213': {
        id: 'T1213',
        name: 'Data from Information Repositories',
        tactic: 'Collection',
        description: 'Adversaries collect data from SharePoint, Confluence, etc.',
        keywords: ['sharepoint', 'confluence', 'wiki', 'repository', 'intranet'],
        logsToCheck: ['SharePoint audit logs', 'Confluence access logs', 'O365 audit logs'],
        commands: {
            windows: ['Search-UnifiedAuditLog -Operations FileDownloaded,FileAccessed -StartDate (Get-Date).AddDays(-1)'],
            linux: ['grep -i "download\\|export" /var/log/application.log']
        },
        containment: ['Revoke suspicious session tokens', 'Review permissions', 'Enable download alerts'],
        falsePositives: ['Normal employee research', 'Onboarding activities', 'Authorized exports']
    },

    // ===== MORE DEFENSE EVASION =====
    'T1562': {
        id: 'T1562',
        name: 'Impair Defenses',
        tactic: 'Defense Evasion',
        description: 'Adversaries disable security tools to evade detection',
        keywords: ['disable', 'av', 'antivirus', 'edr', 'firewall', 'defender', 'tamper'],
        logsToCheck: ['Windows Defender logs', 'EDR status logs', 'Windows Security Event 4688'],
        commands: {
            windows: ['Get-MpPreference | Select-Object DisableRealtimeMonitoring', 'Get-Service WinDefend | Select-Object Status'],
            linux: ['systemctl status clamd', 'auditctl -l']
        },
        containment: ['Re-enable security tools', 'Isolate endpoint', 'Investigate root cause'],
        falsePositives: ['IT maintenance', 'Software conflicts', 'Temporary disable for testing']
    },

    'T1036': {
        id: 'T1036',
        name: 'Masquerading',
        tactic: 'Defense Evasion',
        description: 'Adversaries disguise malicious files or processes',
        keywords: ['masquerading', 'rename', 'disguise', 'fake', 'impersonate', 'svchost'],
        logsToCheck: ['Sysmon Event ID 1', 'File rename logs', 'Process creation with path'],
        commands: {
            windows: ['Get-Process | Where-Object {$_.Path -notmatch "System32" -and $_.Name -match "svchost|csrss|lsass"}'],
            linux: ['ps aux | grep -v "/usr/bin\\|/bin\\|/sbin"']
        },
        containment: ['Terminate suspicious processes', 'Block file hashes', 'Investigate binary origin'],
        falsePositives: ['Portable applications', 'Developer testing', 'Non-standard installations']
    },

    'T1218': {
        id: 'T1218',
        name: 'Signed Binary Proxy Execution',
        tactic: 'Defense Evasion',
        description: 'Adversaries use signed binaries to proxy execution of malicious code',
        keywords: ['lolbin', 'mshta', 'regsvr32', 'rundll32', 'certutil', 'signed binary'],
        logsToCheck: ['Sysmon Event ID 1', 'Windows Security 4688', 'EDR process logs'],
        commands: {
            windows: ['Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=1} | Where-Object {$_.Message -match "mshta|regsvr32|rundll32|certutil|bitsadmin"}'],
            linux: ['N/A - Windows specific']
        },
        containment: ['Block suspicious command lines', 'Enable AppLocker rules', 'Monitor LOLBIN usage'],
        falsePositives: ['Legitimate admin scripts', 'Software installations', 'Certificate operations']
    },

    // ===== MORE DISCOVERY =====
    'T1082': {
        id: 'T1082',
        name: 'System Information Discovery',
        tactic: 'Discovery',
        description: 'Adversaries gather system configuration information',
        keywords: ['systeminfo', 'hostname', 'uname', 'system information', 'discovery'],
        logsToCheck: ['Sysmon Event ID 1', 'Process audit logs', 'Command line logging'],
        commands: {
            windows: ['Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=1} | Where-Object {$_.Message -match "systeminfo|hostname|ipconfig"}'],
            linux: ['grep -E "uname|hostnamectl|cat /etc/os-release" /var/log/auth.log']
        },
        containment: ['Correlate with other discovery', 'Monitor for lateral movement', 'Alert on enumeration chains'],
        falsePositives: ['IT troubleshooting', 'Inventory scripts', 'Monitoring tools']
    },

    'T1083': {
        id: 'T1083',
        name: 'File and Directory Discovery',
        tactic: 'Discovery',
        description: 'Adversaries enumerate files and directories',
        keywords: ['dir', 'ls', 'find', 'tree', 'file discovery', 'directory'],
        logsToCheck: ['Sysmon Event ID 1', 'File access audit logs', 'EDR telemetry'],
        commands: {
            windows: ['Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=1} | Where-Object {$_.Message -match "dir.*recurse|tree|Get-ChildItem.*Recurse"}'],
            linux: ['ausearch -c find -ts today', 'grep -E "find /|ls -la" /var/log/auth.log']
        },
        containment: ['Monitor for sensitive file access', 'Enable file integrity monitoring'],
        falsePositives: ['File searches', 'Backup verification', 'Legitimate admin tasks']
    },

    'T1069': {
        id: 'T1069',
        name: 'Permission Groups Discovery',
        tactic: 'Discovery',
        description: 'Adversaries discover local and domain permission groups',
        keywords: ['net group', 'net localgroup', 'domain admins', 'groups', 'permission'],
        logsToCheck: ['Windows Security Event 4799', 'Sysmon Event ID 1', 'LDAP query logs'],
        commands: {
            windows: ['Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=1} | Where-Object {$_.Message -match "net group|net localgroup|Get-ADGroup"}'],
            linux: ['grep "getent group" /var/log/auth.log']
        },
        containment: ['Monitor for subsequent privilege escalation', 'Review group memberships'],
        falsePositives: ['IT administration', 'Security audits', 'Compliance checks']
    },

    // ===== MORE PERSISTENCE =====
    'T1543': {
        id: 'T1543',
        name: 'Create or Modify System Process',
        tactic: 'Persistence',
        description: 'Adversaries create or modify system services for persistence',
        keywords: ['service', 'daemon', 'systemd', 'sc create', 'new-service'],
        logsToCheck: ['Windows Security Event 4697', 'Sysmon Event ID 1', 'Systemd logs'],
        commands: {
            windows: ['Get-WinEvent -FilterHashtable @{LogName="Security";Id=4697} -MaxEvents 20', 'Get-Service | Where-Object {$_.StartType -eq "Automatic" -and $_.Status -eq "Running"}'],
            linux: ['systemctl list-unit-files --type=service --state=enabled', 'journalctl -u <service>']
        },
        containment: ['Disable malicious services', 'Remove service registry entries', 'Re-image if needed'],
        falsePositives: ['Software installations', 'IT deployments', 'Legitimate service updates']
    },

    'T1136': {
        id: 'T1136',
        name: 'Create Account',
        tactic: 'Persistence',
        description: 'Adversaries create new accounts to maintain access',
        keywords: ['create account', 'new user', 'net user add', 'useradd', 'adduser'],
        logsToCheck: ['Windows Security Event 4720', 'Linux /var/log/auth.log', 'Azure AD audit logs'],
        commands: {
            windows: ['Get-WinEvent -FilterHashtable @{LogName="Security";Id=4720} -MaxEvents 20', 'Get-LocalUser | Where-Object {$_.Enabled -eq $true}'],
            linux: ['grep "useradd\\|adduser" /var/log/auth.log', 'cat /etc/passwd | tail -10']
        },
        containment: ['Disable rogue accounts', 'Reset passwords', 'Audit all recent account creations'],
        falsePositives: ['IT onboarding', 'Service account creation', 'Contractors']
    },

    // ===== MORE INITIAL ACCESS =====
    'T1189': {
        id: 'T1189',
        name: 'Drive-by Compromise',
        tactic: 'Initial Access',
        description: 'Adversaries compromise users through malicious websites',
        keywords: ['drive-by', 'watering hole', 'browser exploit', 'malvertising', 'iframe'],
        logsToCheck: ['Web proxy logs', 'Browser history', 'DNS logs', 'EDR browser events'],
        commands: {
            windows: ['Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {$_.Id -eq 3 -and $_.Message -match "iexplore|chrome|firefox|edge"}'],
            linux: ['grep -E "GET.*\\.js|GET.*\\.html" /var/log/squid/access.log']
        },
        containment: ['Block malicious domains', 'Patch browsers', 'Enable browser isolation'],
        falsePositives: ['Legitimate ad networks', 'Marketing trackers', 'CDN resources']
    },

    'T1199': {
        id: 'T1199',
        name: 'Trusted Relationship',
        tactic: 'Initial Access',
        description: 'Adversaries abuse trusted third-party relationships',
        keywords: ['supply chain', 'vendor', 'third party', 'msp', 'trusted relationship'],
        logsToCheck: ['VPN logs', 'Third-party access logs', 'Service account activity'],
        commands: {
            windows: ['Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624} | Where-Object {$_.Properties[5].Value -match "vendor|msp|support"}'],
            linux: ['grep -E "vendor|support|msp" /var/log/auth.log']
        },
        containment: ['Revoke vendor access', 'Audit third-party permissions', 'Segment vendor networks'],
        falsePositives: ['Legitimate vendor support', 'Managed service activity', 'Authorized remote access']
    },

    // ===== MORE CREDENTIAL ACCESS =====
    'T1558': {
        id: 'T1558',
        name: 'Steal or Forge Kerberos Tickets',
        tactic: 'Credential Access',
        description: 'Adversaries steal or forge Kerberos tickets for access',
        keywords: ['kerberos', 'golden ticket', 'silver ticket', 'kerberoast', 'pass-the-ticket'],
        logsToCheck: ['Windows Security Event 4769', 'Domain Controller logs', 'Kerberos authentication logs'],
        commands: {
            windows: ['Get-WinEvent -FilterHashtable @{LogName="Security";Id=4769} | Where-Object {$_.Properties[4].Value -eq "0x17"}', 'klist'],
            linux: ['N/A - Windows/AD specific']
        },
        containment: ['Reset KRBTGT twice', 'Disable compromised accounts', 'Review SPNs'],
        falsePositives: ['Legitimate Kerberos usage', 'Service authentication', 'SSO systems']
    },

    'T1552': {
        id: 'T1552',
        name: 'Unsecured Credentials',
        tactic: 'Credential Access',
        description: 'Adversaries search for unsecured credentials in files',
        keywords: ['password file', 'credentials', '.env', 'config file', 'plaintext password'],
        logsToCheck: ['File access logs', 'Sysmon Event ID 1', 'EDR file read events'],
        commands: {
            windows: ['Get-ChildItem -Path C:\\ -Recurse -Include "*.config","*.xml","*.ini" -ErrorAction SilentlyContinue | Select-String -Pattern "password|credential|secret" | Select-Object -First 10'],
            linux: ['grep -r "password\\|secret\\|api_key" /etc /home 2>/dev/null | head -20']
        },
        containment: ['Rotate exposed credentials', 'Enable secrets management', 'Remove plaintext passwords'],
        falsePositives: ['Configuration management', 'Development environments', 'Documentation']
    },

    // ===== MORE EXECUTION =====
    'T1204': {
        id: 'T1204',
        name: 'User Execution',
        tactic: 'Execution',
        description: 'Adversaries rely on users to execute malicious content',
        keywords: ['user execution', 'click', 'open', 'run', 'double-click', 'attachment'],
        logsToCheck: ['Sysmon Event ID 1', 'Email gateway logs', 'EDR process creation'],
        commands: {
            windows: ['Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=1} | Where-Object {$_.Message -match "Downloads|Temp|AppData"}'],
            linux: ['ausearch -c bash -ts today | head -50']
        },
        containment: ['Block executable extensions in email', 'User awareness training', 'Enable Mark of the Web'],
        falsePositives: ['Legitimate downloads', 'Software installations', 'Document attachments']
    },

    'T1569': {
        id: 'T1569',
        name: 'System Services',
        tactic: 'Execution',
        description: 'Adversaries abuse system services for code execution',
        keywords: ['service execution', 'sc start', 'systemctl start', 'service control'],
        logsToCheck: ['Windows Security Event 7045', 'Windows Security Event 4697', 'Sysmon logs'],
        commands: {
            windows: ['Get-WinEvent -FilterHashtable @{LogName="System";Id=7045} -MaxEvents 20'],
            linux: ['journalctl -u <service> --since "1 hour ago"']
        },
        containment: ['Stop malicious services', 'Remove from registry', 'Block service binaries'],
        falsePositives: ['IT operations', 'Software updates', 'Restart operations']
    },

    // ===== IMPACT =====
    'T1485': {
        id: 'T1485',
        name: 'Data Destruction',
        tactic: 'Impact',
        description: 'Adversaries destroy data to disrupt availability',
        keywords: ['delete', 'wipe', 'destroy', 'rm -rf', 'format', 'destruction'],
        logsToCheck: ['File deletion logs', 'Sysmon Event ID 23', 'Volume shadow copy logs'],
        commands: {
            windows: ['vssadmin list shadows', 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=23} -MaxEvents 50'],
            linux: ['ausearch -m DEL -ts today', 'df -h']
        },
        containment: ['Isolate immediately', 'Preserve backups', 'Stop destructive processes'],
        falsePositives: ['Disk cleanup', 'File rotation', 'Legitimate deletions']
    },

    'T1490': {
        id: 'T1490',
        name: 'Inhibit System Recovery',
        tactic: 'Impact',
        description: 'Adversaries disable recovery features',
        keywords: ['vssadmin delete', 'bcdedit', 'recovery', 'shadow copy', 'backup delete'],
        logsToCheck: ['Windows Security logs', 'Sysmon Event ID 1', 'Volume shadow copy logs'],
        commands: {
            windows: ['vssadmin list shadows', 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=1} | Where-Object {$_.Message -match "vssadmin|bcdedit|wbadmin"}'],
            linux: ['N/A - Windows specific']
        },
        containment: ['CRITICAL: Isolate immediately', 'Preserve remaining shadows', 'Assess backup integrity'],
        falsePositives: ['IT maintenance', 'Disk space cleanup', 'System rebuild']
    },

    'T1489': {
        id: 'T1489',
        name: 'Service Stop',
        tactic: 'Impact',
        description: 'Adversaries stop services to disrupt operations',
        keywords: ['service stop', 'stop-service', 'sc stop', 'kill', 'shutdown'],
        logsToCheck: ['Windows Security Event 7036', 'Sysmon logs', 'Service control logs'],
        commands: {
            windows: ['Get-WinEvent -FilterHashtable @{LogName="System";Id=7036} -MaxEvents 50 | Where-Object {$_.Message -match "stopped"}'],
            linux: ['journalctl -u <service> | grep -i "stop\\|kill"']
        },
        containment: ['Restart critical services', 'Investigate cause', 'Enable service protection'],
        falsePositives: ['Maintenance windows', 'Updates', 'Restarts']
    },

    // ===== MORE LATERAL MOVEMENT =====
    'T1550': {
        id: 'T1550',
        name: 'Use Alternate Authentication Material',
        tactic: 'Lateral Movement',
        description: 'Adversaries use alternate authentication like pass-the-hash',
        keywords: ['pass-the-hash', 'pass-the-ticket', 'pth', 'overpass', 'ntlm relay'],
        logsToCheck: ['Windows Security Event 4624 (Type 9)', 'NTLM audit logs', 'Kerberos logs'],
        commands: {
            windows: ['Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624} | Where-Object {$_.Properties[8].Value -eq 9}'],
            linux: ['N/A - Windows/AD specific']
        },
        containment: ['Enable Credential Guard', 'Disable NTLM where possible', 'Reset compromised hashes'],
        falsePositives: ['Legitimate delegation', 'Service accounts', 'SSO systems']
    },

    'T1021.002': {
        id: 'T1021.002',
        name: 'SMB/Windows Admin Shares',
        tactic: 'Lateral Movement',
        description: 'Adversaries use SMB shares for lateral movement',
        keywords: ['smb', 'admin share', 'c$', 'admin$', 'ipc$', 'net use'],
        logsToCheck: ['Windows Security Event 5140', 'SMB audit logs', 'Network traffic'],
        commands: {
            windows: ['Get-WinEvent -FilterHashtable @{LogName="Security";Id=5140} -MaxEvents 50', 'net share'],
            linux: ['smbclient -L //target 2>/dev/null']
        },
        containment: ['Disable admin shares if not needed', 'Segment networks', 'Monitor SMB traffic'],
        falsePositives: ['File sharing', 'IT management', 'Backup systems']
    },

    // ===== MORE C2 =====
    'T1572': {
        id: 'T1572',
        name: 'Protocol Tunneling',
        tactic: 'Command and Control',
        description: 'Adversaries tunnel C2 over other protocols',
        keywords: ['tunnel', 'dns tunnel', 'icmp tunnel', 'http tunnel', 'ssh tunnel'],
        logsToCheck: ['DNS query logs', 'Network flow data', 'Firewall logs'],
        commands: {
            windows: ['Get-DnsClientCache | Where-Object {$_.Entry.Length -gt 50}', 'netstat -ano | findstr ESTABLISHED'],
            linux: ['cat /var/log/named/queries.log | awk "{print length, $0}" | sort -rn | head -20']
        },
        containment: ['Block suspicious DNS', 'Enable DNS filtering', 'Monitor for anomalies'],
        falsePositives: ['VPN tunnels', 'SSH legitimate use', 'DNS-based services']
    },

    'T1573': {
        id: 'T1573',
        name: 'Encrypted Channel',
        tactic: 'Command and Control',
        description: 'Adversaries use encryption to hide C2 traffic',
        keywords: ['encrypted', 'ssl', 'tls', 'https', 'encrypted channel'],
        logsToCheck: ['SSL/TLS inspection logs', 'Proxy logs', 'Certificate logs'],
        commands: {
            windows: ['Get-NetTCPConnection | Where-Object {$_.RemotePort -eq 443 -and $_.State -eq "Established"}'],
            linux: ['ss -tunapl | grep ":443"']
        },
        containment: ['Block C2 domains', 'Enable SSL inspection', 'Monitor certificate anomalies'],
        falsePositives: ['Normal HTTPS traffic', 'Cloud services', 'CDNs']
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
