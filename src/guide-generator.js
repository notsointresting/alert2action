/**
 * Investigation Guide Generator
 * Builds comprehensive investigation guides from parsed alerts
 */

const { mapToMitre } = require('./mitre');

/**
 * Generate a complete investigation guide from a parsed alert
 */
function generateGuide(parsedAlert) {
    const mitreMatches = mapToMitre(parsedAlert);

    const guide = {
        // Section 1: What Happened
        whatHappened: generateWhatHappened(parsedAlert),

        // Section 2: MITRE ATT&CK Mapping
        mitreMapping: generateMitreSection(mitreMatches),

        // Section 3: Logs to Check
        logsToCheck: generateLogsToCheck(parsedAlert, mitreMatches),

        // Section 4: Commands to Run
        commands: generateCommands(parsedAlert, mitreMatches),

        // Section 5: Containment Steps
        containment: generateContainment(parsedAlert, mitreMatches),

        // Section 6: False Positive Hints
        falsePositives: generateFalsePositives(parsedAlert, mitreMatches),

        // Metadata
        severity: parsedAlert.severity,
        alertTitle: generateSmartTitle(parsedAlert, mitreMatches),
        timestamp: parsedAlert.timestamp || new Date().toISOString(),
        indicators: parsedAlert.indicators
    };

    return guide;
}

/**
 * Generate a smart, descriptive alert title based on context
 */
function generateSmartTitle(alert, mitreMatches) {
    // If we have a good title already (not just a process name), use it
    if (alert.title && !alert.title.endsWith('.exe') && alert.title.length > 20) {
        return alert.title;
    }

    const parts = [];

    // Check for encoded/obfuscated commands
    const cmdLine = (alert.processCommandLine || '').toLowerCase();
    if (cmdLine.includes('-enc') || cmdLine.includes('base64') || cmdLine.includes('-encoded')) {
        parts.push('Encoded');
    }

    // Check for suspicious processes
    const procName = (alert.processName || '').toLowerCase();
    if (procName.includes('powershell')) {
        parts.push('PowerShell Execution');
    } else if (procName.includes('cmd')) {
        parts.push('Command Shell Execution');
    } else if (procName.includes('wscript') || procName.includes('cscript')) {
        parts.push('Script Execution');
    } else if (alert.processName) {
        parts.push(`${alert.processName} Execution`);
    }

    // Check for network activity
    if (alert.destIp && isExternalIP(alert.destIp)) {
        parts.push('with External Network Connection');
    }

    // Check for privilege escalation keywords
    const allText = [alert.title, alert.description, alert.category, alert.eventType].join(' ').toLowerCase();
    if (allText.includes('privilege') || allText.includes('escalation') || allText.includes('system')) {
        if (!parts.some(p => p.includes('Privilege'))) {
            parts.unshift('Privilege Escalation:');
        }
    }

    // Check for credential access
    if (allText.includes('lsass') || allText.includes('credential') || allText.includes('dump')) {
        if (!parts.some(p => p.includes('Credential'))) {
            parts.unshift('Credential Access:');
        }
    }

    // Add top MITRE tactic if available
    if (mitreMatches.length > 0 && parts.length < 3) {
        const topTactic = mitreMatches[0].technique.tactic;
        if (!parts.some(p => p.toLowerCase().includes(topTactic.toLowerCase()))) {
            parts.push(`(${topTactic})`);
        }
    }

    // Fallback
    if (parts.length === 0) {
        return alert.title || alert.eventType || 'Security Alert';
    }

    return parts.join(' ');
}

/**
 * Generate "What Happened" section - plain English summary
 */
function generateWhatHappened(alert) {
    const parts = [];

    // Build event description
    if (alert.title) {
        parts.push(`**Alert:** ${alert.title}`);
    }

    if (alert.description) {
        parts.push(`**Details:** ${alert.description}`);
    }

    // Build context
    const context = [];

    if (alert.timestamp) {
        context.push(`Detected at ${new Date(alert.timestamp).toLocaleString()}`);
    }

    if (alert.hostname) {
        context.push(`on host **${alert.hostname}**`);
    }

    if (alert.username) {
        context.push(`involving user **${alert.username}**`);
    }

    if (context.length > 0) {
        parts.push(context.join(' '));
    }

    // Network context
    if (alert.sourceIp || alert.destIp) {
        const netContext = [];
        if (alert.sourceIp) {
            const isInternal = !isExternalIP(alert.sourceIp);
            netContext.push(`Source IP: ${alert.sourceIp}${isInternal ? ' (internal - possible lateral movement or local execution)' : ''}`);
        }
        if (alert.destIp) {
            const isExternal = isExternalIP(alert.destIp);
            netContext.push(`Destination IP: ${alert.destIp}${isExternal ? ' (external - potential C2 or exfiltration)' : ''}`);
        }
        if (alert.protocol) netContext.push(`Protocol: ${alert.protocol}`);
        parts.push(`**Network:** ${netContext.join(' | ')}`);
    }

    // Process context
    if (alert.processName || alert.processCommandLine) {
        const procParts = [];
        if (alert.processName) procParts.push(`Process: ${alert.processName}`);
        if (alert.parentProcess) procParts.push(`Parent: ${alert.parentProcess}`);
        if (alert.processCommandLine) {
            // Truncate long command lines
            const cmd = alert.processCommandLine.length > 150
                ? alert.processCommandLine.substring(0, 150) + '...'
                : alert.processCommandLine;
            procParts.push(`Command: \`${cmd}\``);
        }
        parts.push(`**Process:** ${procParts.join(' | ')}`);
    }

    // File context
    if (alert.filePath || alert.fileHash) {
        const fileParts = [];
        if (alert.fileName || alert.filePath) fileParts.push(`File: ${alert.fileName || alert.filePath}`);
        if (alert.fileHash) fileParts.push(`Hash: ${alert.fileHash}`);
        parts.push(`**File:** ${fileParts.join(' | ')}`);
    }

    // Severity assessment
    const severityDesc = {
        'critical': '🔴 **CRITICAL** - Immediate action required!',
        'high': '🟠 **HIGH** - Urgent investigation needed',
        'medium': '🟡 **MEDIUM** - Investigate promptly',
        'low': '🟢 **LOW** - Review when possible',
        'informational': 'ℹ️ **INFO** - For awareness only'
    };

    parts.push(severityDesc[alert.severity] || severityDesc['medium']);

    return parts;
}

/**
 * Generate MITRE ATT&CK mapping section
 */
function generateMitreSection(mitreMatches) {
    if (mitreMatches.length === 0) {
        return [{
            id: 'Unknown',
            name: 'No MITRE Technique Identified',
            tactic: 'N/A',
            confidence: 'low',
            description: 'Unable to map this alert to a specific MITRE ATT&CK technique. Manual analysis recommended.'
        }];
    }

    return mitreMatches.map(match => ({
        id: match.technique.id,
        name: match.technique.name,
        tactic: match.technique.tactic,
        confidence: match.confidence,
        description: match.technique.description,
        matchedKeywords: match.matchedKeywords,
        url: `https://attack.mitre.org/techniques/${match.technique.id.replace('.', '/')}/`
    }));
}

/**
 * Generate logs to check section
 */
function generateLogsToCheck(alert, mitreMatches) {
    const logs = new Set();

    // Add technique-specific logs
    for (const match of mitreMatches) {
        if (match.technique.logsToCheck) {
            match.technique.logsToCheck.forEach(log => logs.add(log));
        }
    }

    // Add context-based logs
    if (alert.hostname) {
        logs.add('Endpoint security logs (EDR/AV)');
    }

    if (alert.sourceIp || alert.destIp) {
        logs.add('Firewall connection logs');
        logs.add('Network flow data (NetFlow/IPFIX)');
    }

    if (alert.username) {
        logs.add('Active Directory/LDAP logs');
        logs.add('Identity provider logs (Azure AD, Okta, etc.)');
    }

    if (alert.processName || alert.processCommandLine) {
        logs.add('Process creation logs (Sysmon Event ID 1, Security 4688)');
    }

    // Always recommend
    logs.add('SIEM correlation rules for related events');

    return Array.from(logs);
}

/**
 * Generate investigation commands
 */
function generateCommands(alert, mitreMatches) {
    // Detect if this is a Windows-specific alert
    const isWindowsAlert = detectWindowsContext(alert);

    const commands = {
        windows: [],
        linux: [],
        linuxNote: isWindowsAlert ? '(Cross-platform reference - use if environment includes Linux/Mac)' : null
    };

    // Add technique-specific commands
    for (const match of mitreMatches) {
        if (match.technique.commands) {
            if (match.technique.commands.windows) {
                commands.windows.push(...match.technique.commands.windows);
            }
            if (match.technique.commands.linux) {
                commands.linux.push(...match.technique.commands.linux);
            }
        }
    }

    // Add context-specific commands
    if (alert.sourceIp) {
        commands.windows.push(`# Check connections from source IP ${alert.sourceIp}`);
        commands.windows.push(`Get-NetTCPConnection | Where-Object {$_.RemoteAddress -eq "${alert.sourceIp}"}`);
        commands.linux.push(`# Check connections from source IP ${alert.sourceIp}`);
        commands.linux.push(`netstat -an | grep "${alert.sourceIp}"`);
    }

    if (alert.username) {
        commands.windows.push(`# Get recent activity for user ${alert.username}`);
        commands.windows.push(`Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624,4625,4648} | Where-Object {$_.Message -match "${alert.username}"} | Select-Object -First 20`);
        commands.linux.push(`# Get recent activity for user ${alert.username}`);
        commands.linux.push(`grep "${alert.username}" /var/log/auth.log | tail -50`);
    }

    if (alert.hostname) {
        commands.windows.push(`# Quick system health check on ${alert.hostname}`);
        commands.windows.push(`Get-Process | Sort-Object CPU -Descending | Select-Object -First 10`);
        commands.windows.push(`Get-Service | Where-Object {$_.Status -eq "Running" -and $_.StartType -eq "Automatic"}`);
    }

    if (alert.processName) {
        commands.windows.push(`# Find all instances of suspicious process`);
        commands.windows.push(`Get-Process -Name "${alert.processName.replace('.exe', '')}" -ErrorAction SilentlyContinue | Select-Object Id,Name,Path,StartTime`);
        commands.linux.push(`# Find all instances of suspicious process`);
        commands.linux.push(`ps aux | grep -i "${alert.processName}"`);
    }

    if (alert.fileHash) {
        commands.windows.push(`# Search for file by hash (requires PowerShell 4.0+)`);
        commands.windows.push(`Get-ChildItem -Path C:\\ -Recurse -File -ErrorAction SilentlyContinue | Get-FileHash | Where-Object {$_.Hash -eq "${alert.fileHash}"}`);
        commands.linux.push(`# Search for file by hash`);
        commands.linux.push(`find / -type f -exec sha256sum {} \\; 2>/dev/null | grep "${alert.fileHash}"`);
    }

    // Deduplicate
    commands.windows = [...new Set(commands.windows)];
    commands.linux = [...new Set(commands.linux)];

    return commands;
}

/**
 * Detect if alert is Windows-specific based on context
 */
function detectWindowsContext(alert) {
    const windowsIndicators = [
        // Process paths
        alert.processPath?.includes('C:\\'),
        alert.processPath?.includes('Windows'),
        // Process names
        alert.processName?.endsWith('.exe'),
        alert.processName?.toLowerCase().includes('powershell'),
        alert.processName?.toLowerCase().includes('schtasks'),
        alert.processName?.toLowerCase().includes('cmd.exe'),
        // Command line
        alert.processCommandLine?.includes('C:\\'),
        alert.processCommandLine?.includes('powershell'),
        // Hostname patterns
        alert.hostname?.includes('.local'),
        alert.hostname?.match(/^[A-Z]+-?[A-Z0-9]+$/i),  // WORKSTATION-01 pattern
        // Source indicators
        alert.source?.toLowerCase().includes('defender'),
        alert.source?.toLowerCase().includes('windows'),
        alert.source?.toLowerCase().includes('sysmon')
    ];

    return windowsIndicators.filter(Boolean).length >= 2;
}

/**
 * Generate containment steps
 */
function generateContainment(alert, mitreMatches) {
    const steps = [];
    const priority = {
        immediate: [],
        shortTerm: [],
        longTerm: []
    };

    // Severity-based immediate actions
    if (alert.severity === 'critical') {
        priority.immediate.push('🚨 CRITICAL: Escalate to incident commander immediately');
        priority.immediate.push('Consider isolating affected endpoint from network');
    }

    // Add technique-specific containment
    for (const match of mitreMatches) {
        if (match.technique.containment) {
            match.technique.containment.forEach((step, idx) => {
                if (idx === 0) {
                    priority.immediate.push(step);
                } else if (idx < 3) {
                    priority.shortTerm.push(step);
                } else {
                    priority.longTerm.push(step);
                }
            });
        }
    }

    // Context-based containment
    if (alert.sourceIp && isExternalIP(alert.sourceIp)) {
        priority.immediate.push(`Block source IP ${alert.sourceIp} at perimeter firewall`);
    }

    if (alert.username) {
        priority.shortTerm.push(`Review account ${alert.username} for compromise indicators`);
        priority.shortTerm.push(`Consider temporary account lockout if suspicious`);
    }

    if (alert.hostname) {
        priority.shortTerm.push(`Collect forensic image of ${alert.hostname} if needed`);
        priority.shortTerm.push('Preserve volatile data (memory, network connections)');
    }

    // Deduplicate 
    priority.immediate = [...new Set(priority.immediate)];
    priority.shortTerm = [...new Set(priority.shortTerm)];
    priority.longTerm = [...new Set(priority.longTerm)];

    // Combine with headers
    if (priority.immediate.length > 0) {
        steps.push({ phase: 'Immediate (0-30 min)', actions: priority.immediate.slice(0, 5) });
    }
    if (priority.shortTerm.length > 0) {
        steps.push({ phase: 'Short-term (1-4 hours)', actions: priority.shortTerm.slice(0, 5) });
    }
    if (priority.longTerm.length > 0) {
        steps.push({ phase: 'Long-term (Post-incident)', actions: priority.longTerm.slice(0, 3) });
    }

    return steps;
}

/**
 * Generate false positive hints
 */
function generateFalsePositives(alert, mitreMatches) {
    const hints = [];

    // Add technique-specific false positives
    for (const match of mitreMatches) {
        if (match.technique.falsePositives) {
            hints.push(...match.technique.falsePositives);
        }
    }

    // Add general investigation questions
    hints.push('--- Investigation Questions ---');

    if (alert.username) {
        hints.push(`Is ${alert.username} a legitimate admin or service account?`);
        hints.push('Was this activity during normal working hours for this user?');
    }

    if (alert.hostname) {
        hints.push(`Is ${alert.hostname} a development/test machine where this behavior is expected?`);
        hints.push('Is there scheduled maintenance or patching occurring?');
    }

    if (alert.processName) {
        hints.push(`Is ${alert.processName} part of approved software inventory?`);
        hints.push('Is this a known IT management or security tool?');
    }

    if (alert.sourceIp) {
        hints.push('Is the source IP from a known corporate or VPN range?');
        hints.push('Is this a known penetration testing or vulnerability scanning source?');
    }

    return [...new Set(hints)];
}

/**
 * Simple check if IP is likely external (not RFC1918)
 */
function isExternalIP(ip) {
    if (!ip) return false;

    // Common internal ranges
    const internalPatterns = [
        /^10\./,
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
        /^192\.168\./,
        /^127\./,
        /^169\.254\./,
        /^::1$/,
        /^fc00:/,
        /^fe80:/
    ];

    return !internalPatterns.some(pattern => pattern.test(ip));
}

module.exports = { generateGuide };
