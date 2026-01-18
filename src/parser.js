/**
 * Alert Parser Module
 * Normalizes different alert formats into a standard structure
 */

/**
 * Parse and normalize an alert from various formats
 * Supports: Generic, Splunk, Microsoft Sentinel, Elastic, CrowdStrike, etc.
 */
function parseAlert(rawAlert) {
    const normalized = {
        // Basic info
        id: null,
        title: null,
        description: null,
        severity: 'medium',
        timestamp: null,
        source: null,

        // Network indicators
        sourceIp: null,
        destIp: null,
        sourcePort: null,
        destPort: null,
        protocol: null,

        // Host indicators
        hostname: null,
        username: null,
        domain: null,

        // Process indicators
        processName: null,
        processPath: null,
        processCommandLine: null,
        parentProcess: null,
        processId: null,

        // File indicators
        filePath: null,
        fileHash: null,
        fileName: null,

        // Additional context
        category: null,
        action: null,
        status: null,
        eventType: null,
        rawData: rawAlert,

        // Extracted indicators for MITRE mapping
        indicators: [],
        keywords: []
    };

    // Try to extract from common field patterns
    normalized.id = extractField(rawAlert, ['id', 'alert_id', 'event_id', 'alertId', 'eventId', '_id', 'uuid']);
    normalized.title = extractField(rawAlert, ['title', 'name', 'alert_name', 'alertName', 'rule_name', 'ruleName', 'signature', 'event_type', 'eventType']);
    normalized.description = extractField(rawAlert, ['description', 'message', 'msg', 'details', 'summary', 'reason']);
    normalized.severity = normalizeSeverity(extractField(rawAlert, ['severity', 'priority', 'risk_level', 'riskLevel', 'threat_level', 'urgency', 'criticality']));
    normalized.timestamp = extractField(rawAlert, ['timestamp', 'time', 'created_at', 'createdAt', 'detection_time', '@timestamp', 'event_time', 'eventTime']);
    normalized.source = extractField(rawAlert, ['source', 'product', 'vendor', 'tool', 'detector', 'data_source', 'log_source']);

    // Network
    normalized.sourceIp = extractField(rawAlert, ['source_ip', 'sourceIp', 'src_ip', 'srcIp', 'src', 'attacker_ip', 'remote_ip', 'client_ip']);
    normalized.destIp = extractField(rawAlert, ['dest_ip', 'destIp', 'dst_ip', 'dstIp', 'dst', 'destination_ip', 'target_ip', 'server_ip', 'local_ip']);
    normalized.sourcePort = extractField(rawAlert, ['source_port', 'sourcePort', 'src_port', 'srcPort']);
    normalized.destPort = extractField(rawAlert, ['dest_port', 'destPort', 'dst_port', 'dstPort', 'port']);
    normalized.protocol = extractField(rawAlert, ['protocol', 'proto', 'network_protocol']);

    // Host
    normalized.hostname = extractField(rawAlert, ['hostname', 'host', 'computer_name', 'computerName', 'machine', 'device_name', 'endpoint']);
    normalized.username = extractField(rawAlert, ['username', 'user', 'user_name', 'userName', 'account', 'account_name', 'actor']);
    normalized.domain = extractField(rawAlert, ['domain', 'domain_name', 'ad_domain']);

    // Process
    normalized.processName = extractField(rawAlert, ['process_name', 'processName', 'process', 'image', 'exe', 'executable']);
    normalized.processPath = extractField(rawAlert, ['process_path', 'processPath', 'image_path', 'file_path', 'exe_path']);
    normalized.processCommandLine = extractField(rawAlert, ['command_line', 'commandLine', 'cmdline', 'cmd', 'process_command_line', 'command']);
    normalized.parentProcess = extractField(rawAlert, ['parent_process', 'parentProcess', 'parent_image', 'parent']);
    normalized.processId = extractField(rawAlert, ['process_id', 'processId', 'pid']);

    // File
    normalized.filePath = extractField(rawAlert, ['file_path', 'filePath', 'path', 'target_path']);
    normalized.fileHash = extractField(rawAlert, ['file_hash', 'fileHash', 'hash', 'md5', 'sha256', 'sha1']);
    normalized.fileName = extractField(rawAlert, ['file_name', 'fileName', 'filename', 'file']);

    // Context
    normalized.category = extractField(rawAlert, ['category', 'type', 'alert_type', 'alertType', 'tactic', 'technique']);
    normalized.action = extractField(rawAlert, ['action', 'event_action', 'result', 'outcome']);
    normalized.status = extractField(rawAlert, ['status', 'state', 'resolution']);
    normalized.eventType = extractField(rawAlert, ['event_type', 'eventType', 'type', 'activity_type']);

    // Extract keywords for MITRE mapping
    normalized.keywords = extractKeywords(normalized);
    normalized.indicators = extractIndicators(normalized);

    return normalized;
}

/**
 * Extract a field value from multiple possible field names
 */
function extractField(obj, fieldNames) {
    for (const field of fieldNames) {
        // Check top level
        if (obj[field] !== undefined && obj[field] !== null && obj[field] !== '') {
            return obj[field];
        }

        // Check nested common paths
        const nestedPaths = ['data', 'event', 'alert', 'result', 'fields', 'source'];
        for (const path of nestedPaths) {
            if (obj[path] && obj[path][field] !== undefined) {
                return obj[path][field];
            }
        }
    }
    return null;
}

/**
 * Normalize severity levels to standard values
 */
function normalizeSeverity(severity) {
    if (!severity) return 'medium';

    const severityStr = String(severity).toLowerCase();

    // Map various severity representations
    const severityMap = {
        'critical': 'critical',
        'crit': 'critical',
        '5': 'critical',
        'very high': 'critical',
        'emergency': 'critical',

        'high': 'high',
        '4': 'high',
        'major': 'high',
        'severe': 'high',

        'medium': 'medium',
        'med': 'medium',
        '3': 'medium',
        'moderate': 'medium',
        'warning': 'medium',

        'low': 'low',
        '2': 'low',
        'minor': 'low',

        'informational': 'informational',
        'info': 'informational',
        '1': 'informational',
        'notice': 'informational'
    };

    return severityMap[severityStr] || 'medium';
}

/**
 * Extract keywords from alert for MITRE technique mapping
 */
function extractKeywords(alert) {
    const keywords = new Set();

    // Extract from title and description
    const textFields = [alert.title, alert.description, alert.category, alert.eventType, alert.action];
    const keywordPatterns = [
        // Authentication
        'brute force', 'login', 'authentication', 'credential', 'password', 'logon', 'failed login',
        // Execution
        'powershell', 'cmd', 'script', 'execution', 'wscript', 'cscript', 'macro', 'command line',
        // Persistence
        'registry', 'scheduled task', 'service', 'startup', 'autorun', 'persistence',
        // Privilege Escalation
        'privilege', 'escalation', 'admin', 'root', 'sudo', 'elevation',
        // Defense Evasion
        'obfuscation', 'encoded', 'base64', 'hidden', 'masquerading', 'disable', 'bypass',
        // Credential Access
        'mimikatz', 'lsass', 'credential dump', 'hash', 'kerberos', 'ntlm',
        // Discovery
        'enumeration', 'reconnaissance', 'scan', 'discovery', 'query', 'whoami',
        // Lateral Movement
        'lateral', 'psexec', 'wmi', 'remote', 'smb', 'rdp', 'ssh',
        // Collection
        'data collection', 'keylogger', 'screenshot', 'clipboard',
        // Exfiltration
        'exfiltration', 'data transfer', 'upload', 'c2', 'command and control', 'beacon',
        // Impact
        'ransomware', 'encrypt', 'wipe', 'destruct', 'delete',
        // Malware
        'malware', 'virus', 'trojan', 'worm', 'backdoor', 'rat', 'rootkit',
        // Network
        'phishing', 'spam', 'suspicious', 'anomaly', 'unusual', 'dns', 'http', 'https',
        // File
        'suspicious file', 'malicious', 'dropper', 'payload'
    ];

    for (const text of textFields) {
        if (!text) continue;
        const lowerText = String(text).toLowerCase();

        for (const pattern of keywordPatterns) {
            if (lowerText.includes(pattern)) {
                keywords.add(pattern);
            }
        }
    }

    // Check command line for suspicious patterns
    if (alert.processCommandLine) {
        const cmd = alert.processCommandLine.toLowerCase();
        if (cmd.includes('-enc') || cmd.includes('-encoded')) keywords.add('encoded');
        if (cmd.includes('downloadstring') || cmd.includes('invoke-webrequest')) keywords.add('download');
        if (cmd.includes('bypass') || cmd.includes('-ep bypass')) keywords.add('bypass');
        if (cmd.includes('hidden') || cmd.includes('-w hidden')) keywords.add('hidden');
        if (cmd.includes('invoke-mimikatz')) keywords.add('mimikatz');
    }

    // Check process names
    if (alert.processName) {
        const proc = alert.processName.toLowerCase();
        const suspiciousProcs = ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'regsvr32', 'rundll32', 'certutil', 'bitsadmin'];
        for (const sp of suspiciousProcs) {
            if (proc.includes(sp)) keywords.add(sp);
        }
    }

    return Array.from(keywords);
}

/**
 * Extract IOC indicators from alert
 */
function extractIndicators(alert) {
    const indicators = [];

    if (alert.sourceIp) indicators.push({ type: 'ip', value: alert.sourceIp, context: 'source' });
    if (alert.destIp) indicators.push({ type: 'ip', value: alert.destIp, context: 'destination' });
    if (alert.fileHash) indicators.push({ type: 'hash', value: alert.fileHash, context: 'file' });
    if (alert.hostname) indicators.push({ type: 'hostname', value: alert.hostname, context: 'endpoint' });
    if (alert.username) indicators.push({ type: 'username', value: alert.username, context: 'actor' });
    if (alert.processName) indicators.push({ type: 'process', value: alert.processName, context: 'execution' });

    return indicators;
}

module.exports = { parseAlert };
