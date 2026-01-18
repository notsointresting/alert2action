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

    // Try to extract from common field patterns (including Splunk CIM)
    normalized.id = extractField(rawAlert, ['id', 'alert_id', 'event_id', 'alertId', 'eventId', '_id', 'uuid', 'host_id', 'sid', 'search_id']);
    normalized.title = extractField(rawAlert, ['title', 'name', 'alert_name', 'alertName', 'rule_name', 'ruleName', 'signature', 'event_type', 'eventType', 'rule_name', 'summary', 'search_name', 'savedsearch_name']);
    normalized.description = extractField(rawAlert, ['description', 'message', 'msg', 'details', 'summary', 'reason', 'technique_details', 'search_description']);
    normalized.severity = normalizeSeverity(extractField(rawAlert, ['severity', 'event_severity', 'priority', 'risk_level', 'riskLevel', 'threat_level', 'urgency', 'criticality', 'risk_score', 'info_min_time']));
    normalized.timestamp = extractField(rawAlert, ['timestamp', 'time', 'created_at', 'createdAt', 'detection_time', '@timestamp', 'event_time', 'eventTime', 'ingested_time', '_time', 'trigger_time', 'index_time']);
    normalized.source = extractField(rawAlert, ['source', 'product', 'vendor', 'tool', 'detector', 'data_source', 'log_source', 'sourcetype', 'eventtype', 'index']);

    // Network (Splunk Network CIM)
    normalized.sourceIp = extractField(rawAlert, ['source_ip', 'sourceIp', 'src_ip', 'srcIp', 'src', 'attacker_ip', 'remote_ip', 'client_ip', 'ip_address', 'src_ip_addr', 'orig_src']);
    normalized.destIp = extractField(rawAlert, ['dest_ip', 'destIp', 'dst_ip', 'dstIp', 'dst', 'destination_ip', 'target_ip', 'server_ip', 'local_ip', 'dest', 'dest_ip_addr', 'orig_dest']);
    normalized.sourcePort = extractField(rawAlert, ['source_port', 'sourcePort', 'src_port', 'srcPort', 'orig_src_port']);
    normalized.destPort = extractField(rawAlert, ['dest_port', 'destPort', 'dst_port', 'dstPort', 'port', 'dest_port', 'orig_dest_port']);
    normalized.protocol = extractField(rawAlert, ['protocol', 'proto', 'network_protocol', 'transport', 'app_protocol']);

    // Host (Splunk Endpoint CIM)
    normalized.hostname = extractField(rawAlert, ['hostname', 'host', 'computer_name', 'computerName', 'machine', 'device_name', 'endpoint', 'dvc', 'dvc_host', 'dest_host', 'src_host']);
    normalized.username = extractField(rawAlert, ['username', 'user', 'user_name', 'userName', 'account', 'account_name', 'actor', 'original_user', 'escalated_user', 'src_user', 'dest_user', 'owner']);
    normalized.domain = extractField(rawAlert, ['domain', 'domain_name', 'ad_domain', 'nt_domain', 'user_domain']);

    // Process (Splunk Endpoint CIM)
    normalized.processName = extractField(rawAlert, ['process_name', 'processName', 'process', 'image', 'exe', 'executable', 'suspicious_binary', 'process_exec', 'process_file_name']);
    normalized.processPath = extractField(rawAlert, ['process_path', 'processPath', 'image_path', 'file_path', 'exe_path', 'service_binary', 'process_file_path']);
    normalized.processCommandLine = extractField(rawAlert, ['command_line', 'commandLine', 'cmdline', 'cmd', 'process_command_line', 'command', 'process_cmd']);
    normalized.parentProcess = extractField(rawAlert, ['parent_process', 'parentProcess', 'parent_image', 'parent', 'parent_process_name', 'parent_cmd', 'parent_file_path']);
    normalized.processId = extractField(rawAlert, ['process_id', 'processId', 'pid', 'process_pid']);

    // File (Splunk Change Analysis CIM)
    normalized.filePath = extractField(rawAlert, ['file_path', 'filePath', 'path', 'target_path', 'service_binary', 'object_path', 'dest_file_path']);
    normalized.fileHash = extractField(rawAlert, ['file_hash', 'fileHash', 'hash', 'md5', 'sha256', 'sha1', 'file_md5', 'file_sha256', 'file_sha1']);
    normalized.fileName = extractField(rawAlert, ['file_name', 'fileName', 'filename', 'file', 'suspicious_binary', 'object_name', 'dest_file_name']);

    // Context
    normalized.category = extractField(rawAlert, ['category', 'type', 'alert_type', 'alertType', 'tactic', 'technique', 'method', 'vector', 'rule_category', 'analytic_type']);
    normalized.action = extractField(rawAlert, ['action', 'event_action', 'result', 'outcome', 'success', 'vendor_action', 'dvc_action']);
    normalized.status = extractField(rawAlert, ['status', 'state', 'resolution', 'event_status', 'isolation_status', 'alert_status', 'notable_status']);
    normalized.eventType = extractField(rawAlert, ['event_type', 'eventType', 'type', 'activity_type', 'signature_type', 'event_category']);

    // Extract keywords for MITRE mapping
    normalized.keywords = extractKeywords(normalized);
    normalized.indicators = extractIndicators(normalized);

    return normalized;
}

/**
 * Extract a field value from multiple possible field names
 * Searches top-level, common nested paths, and deeply nested objects
 */
function extractField(obj, fieldNames) {
    for (const field of fieldNames) {
        // Check top level
        if (obj[field] !== undefined && obj[field] !== null && obj[field] !== '') {
            // If it's an object (like host: {hostname: ...}), skip it
            if (typeof obj[field] !== 'object') {
                return obj[field];
            }
        }

        // Check nested common paths (expanded for more formats)
        const nestedPaths = [
            'data', 'event', 'alert', 'result', 'fields', 'source',
            'host', 'user', 'process', 'file', 'network', 'destination',
            'file_activity', 'persistence', 'detection', 'exploitation',
            'privilege_change', 'ioc', 'analyst_notes', 'hashes'
        ];
        for (const path of nestedPaths) {
            if (obj[path] && typeof obj[path] === 'object') {
                if (obj[path][field] !== undefined && obj[path][field] !== null && obj[path][field] !== '') {
                    if (typeof obj[path][field] !== 'object') {
                        return obj[path][field];
                    }
                }
                // Check one level deeper (e.g., host.os.name)
                for (const subPath of Object.keys(obj[path])) {
                    if (typeof obj[path][subPath] === 'object' && obj[path][subPath]) {
                        if (obj[path][subPath][field] !== undefined) {
                            return obj[path][subPath][field];
                        }
                    }
                }
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
        // Authentication & Brute Force
        'brute force', 'login', 'authentication', 'credential', 'password', 'logon', 'failed login',
        'password spray', 'credential stuffing', 'account lockout',

        // Execution
        'powershell', 'cmd', 'script', 'execution', 'wscript', 'cscript', 'macro', 'command line',
        'living off the land', 'lolbin', 'mshta', 'regsvr32', 'rundll32', 'certutil',

        // Persistence
        'registry', 'scheduled task', 'service', 'startup', 'autorun', 'persistence',
        'cron', 'boot', 'wmi subscription', 'service creation',

        // Privilege Escalation
        'privilege', 'escalation', 'admin', 'root', 'sudo', 'elevation', 'uac bypass',
        'token manipulation', 'impersonation', 'system', 'kernel exploit', 'setuid',

        // Defense Evasion
        'obfuscation', 'encoded', 'base64', 'hidden', 'masquerading', 'disable', 'bypass',
        'process injection', 'dll injection', 'hollowing', 'av evasion', 'edr tampering',
        'log clearing', 'timestomp', 'signed binary', 'code signing',

        // Credential Access
        'mimikatz', 'lsass', 'credential dump', 'hash', 'kerberos', 'ntlm', 'keylogger',
        'password store', 'browser credential', 'sam', 'ntds', 'dcSync',

        // Discovery
        'enumeration', 'reconnaissance', 'scan', 'discovery', 'query', 'whoami',
        'network scan', 'port scan', 'service enumeration', 'account discovery',
        'domain enumeration', 'process discovery', 'system information',

        // Lateral Movement
        'lateral', 'psexec', 'wmi', 'remote', 'smb', 'rdp', 'ssh', 'winrm',
        'pass the hash', 'pass the ticket', 'remote service', 'dcom',

        // Collection
        'data collection', 'keylogger', 'screenshot', 'clipboard', 'archive', 'staging',

        // Command and Control
        'c2', 'command and control', 'beacon', 'callback', 'beaconing',
        'dns tunneling', 'encrypted channel', 'proxy', 'covert channel',

        // Exfiltration
        'exfiltration', 'data transfer', 'upload', 'data theft', 'large transfer',
        'cloud exfil', 'ftp', 'dns exfil',

        // Impact
        'ransomware', 'encrypt', 'wipe', 'destruct', 'delete', 'defacement',
        'resource hijacking', 'cryptomining', 'dos', 'denial of service',

        // Malware
        'malware', 'virus', 'trojan', 'worm', 'backdoor', 'rat', 'rootkit',
        'dropper', 'loader', 'implant',

        // Network & Initial Access  
        'phishing', 'spam', 'suspicious', 'anomaly', 'unusual', 'dns', 'http', 'https',
        'drive-by', 'exploit', 'vulnerability', 'cve', 'web shell',

        // File & Payload
        'suspicious file', 'malicious', 'dropper', 'payload', 'attachment',

        // Identity & Compliance
        'impossible travel', 'privileged login', 'service account', 'oauth',
        'policy violation', 'audit', 'compliance', 'configuration drift',

        // Threat Intel
        'ioc', 'indicator', 'threat intel', 'behavior anomaly', 'threat hunt'
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
