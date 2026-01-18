# alert2action

> **SOC Alert → Investigation Guide CLI**

Transform security alerts into actionable investigation guides with MITRE ATT&CK mapping, investigation commands, and containment playbooks.

![alert2action demo](https://img.shields.io/badge/SOC-Automation-blue) ![Node.js](https://img.shields.io/badge/node-%3E%3D14.0.0-green) ![License](https://img.shields.io/badge/license-MIT-brightgreen)

## 🎯 What It Does

```bash
alert2action alert.json
```

**Input:** A security alert JSON file (from any SIEM, EDR, or security tool)

**Output:** A comprehensive investigation guide with:
- 📖 **What Happened** - Plain-English summary
- 🎯 **MITRE ATT&CK Mapping** - Matched techniques with confidence scores
- 📁 **Logs to Check** - Relevant log sources for investigation
- ⚡ **Commands to Run** - PowerShell & Linux commands for analysis
- 🛡️ **Containment Steps** - Prioritized response actions
- 🤔 **False Positive Hints** - Common benign causes to rule out

## 💡 Why This Is GOLD

- ✅ **Helps SOC freshers** - Learn investigation workflow
- ✅ **Saves senior analyst time** - Skip the basics, focus on threats
- ✅ **No strong open-source competitor** - Fills a real gap
- ✅ **Works with any SIEM** - Normalizes different alert formats
- ✅ **Offline capable** - No API keys needed

## 🚀 Quick Start

### Installation via npm (Recommended)

```bash
npm install -g alert2action
```

### Or Clone from GitHub

```bash
git clone https://github.com/yourusername/alert2action.git
cd alert2action
npm install
npm link  # Makes it globally available
```

### Run on an Example Alert

```bash
alert2action examples/brute-force-alert.json
# or
node bin/alert2action.js examples/brute-force-alert.json
```

## 📋 Usage

### Basic Usage

```bash
alert2action <alert-file.json>
```

### Options

```bash
alert2action alert.json            # Colored CLI output
alert2action alert.json -o json    # JSON format
alert2action alert.json -o markdown # Markdown for tickets
alert2action alert.json -v         # Verbose mode
alert2action --help                # Show help
```

### Output Formats

- **text** (default) - Colorized CLI output for terminal
- **json** - Raw JSON for integration with other tools
- **markdown** - Perfect for pasting into tickets/docs

## 📁 Supported Alert Formats

alert2action automatically normalizes alerts from various sources:

- **Generic JSON** - Any custom format
- **Splunk** - Splunk alert output
- **Microsoft Sentinel** - Azure Sentinel incidents
- **Elastic SIEM** - Elasticsearch alerts
- **CrowdStrike Falcon** - Falcon detection events
- **Microsoft Defender** - MDE/MDI alerts
- **Custom SIEM** - Maps common field names automatically

### Example Alert Structure

```json
{
  "title": "Multiple Failed Login Attempts",
  "severity": "high",
  "timestamp": "2024-01-18T10:30:00Z",
  "source_ip": "185.220.101.45",
  "hostname": "DC01.corp.local",
  "username": "administrator",
  "description": "Over 50 failed login attempts detected"
}
```

## 🎯 MITRE ATT&CK Coverage

Currently maps to **21 techniques** across all major tactics:

| Tactic | Techniques |
|--------|------------|
| Reconnaissance | T1595 (Active Scanning) |
| Initial Access | T1566 (Phishing), T1190 (Exploit), T1078 (Valid Accounts) |
| Execution | T1059 (Command/Script), T1059.001 (PowerShell) |
| Persistence | T1053 (Scheduled Task), T1547 (Boot Autostart) |
| Privilege Escalation | T1548.002 (UAC Bypass), T1134 (Token Manipulation) |
| Defense Evasion | T1055 (Process Injection), T1070 (Indicator Removal) |
| Credential Access | T1003 (Credential Dumping), T1110 (Brute Force) |
| Discovery | T1087 (Account Discovery) |
| Lateral Movement | T1021 (Remote Services) |
| Command & Control | T1071 (Application Protocol) |
| Exfiltration | T1041 (Exfil Over C2) |
| Impact | T1486 (Ransomware) |

## 📂 Example Alerts Included

Try these sample alerts in the `examples/` folder:

```bash
# Brute force attack
node bin/alert2action.js examples/brute-force-alert.json

# Malware execution (PowerShell download cradle)
node bin/alert2action.js examples/malware-alert.json

# Phishing email
node bin/alert2action.js examples/phishing-alert.json

# Credential dumping (LSASS access)
node bin/alert2action.js examples/credential-dump-alert.json

# Lateral movement (PsExec)
node bin/alert2action.js examples/lateral-movement-alert.json

# Privilege escalation (UAC Bypass)
node bin/alert2action.js examples/privesc-alert.json

# Multi-stage attack (Encoded PS + C2 + Persistence)
node bin/alert2action.js examples/soc-test-alert.json
```

## 🛠️ Programmatic Usage

Use alert2action as a library in your own scripts:

```javascript
const { analyze, parseAlert, generateGuide } = require('alert2action');

// Quick analysis
const alertJson = require('./my-alert.json');
console.log(analyze(alertJson));

// Or step by step
const parsed = parseAlert(alertJson);
const guide = generateGuide(parsed);
console.log(guide);
```

## 🗺️ Roadmap

### Coming Soon
- [ ] **More MITRE techniques** - Expand to 50+ techniques
- [ ] **Threat intelligence integration** - VirusTotal, AbuseIPDB, OTX lookups
- [ ] **Export to TheHive** - Create cases directly from alerts
- [ ] **Splunk-specific mapping** - Native Splunk field support
- [ ] **Interactive mode** - Guided Q&A investigation workflow
- [ ] **Custom playbook templates** - YAML-based playbook definitions

### Future Ideas
- [ ] Sigma rule suggestions
- [ ] YARA rule generation
- [ ] Timeline visualization
- [ ] Multi-alert correlation
- [ ] Webhook integrations (Slack, Teams, Discord)

## 🤝 Contributing

Contributions welcome! Areas that need help:

1. **More MITRE techniques** - Add coverage for more attack patterns
2. **SIEM-specific parsers** - Better support for specific products
3. **Investigation commands** - More forensic one-liners
4. **False positive knowledge** - Common FP patterns

## 📄 License

MIT License - Use freely in your SOC!

---

Built with ❤️ for SOC analysts everywhere
