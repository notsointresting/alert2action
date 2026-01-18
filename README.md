# 🚨 alert2action

> **SOC Alert → Investigation Guide CLI**

Transform security alerts into actionable investigation guides with MITRE ATT&CK mapping, investigation commands, and containment playbooks.

[![npm version](https://img.shields.io/npm/v/alert2action.svg?style=flat-square)](https://www.npmjs.com/package/alert2action)
[![npm downloads](https://img.shields.io/npm/dm/alert2action.svg?style=flat-square)](https://www.npmjs.com/package/alert2action)
[![GitHub stars](https://img.shields.io/github/stars/notsointresting/alert2action?style=flat-square)](https://github.com/notsointresting/alert2action/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D14.0.0-green?style=flat-square)](https://nodejs.org)

![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-51%20Techniques-red?style=flat-square)
![VirusTotal](https://img.shields.io/badge/VirusTotal-Integration-green?style=flat-square)
![TheHive](https://img.shields.io/badge/TheHive-Export-orange?style=flat-square)
![Splunk](https://img.shields.io/badge/Splunk-CIM%20Ready-blue?style=flat-square)

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
git clone https://github.com/notsointresting/alert2action.git
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
alert2action alert.json              # Colored CLI output
alert2action alert.json -o json      # JSON format
alert2action alert.json -o markdown  # Markdown for tickets
alert2action alert.json -o thehive   # TheHive case export
alert2action alert.json --enrich     # VirusTotal enrichment
alert2action alert.json -v           # Verbose mode
alert2action --help                  # Show help
```

### Output Formats

- **text** (default) - Colorized CLI output for terminal
- **json** - Raw JSON for integration with other tools
- **markdown** - Perfect for pasting into tickets/docs
- **thehive** - TheHive case format (4.x/5.x compatible)

### Threat Intelligence Enrichment (NEW in v1.1.0)

Enrich IOCs with VirusTotal (free tier - 4 requests/min):

```bash
# Using environment variable
export VIRUSTOTAL_API_KEY=your_free_api_key
alert2action alert.json --enrich

# Using flag
alert2action alert.json --enrich --vt-key your_api_key
```

Get your free API key at https://www.virustotal.com/gui/join-us

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

Currently maps to **51 techniques** across all 14 tactics:

| Tactic | Techniques |
|--------|------------|
| Reconnaissance | T1595 (Active Scanning) |
| Initial Access | T1566, T1190, T1078, T1189, T1199 |
| Execution | T1059, T1059.001, T1204, T1569 |
| Persistence | T1053, T1547, T1543, T1136 |
| Privilege Escalation | T1548.002, T1134 |
| Defense Evasion | T1055, T1070, T1562, T1036, T1218 |
| Credential Access | T1003, T1110, T1558, T1552 |
| Discovery | T1087, T1082, T1083, T1069 |
| Collection | T1560, T1119, T1213 |
| Lateral Movement | T1021, T1550, T1021.002 |
| Command & Control | T1071, T1572, T1573 |
| Exfiltration | T1041 |
| Impact | T1486, T1485, T1490, T1489 |

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
