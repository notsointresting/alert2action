/**
 * Output Formatter
 * Formats investigation guides for CLI display with colors
 */

const chalk = require('chalk');

/**
 * Format the investigation guide for output
 */
function formatOutput(guide, options = {}) {
    const format = options.output || 'text';

    switch (format) {
        case 'json':
            return JSON.stringify(guide, null, 2);
        case 'markdown':
            return formatMarkdown(guide);
        case 'thehive':
            return JSON.stringify(formatTheHive(guide, options), null, 2);
        case 'text':
        default:
            return formatText(guide, options);
    }
}

/**
 * Format as colored CLI text output
 */
function formatText(guide, options) {
    const lines = [];
    const divider = chalk.gray('─'.repeat(65));
    const sectionDivider = chalk.cyan('━'.repeat(65));

    // Header with severity coloring
    const severityColors = {
        critical: chalk.bgRed.white.bold,
        high: chalk.bgYellow.black.bold,
        medium: chalk.bgBlue.white.bold,
        low: chalk.bgGreen.white.bold,
        informational: chalk.bgGray.white
    };

    const severityColor = severityColors[guide.severity] || severityColors.medium;

    lines.push('');
    lines.push(severityColor(` ${guide.severity.toUpperCase()} SEVERITY `));
    lines.push(chalk.bold.white(`📋 ${guide.alertTitle}`));
    lines.push(chalk.gray(`   Timestamp: ${guide.timestamp}`));
    lines.push('');
    lines.push(sectionDivider);

    // Section 1: What Happened
    lines.push('');
    lines.push(chalk.bold.cyan('📖 WHAT HAPPENED'));
    lines.push(divider);
    for (const item of guide.whatHappened) {
        // Parse markdown-like formatting
        const formatted = item
            .replace(/\*\*(.*?)\*\*/g, (_, text) => chalk.bold(text))
            .replace(/`(.*?)`/g, (_, text) => chalk.yellow(text));
        lines.push(`   ${formatted}`);
    }
    lines.push('');

    // Section 2: MITRE ATT&CK Mapping
    lines.push(chalk.bold.magenta('🎯 MITRE ATT&CK MAPPING'));
    lines.push(divider);
    for (const mapping of guide.mitreMapping) {
        const confidenceIcon = mapping.confidence === 'high' ? '🔴' : mapping.confidence === 'medium' ? '🟠' : '🟡';
        lines.push(`   ${confidenceIcon} ${chalk.bold.yellow(mapping.id)} - ${chalk.bold(mapping.name)}`);
        lines.push(`      ${chalk.gray('Tactic:')} ${mapping.tactic}`);
        lines.push(`      ${chalk.gray('Confidence:')} ${mapping.confidence}`);
        if (mapping.description) {
            lines.push(`      ${chalk.gray(mapping.description)}`);
        }
        if (mapping.url) {
            lines.push(`      ${chalk.blue.underline(mapping.url)}`);
        }
        if (mapping.matchedKeywords && mapping.matchedKeywords.length > 0) {
            lines.push(`      ${chalk.gray('Matched:')} ${mapping.matchedKeywords.join(', ')}`);
        }
        lines.push('');
    }

    // Section 3: Logs to Check
    lines.push(chalk.bold.green('📁 LOGS TO CHECK'));
    lines.push(divider);
    for (const log of guide.logsToCheck) {
        lines.push(`   ${chalk.green('•')} ${log}`);
    }
    lines.push('');

    // Section 4: Commands to Run
    lines.push(chalk.bold.yellow('⚡ COMMANDS TO RUN'));
    lines.push(divider);

    if (guide.commands.windows.length > 0) {
        lines.push(`   ${chalk.bold.blue('Windows (PowerShell):')}`);
        for (const cmd of guide.commands.windows) {
            if (cmd.startsWith('#')) {
                lines.push(`   ${chalk.gray(cmd)}`);
            } else {
                lines.push(`   ${chalk.cyan('$')} ${chalk.white(cmd)}`);
            }
        }
        lines.push('');
    }

    if (guide.commands.linux.length > 0) {
        const linuxHeader = guide.commands.linuxNote
            ? `Linux/MacOS ${chalk.gray.italic(guide.commands.linuxNote)}`
            : 'Linux/MacOS:';
        lines.push(`   ${chalk.bold.magenta(linuxHeader)}`);
        for (const cmd of guide.commands.linux) {
            if (cmd.startsWith('#')) {
                lines.push(`   ${chalk.gray(cmd)}`);
            } else {
                lines.push(`   ${chalk.green('$')} ${chalk.white(cmd)}`);
            }
        }
        lines.push('');
    }

    // Section 5: Containment Steps
    lines.push(chalk.bold.red('🛡️ CONTAINMENT STEPS'));
    lines.push(divider);
    for (const phase of guide.containment) {
        lines.push(`   ${chalk.bold.underline(phase.phase)}`);
        for (let i = 0; i < phase.actions.length; i++) {
            const icon = phase.phase.includes('Immediate') ? '🚨' : phase.phase.includes('Short') ? '⚠️' : '📋';
            lines.push(`   ${icon} ${i + 1}. ${phase.actions[i]}`);
        }
        lines.push('');
    }

    // Section 6: False Positive Hints
    lines.push(chalk.bold.white('🤔 FALSE POSITIVE HINTS'));
    lines.push(divider);
    let inQuestions = false;
    for (const hint of guide.falsePositives) {
        if (hint.includes('---')) {
            inQuestions = true;
            lines.push(`   ${chalk.gray.italic(hint.replace(/---/g, ''))}`);
        } else if (inQuestions) {
            lines.push(`   ${chalk.cyan('?')} ${hint}`);
        } else {
            lines.push(`   ${chalk.yellow('•')} ${hint}`);
        }
    }
    lines.push('');

    // Indicators of Compromise
    if (guide.indicators && guide.indicators.length > 0) {
        lines.push(chalk.bold.red('🔍 INDICATORS OF COMPROMISE (IOCs)'));
        lines.push(divider);
        for (const ioc of guide.indicators) {
            lines.push(`   ${chalk.gray(`[${ioc.type.toUpperCase()}]`)} ${chalk.white(ioc.value)} ${chalk.gray(`(${ioc.context})`)}`);
        }
        lines.push('');
    }

    // Footer
    lines.push(sectionDivider);
    lines.push(chalk.gray.italic('   Generated by alert2action | Always verify findings before taking action'));
    lines.push('');

    return lines.join('\n');
}

/**
 * Format as Markdown (for documentation/ticketing)
 */
function formatMarkdown(guide) {
    const lines = [];

    lines.push(`# Investigation Guide: ${guide.alertTitle}`);
    lines.push('');
    lines.push(`**Severity:** ${guide.severity.toUpperCase()}`);
    lines.push(`**Timestamp:** ${guide.timestamp}`);
    lines.push('');

    // What Happened
    lines.push('## 📖 What Happened');
    lines.push('');
    for (const item of guide.whatHappened) {
        lines.push(`- ${item}`);
    }
    lines.push('');

    // MITRE Mapping
    lines.push('## 🎯 MITRE ATT&CK Mapping');
    lines.push('');
    lines.push('| Technique ID | Name | Tactic | Confidence |');
    lines.push('|-------------|------|--------|------------|');
    for (const mapping of guide.mitreMapping) {
        lines.push(`| [${mapping.id}](${mapping.url || '#'}) | ${mapping.name} | ${mapping.tactic} | ${mapping.confidence} |`);
    }
    lines.push('');

    // Logs to Check
    lines.push('## 📁 Logs to Check');
    lines.push('');
    for (const log of guide.logsToCheck) {
        lines.push(`- [ ] ${log}`);
    }
    lines.push('');

    // Commands
    lines.push('## ⚡ Commands to Run');
    lines.push('');
    if (guide.commands.windows.length > 0) {
        lines.push('### Windows (PowerShell)');
        lines.push('```powershell');
        lines.push(guide.commands.windows.join('\n'));
        lines.push('```');
        lines.push('');
    }
    if (guide.commands.linux.length > 0) {
        const linuxHeader = guide.commands.linuxNote
            ? `### Linux/MacOS ${guide.commands.linuxNote}`
            : '### Linux/MacOS';
        lines.push(linuxHeader);
        lines.push('```bash');
        lines.push(guide.commands.linux.join('\n'));
        lines.push('```');
        lines.push('');
    }

    // Containment
    lines.push('## 🛡️ Containment Steps');
    lines.push('');
    for (const phase of guide.containment) {
        lines.push(`### ${phase.phase}`);
        for (let i = 0; i < phase.actions.length; i++) {
            lines.push(`${i + 1}. ${phase.actions[i]}`);
        }
        lines.push('');
    }

    // False Positives
    lines.push('## 🤔 False Positive Hints');
    lines.push('');
    for (const hint of guide.falsePositives) {
        if (!hint.includes('---')) {
            lines.push(`- ${hint}`);
        }
    }
    lines.push('');

    // IOCs
    if (guide.indicators && guide.indicators.length > 0) {
        lines.push('## 🔍 Indicators of Compromise');
        lines.push('');
        lines.push('| Type | Value | Context |');
        lines.push('|------|-------|---------|');
        for (const ioc of guide.indicators) {
            lines.push(`| ${ioc.type} | \`${ioc.value}\` | ${ioc.context} |`);
        }
        lines.push('');
    }

    lines.push('---');
    lines.push('*Generated by alert2action*');

    return lines.join('\n');
}

/**
 * Format as TheHive case JSON (compatible with TheHive 4.x/5.x API)
 */
function formatTheHive(guide, options = {}) {
    const severityMap = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1,
        'informational': 1
    };

    const tlpMap = {
        'critical': 3, // RED
        'high': 2,     // AMBER
        'medium': 1,   // GREEN
        'low': 0,      // WHITE
        'informational': 0
    };

    // Build observables from indicators
    const observables = (guide.indicators || []).map(ind => {
        const dataTypeMap = {
            'ip': 'ip',
            'hash': 'hash',
            'hostname': 'hostname',
            'username': 'user-agent',
            'process': 'filename',
            'domain': 'domain'
        };

        return {
            dataType: dataTypeMap[ind.type] || 'other',
            data: ind.value,
            message: ind.context || '',
            tlp: tlpMap[guide.severity] || 1,
            ioc: true,
            sighted: true,
            tags: [ind.type, ind.context]
        };
    });

    // Build MITRE TTPs
    const ttps = (guide.mitreMapping || []).map(m => ({
        patternId: m.id,
        patternName: m.name,
        tactic: m.tactic
    }));

    // Build description
    const description = [
        '## What Happened',
        ...(guide.whatHappened || []),
        '',
        '## MITRE ATT&CK Mapping',
        ...(guide.mitreMapping || []).map(m => `- **${m.id}** - ${m.name} (${m.tactic}) [${m.confidence}]`),
        '',
        '## Logs to Check',
        ...(guide.logsToCheck || []).map(l => `- ${l}`),
        '',
        '## Recommended Commands',
        '### Windows',
        ...(guide.commands?.windows || []).slice(0, 5).map(c => `\`${c}\``),
        '',
        '### Linux',
        ...(guide.commands?.linux || []).slice(0, 5).map(c => `\`${c}\``),
        '',
        '## Containment Steps',
        ...(guide.containment || []).flatMap(p => p.actions.map((a, i) => `${i + 1}. ${a}`)),
        '',
        '---',
        '*Generated by alert2action*'
    ].join('\n');

    // TheHive Case format
    return {
        title: guide.alertTitle || 'Security Alert',
        description: description,
        severity: severityMap[guide.severity] || 2,
        tlp: tlpMap[guide.severity] || 1,
        pap: 2, // AMBER by default
        status: 'New',
        tags: [
            'alert2action',
            `severity:${guide.severity}`,
            ...(guide.mitreMapping || []).map(m => `mitre:${m.id}`)
        ],
        flag: guide.severity === 'critical',
        startDate: new Date(guide.timestamp).getTime(),
        customFields: {
            alert2actionVersion: { string: '1.1.0' },
            mitreCount: { integer: (guide.mitreMapping || []).length }
        },
        tasks: [
            {
                title: 'Initial Triage',
                status: 'Waiting',
                description: 'Review alert details and confirm true positive'
            },
            {
                title: 'Investigation',
                status: 'Waiting',
                description: 'Run recommended commands and check logs'
            },
            {
                title: 'Containment',
                status: 'Waiting',
                description: 'Execute containment steps if confirmed malicious'
            }
        ],
        observables: observables,
        ttp: ttps
    };
}

module.exports = { formatOutput };

