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

module.exports = { formatOutput };
