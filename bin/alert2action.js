#!/usr/bin/env node

/**
 * alert2action CLI
 * SOC Alert to Investigation Guide Generator
 * 
 * Usage: alert2action <alert.json>
 */

const { program } = require('commander');
const chalk = require('chalk');
const fs = require('fs');
const path = require('path');

const { parseAlert } = require('../src/parser');
const { generateGuide } = require('../src/guide-generator');
const { formatOutput } = require('../src/formatter');
const { enrichIndicators, formatEnrichmentResults, getApiKey } = require('../src/enricher');

// ASCII Banner
const banner = `
${chalk.cyan('╔═══════════════════════════════════════════════════════════════╗')}
${chalk.cyan('║')}  ${chalk.bold.yellow('⚡ ALERT')}${chalk.bold.red('2')}${chalk.bold.green('ACTION')}  ${chalk.gray('- SOC Investigation Guide Generator')}   ${chalk.cyan('║')}
${chalk.cyan('╚═══════════════════════════════════════════════════════════════╝')}
`;

program
  .name('alert2action')
  .description('Transform SOC alerts into actionable investigation guides')
  .version('1.1.0')
  .argument('<alert-file>', 'Path to the alert JSON file')
  .option('-o, --output <format>', 'Output format: text, json, markdown, thehive', 'text')
  .option('-v, --verbose', 'Show detailed analysis')
  .option('--no-color', 'Disable colored output')
  .option('--enrich', 'Enrich IOCs with VirusTotal (requires API key)')
  .option('--vt-key <key>', 'VirusTotal API key (or set VIRUSTOTAL_API_KEY env)')
  .action(async (alertFile, options) => {
    try {
      // Show banner
      if (options.color !== false) {
        console.log(banner);
      }

      // Validate file exists
      const filePath = path.resolve(alertFile);
      if (!fs.existsSync(filePath)) {
        console.error(chalk.red(`\n❌ Error: File not found: ${alertFile}`));
        process.exit(1);
      }

      // Read and parse alert
      const alertData = fs.readFileSync(filePath, 'utf8');
      let alert;
      try {
        alert = JSON.parse(alertData);
      } catch (e) {
        console.error(chalk.red(`\n❌ Error: Invalid JSON in ${alertFile}`));
        process.exit(1);
      }

      // Parse and normalize alert
      const parsedAlert = parseAlert(alert);

      // Generate investigation guide
      const guide = generateGuide(parsedAlert);

      // Enrich indicators if requested
      if (options.enrich) {
        const apiKey = getApiKey(options.vtKey);
        if (!apiKey) {
          console.log(chalk.yellow('\n⚠️ No VirusTotal API key provided.'));
          console.log(chalk.gray('  Set VIRUSTOTAL_API_KEY env or use --vt-key flag\n'));
        } else {
          console.log(chalk.cyan('\n🔍 Enriching indicators with VirusTotal...'));
          const enrichment = await enrichIndicators(parsedAlert, apiKey);
          const enrichmentLines = formatEnrichmentResults(enrichment);

          // Add enrichment to guide
          guide.enrichment = enrichment;
          guide.enrichmentDisplay = enrichmentLines;

          // Display enrichment results
          console.log(chalk.cyan('\n━━━ THREAT INTELLIGENCE ━━━'));
          enrichmentLines.forEach(line => console.log(line));
          console.log('');
        }
      }

      // Format and output
      const output = formatOutput(guide, options);
      console.log(output);

    } catch (error) {
      console.error(chalk.red(`\n❌ Error: ${error.message}`));
      if (options.verbose) {
        console.error(error.stack);
      }
      process.exit(1);
    }
  });

program.parse();
