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

// ASCII Banner
const banner = `
${chalk.cyan('╔═══════════════════════════════════════════════════════════════╗')}
${chalk.cyan('║')}  ${chalk.bold.yellow('⚡ ALERT')}${chalk.bold.red('2')}${chalk.bold.green('ACTION')}  ${chalk.gray('- SOC Investigation Guide Generator')}   ${chalk.cyan('║')}
${chalk.cyan('╚═══════════════════════════════════════════════════════════════╝')}
`;

program
  .name('alert2action')
  .description('Transform SOC alerts into actionable investigation guides')
  .version('1.0.0')
  .argument('<alert-file>', 'Path to the alert JSON file')
  .option('-o, --output <format>', 'Output format: text, json, markdown', 'text')
  .option('-v, --verbose', 'Show detailed analysis')
  .option('--no-color', 'Disable colored output')
  .action((alertFile, options) => {
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
