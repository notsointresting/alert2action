/**
 * alert2action - Main Module
 * Exports core functionality for programmatic use
 */

const { parseAlert } = require('./parser');
const { generateGuide } = require('./guide-generator');
const { formatOutput } = require('./formatter');
const { mapToMitre, getTechnique, getAllTechniques } = require('./mitre');

module.exports = {
    // Core functions
    parseAlert,
    generateGuide,
    formatOutput,

    // MITRE utilities
    mapToMitre,
    getTechnique,
    getAllTechniques,

    // Convenience function - all in one
    analyze: function (alertJson, options = {}) {
        const parsed = parseAlert(alertJson);
        const guide = generateGuide(parsed);
        return options.raw ? guide : formatOutput(guide, options);
    }
};
