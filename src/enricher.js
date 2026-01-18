/**
 * Threat Intelligence Enricher
 * Integrates with VirusTotal (free tier) to enrich IOCs
 */

const https = require('https');

// Rate limiting for free tier (4 requests/min)
let lastRequestTime = 0;
const MIN_REQUEST_INTERVAL = 15000; // 15 seconds between requests

/**
 * Check if enrichment is available
 */
function isEnrichmentAvailable() {
    return !!(process.env.VIRUSTOTAL_API_KEY || process.env.VT_API_KEY);
}

/**
 * Get API key from environment
 */
function getApiKey(providedKey) {
    return providedKey || process.env.VIRUSTOTAL_API_KEY || process.env.VT_API_KEY;
}

/**
 * Rate-limited request wrapper
 */
async function rateLimitedRequest(fn) {
    const now = Date.now();
    const timeSinceLastRequest = now - lastRequestTime;

    if (timeSinceLastRequest < MIN_REQUEST_INTERVAL) {
        await new Promise(resolve => setTimeout(resolve, MIN_REQUEST_INTERVAL - timeSinceLastRequest));
    }

    lastRequestTime = Date.now();
    return fn();
}

/**
 * Check IP reputation on VirusTotal
 */
async function checkIP(ip, apiKey) {
    return rateLimitedRequest(() => {
        return new Promise((resolve, reject) => {
            const options = {
                hostname: 'www.virustotal.com',
                path: `/api/v3/ip_addresses/${ip}`,
                method: 'GET',
                headers: {
                    'x-apikey': apiKey
                }
            };

            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const result = JSON.parse(data);
                        if (result.error) {
                            resolve({ error: result.error.message, ip });
                        } else {
                            const stats = result.data?.attributes?.last_analysis_stats || {};
                            resolve({
                                ip,
                                malicious: stats.malicious || 0,
                                suspicious: stats.suspicious || 0,
                                harmless: stats.harmless || 0,
                                reputation: result.data?.attributes?.reputation || 0,
                                country: result.data?.attributes?.country || 'Unknown',
                                asOwner: result.data?.attributes?.as_owner || 'Unknown',
                                verdict: getVerdict(stats.malicious, stats.suspicious)
                            });
                        }
                    } catch (e) {
                        resolve({ error: 'Parse error', ip });
                    }
                });
            });

            req.on('error', (e) => resolve({ error: e.message, ip }));
            req.setTimeout(10000, () => {
                req.destroy();
                resolve({ error: 'Timeout', ip });
            });
            req.end();
        });
    });
}

/**
 * Check file hash on VirusTotal
 */
async function checkHash(hash, apiKey) {
    return rateLimitedRequest(() => {
        return new Promise((resolve, reject) => {
            const options = {
                hostname: 'www.virustotal.com',
                path: `/api/v3/files/${hash}`,
                method: 'GET',
                headers: {
                    'x-apikey': apiKey
                }
            };

            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const result = JSON.parse(data);
                        if (result.error) {
                            resolve({ error: result.error.message, hash });
                        } else {
                            const stats = result.data?.attributes?.last_analysis_stats || {};
                            resolve({
                                hash,
                                malicious: stats.malicious || 0,
                                suspicious: stats.suspicious || 0,
                                harmless: stats.harmless || 0,
                                fileName: result.data?.attributes?.meaningful_name || 'Unknown',
                                fileType: result.data?.attributes?.type_description || 'Unknown',
                                verdict: getVerdict(stats.malicious, stats.suspicious)
                            });
                        }
                    } catch (e) {
                        resolve({ error: 'Parse error', hash });
                    }
                });
            });

            req.on('error', (e) => resolve({ error: e.message, hash }));
            req.setTimeout(10000, () => {
                req.destroy();
                resolve({ error: 'Timeout', hash });
            });
            req.end();
        });
    });
}

/**
 * Check domain on VirusTotal
 */
async function checkDomain(domain, apiKey) {
    return rateLimitedRequest(() => {
        return new Promise((resolve, reject) => {
            const options = {
                hostname: 'www.virustotal.com',
                path: `/api/v3/domains/${domain}`,
                method: 'GET',
                headers: {
                    'x-apikey': apiKey
                }
            };

            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const result = JSON.parse(data);
                        if (result.error) {
                            resolve({ error: result.error.message, domain });
                        } else {
                            const stats = result.data?.attributes?.last_analysis_stats || {};
                            resolve({
                                domain,
                                malicious: stats.malicious || 0,
                                suspicious: stats.suspicious || 0,
                                harmless: stats.harmless || 0,
                                reputation: result.data?.attributes?.reputation || 0,
                                verdict: getVerdict(stats.malicious, stats.suspicious)
                            });
                        }
                    } catch (e) {
                        resolve({ error: 'Parse error', domain });
                    }
                });
            });

            req.on('error', (e) => resolve({ error: e.message, domain }));
            req.setTimeout(10000, () => {
                req.destroy();
                resolve({ error: 'Timeout', domain });
            });
            req.end();
        });
    });
}

/**
 * Get verdict based on detection counts
 */
function getVerdict(malicious, suspicious) {
    if (malicious >= 5) return '🔴 MALICIOUS';
    if (malicious >= 1 || suspicious >= 3) return '🟠 SUSPICIOUS';
    if (suspicious >= 1) return '🟡 LOW RISK';
    return '🟢 CLEAN';
}

/**
 * Enrich all indicators from parsed alert
 */
async function enrichIndicators(parsedAlert, apiKey) {
    const results = {
        ips: [],
        hashes: [],
        domains: [],
        enriched: false,
        error: null
    };

    if (!apiKey) {
        results.error = 'No API key provided. Set VIRUSTOTAL_API_KEY environment variable.';
        return results;
    }

    const indicators = parsedAlert.indicators || [];

    try {
        // Enrich IPs
        for (const ind of indicators.filter(i => i.type === 'ip')) {
            // Skip private IPs
            if (isPrivateIP(ind.value)) continue;
            const result = await checkIP(ind.value, apiKey);
            results.ips.push(result);
        }

        // Enrich hashes
        for (const ind of indicators.filter(i => i.type === 'hash')) {
            const result = await checkHash(ind.value, apiKey);
            results.hashes.push(result);
        }

        results.enriched = true;
    } catch (e) {
        results.error = e.message;
    }

    return results;
}

/**
 * Check if IP is private
 */
function isPrivateIP(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;

    const first = parseInt(parts[0]);
    const second = parseInt(parts[1]);

    if (first === 10) return true;
    if (first === 172 && second >= 16 && second <= 31) return true;
    if (first === 192 && second === 168) return true;
    if (first === 127) return true;

    return false;
}

/**
 * Format enrichment results for display
 */
function formatEnrichmentResults(results) {
    const lines = [];

    if (results.error) {
        lines.push(`⚠️ Enrichment Error: ${results.error}`);
        return lines;
    }

    if (results.ips.length > 0) {
        lines.push('📡 IP Reputation:');
        for (const ip of results.ips) {
            if (ip.error) {
                lines.push(`   ${ip.ip}: ❌ ${ip.error}`);
            } else {
                lines.push(`   ${ip.ip}: ${ip.verdict} (${ip.malicious} malicious, ${ip.suspicious} suspicious)`);
                lines.push(`      Country: ${ip.country} | ASN: ${ip.asOwner}`);
            }
        }
    }

    if (results.hashes.length > 0) {
        lines.push('🔍 Hash Reputation:');
        for (const hash of results.hashes) {
            if (hash.error) {
                lines.push(`   ${hash.hash.substring(0, 16)}...: ❌ ${hash.error}`);
            } else {
                lines.push(`   ${hash.hash.substring(0, 16)}...: ${hash.verdict} (${hash.malicious} detections)`);
                lines.push(`      File: ${hash.fileName} (${hash.fileType})`);
            }
        }
    }

    if (results.ips.length === 0 && results.hashes.length === 0) {
        lines.push('ℹ️ No enrichable indicators (external IPs or file hashes) found.');
    }

    return lines;
}

module.exports = {
    isEnrichmentAvailable,
    getApiKey,
    checkIP,
    checkHash,
    checkDomain,
    enrichIndicators,
    formatEnrichmentResults
};
