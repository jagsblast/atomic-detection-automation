const fs = require('fs');
const csv = require('csv-parser');
const { Client } = require('@elastic/elasticsearch');
const winrm = require('nodejs-winrm');

// ElasticSearch credentials
const ELK_USER = '';
const ELK_PASSWORD = '';

const client = new Client({
    node: 'https://elastic.spooledup.co.uk/',
    auth: {
        username: ELK_USER,
        password: ELK_PASSWORD
    }
});

// Function to search ELK for alerts
async function searchElkForHost(hostName, startTime, endTime) {
    try {
        const response = await client.search({
            index: '.alerts-security.alerts-default',
            body: {
                query: {
                    bool: {
                        must: [
                            { match: { 'host.name': hostName } },
                            { range: { '@timestamp': { gte: startTime, lte: endTime, format: 'strict_date_optional_time' } } }
                        ]
                    }
                }
            },
            size: 1000
        });

        return response;
    } catch (error) {
        console.error(`Error searching ELK for host: ${error}`);
        throw error;
    }
}

// Delay function
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Function to run Atomic Red Team test
async function runAtomicTest(params, techniqueId, testNumber) {
    try {
        const command = `powershell -Command "Import-Module 'C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1' -Force; Invoke-AtomicTest '${techniqueId}' -TestNumbers ${testNumber}"`;
        params['command'] = command;
        params['commandId'] = await winrm.command.doExecuteCommand(params);
        const output = await winrm.command.doReceiveOutput(params);
        console.log(`Atomic Test Output:\n${output}`);
        return output;
    } catch (error) {
        console.error(`Error running Atomic Test: ${error}`);
        throw error;
    }
}

// Log test results to a file
async function writeResultsToFile(results) {
    try {
        let existingResults = {};
        const filePath = './test_results.json';

        if (fs.existsSync(filePath)) {
            const data = fs.readFileSync(filePath, 'utf8');
            try {
                existingResults = JSON.parse(data);
            } catch (err) {
                console.error('Error parsing existing JSON data. Initializing with an empty object.', err);
                existingResults = {};
            }
        }

        const updatedResults = { ...existingResults, ...results };

        fs.writeFileSync(filePath, JSON.stringify(updatedResults, null, 2));
    } catch (error) {
        console.error('Error writing results to file:', error);
    }
}

// Function to group alerts and techniques in the desired format
function groupAlertsAndTechniques(elkResults) {
    const alertIds = [];
    const techniques = [];

    elkResults.hits.hits.forEach(hit => {
        const alertId = hit._id;
        const threat = hit._source.threat;

        // Add alert ID to the array
        alertIds.push(alertId);

        // Add techniques and tactics to the techniques array
        if (threat && Array.isArray(threat)) {
            threat.forEach(thr => {
                const tacticName = thr.tactic.name;

                thr.technique.forEach(tech => {
                    techniques.push({
                        id: tech.id,
                        name: tech.name,
                        tactic: tacticName
                    });

                    if (tech.subtechnique && Array.isArray(tech.subtechnique)) {
                        tech.subtechnique.forEach(subtech => {
                            techniques.push({
                                id: subtech.id,
                                name: subtech.name,
                                tactic: tacticName
                            });
                        });
                    }
                });
            });
        }
    });

    return {
        alerts: alertIds, // Array of alert IDs
        techniques: techniques // Array of techniques and their corresponding tactics
    };
}

// Compare Atomic tests with ELK alerts and handle detection
async function compareAtomicTestsWithElk(hostName) {
    const atomicTests = [];
    const startTime = new Date().toISOString(); // Get current time for alerts

    fs.createReadStream('./windows-index.csv')
        .pipe(csv())
        .on('data', (row) => {
            atomicTests.push(row);
        })
        .on('end', async () => {
            console.log('CSV file successfully processed');

            const params = {
                host: '192.168.68.52',
                port: 5985,
                path: '/wsman',
                auth: 'Basic ' + Buffer.from('Vagrant:vagrant').toString('base64')
            };

            params['shellId'] = await winrm.shell.doCreateShell(params);

            for (const { 'Technique #': techniqueId, 'Test #': testNumber } of atomicTests) {
                console.log(`Running Atomic Test for technique: ${techniqueId}`);

                const results = {
                    [techniqueId]: {
                        techniqueId: techniqueId,
                        testNumber: testNumber,
                        alerts: [], // All unique alert IDs
                        techniques: [], // All unique techniques and tactics combinations
                        passed: false
                    }
                };

                try {
                    const output = await runAtomicTest(params, techniqueId, testNumber);

                    console.log(`Output for Test ${testNumber} under Technique ${techniqueId}:\n${output}`);

                    const pollInterval = 30000; // 30 seconds
                    const maxWaitTime = 180000; // 3 minutes
                    let waitedTime = 0;

                    const endTime = new Date(Date.now() + maxWaitTime).toISOString();

                    while (waitedTime < maxWaitTime) {
                        console.log('Waiting for alerts to propagate to ELK...');
                        await delay(pollInterval);
                        waitedTime += pollInterval;

                        const elkResults = await searchElkForHost(hostName, startTime, endTime);

                        const groupedData = groupAlertsAndTechniques(elkResults);

                        results[techniqueId].alerts = groupedData.alerts; // Array of alert IDs
                        results[techniqueId].techniques = groupedData.techniques; // Array of techniques and tactics

                        // Check if full detection (matching technique ID) occurred
                        const detectedAlerts = elkResults.hits.hits.filter(hit =>
                            hit._source &&
                            hit._source.event &&
                            hit._source.event.action &&
                            hit._source.event.action.includes(techniqueId)
                        );

                        if (detectedAlerts.length > 0) {
                            console.log(`✅ FULL DETECTION: ${detectedAlerts.length} event(s) found for technique ${techniqueId} on host: ${hostName}`);
                            results[techniqueId].passed = true; // Mark as passed
                            break; // Exit the loop once detection occurs
                        } else {
                            console.log(`❌ No technique-based events detected for ${techniqueId} on host: ${hostName}`);
                        }
                    }

                    if (waitedTime >= maxWaitTime) {
                        console.log(`Max wait time exceeded for host: ${hostName}. No alerts found for technique ${techniqueId}.`);
                    }
                } catch (error) {
                    console.error(`Error during comparison for technique ${techniqueId}:`, error);
                }

                // Write results to JSON file after each test
                await writeResultsToFile(results);
            }

            await winrm.shell.doDeleteShell(params);
        });
}

const testHostName = 'kingslanding'; // Replace with your host name

compareAtomicTestsWithElk(testHostName);
