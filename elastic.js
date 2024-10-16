const fs = require('fs');
const csv = require('csv-parser');
const { Client } = require('@elastic/elasticsearch');
const winrm = require('nodejs-winrm');

// ElasticSearch credentials
const ELK_USER = 'elastic'; // Replace with your actual username
const ELK_PASSWORD = '2HsejWbPb*wV6fF8eqtf'; // Replace with your actual password

// Initialize Elasticsearch client
const client = new Client({
    node: 'https://elastic.spooledup.co.uk/', // Replace with your ELK server URL if different
    auth: {
        username: ELK_USER,
        password: ELK_PASSWORD
    }
});

// Function to introduce a delay
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Function to search ELK for alerts
async function searchElkForHost(hostName, startTime) {
    try {
        const response = await client.search({
            index: '.alerts-security.alerts-default',
            body: {
                query: {
                    bool: {
                        must: [
                            {
                                match: {
                                    'host.name': hostName
                                }
                            },
                            {
                                range: {
                                    '@timestamp': {
                                        gte: startTime, // Use the start time to filter
                                        lte: 'now',
                                        format: 'strict_date_optional_time'
                                    }
                                }
                            }
                        ]
                    }
                }
            },
            size: 1000 // Adjust based on expected number of alerts
        });

        return response;
    } catch (error) {
        console.error(`Error searching ELK for host: ${error}`);
        throw error;
    }
}

// Function to run Atomic Red Team test via WinRM
async function runAtomicTest(params, techniqueId, testNumber) {
    try {
        // Construct command to run the Atomic Test with module import
        const command = `powershell -Command "Import-Module 'C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1' -Force; Invoke-AtomicTest '${techniqueId}' -TestNumbers ${testNumber}"`;

        // Execute Command
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

// Function to parse the CSV and compare Atomic Red Team tests with ELK detections
async function compareAtomicTestsWithElk(hostName) {
    const atomicTests = [];
    const startTime = new Date().toISOString(); // Capture start time

    // Read the CSV file and populate atomicTests array
    fs.createReadStream('./windows-index.csv') // Update with the actual path to your CSV
        .pipe(csv())
        .on('data', (row) => {
            atomicTests.push(row);
        })
        .on('end', async () => {
            console.log('CSV file successfully processed');

            // Create WinRM client parameters
            const params = {
                host: '192.168.68.52', // Your Windows host
                port: 5985, // Default WinRM HTTP port (or 5986 for HTTPS)
                path: '/wsman',
                auth: 'Basic ' + Buffer.from('Vagrant:vagrant').toString('base64')
            };

            // Get the Shell ID
            params['shellId'] = await winrm.shell.doCreateShell(params);

            for (const { 'Technique #': techniqueId, 'Test #': testNumber } of atomicTests) {
                console.log(`Running Atomic Test for technique: ${techniqueId}`);

                try {
                    // Run the Atomic test via WinRM
                    await runAtomicTest(params, techniqueId, testNumber);

                    // Polling for alerts in ELK
                    const pollInterval = 30000; // 30 seconds
                    const maxWaitTime = 900000; // 15 minutes
                    let waitedTime = 0;

                    while (waitedTime < maxWaitTime) {
                        console.log('Waiting for alerts to propagate to ELK...');
                        await delay(pollInterval);
                        waitedTime += pollInterval;

                        // After waiting, search for detections in ELK
                        const elkResults = await searchElkForHost(hostName, startTime);
                        console.log(JSON.stringify(elkResults, null, 2)); // Log the entire response for debugging

                        // Check if any alert corresponds to the specific technique
                        const detectedAlerts = elkResults.hits.hits.filter(hit => 
                            hit._source && 
                            hit._source.event && 
                            hit._source.event.action && 
                            hit._source.event.action.includes(techniqueId)
                        );

                        if (detectedAlerts.length > 0) {
                            console.log(`ALERT DETECTED for technique ${techniqueId}: ${detectedAlerts.length} event(s) found for host: ${hostName}`);
                            break; // Exit the polling loop
                        } else {
                            console.log(`No events detected in ELK for technique ${techniqueId} on host: ${hostName}`);
                        }
                    }

                    if (waitedTime >= maxWaitTime) {
                        console.log(`Max wait time exceeded for host: ${hostName}. No alerts found for technique ${techniqueId}.`);
                    }
                } catch (error) {
                    console.error(`Error during comparison for technique ${techniqueId}:`, error);
                }
            }

            // Close the Shell
            await winrm.shell.doDeleteShell(params);
        });
}

// Example host name to test
const testHostName = 'kingslanding'; // Replace with your actual target host

compareAtomicTestsWithElk(testHostName);
