// Manual script to trigger reparse through the deployed Worker
// This script calls a special endpoint we'll add to manually trigger reparse

const WORKER_URL = 'https://ios-security-tracker.graceliu.workers.dev';

async function triggerManualReparse(versions) {
    const response = await fetch(`${WORKER_URL}/admin/reparse`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Admin-Key': 'manual-reparse-2024' // Simple auth
        },
        body: JSON.stringify({
            versions: versions,
            forceUpdate: true
        })
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Reparse failed: ${response.status} ${response.statusText}\n${errorText}`);
    }

    const result = await response.json();
    console.log('Reparse result:', JSON.stringify(result, null, 2));
    return result;
}

// iOS versions to reparse (corrected based on Apple's actual releases)
const versionsToReparse = [
    // iOS 18 versions
    '18.0', '18.1', '18.2', '18.3', '18.4', '18.5', '18.6',
    // iOS 26 (Apple jumped from 18.7 to 26)
    '26'
];

console.log('Starting manual reparse for versions:', versionsToReparse);
triggerManualReparse(versionsToReparse)
    .then(result => {
        console.log('Manual reparse completed successfully:', result);
    })
    .catch(error => {
        console.error('Manual reparse failed:', error);
    });