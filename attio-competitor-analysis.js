#!/usr/bin/env node

/**
 * Attio Competitor Analysis using Browser AI
 * This script analyzes Attio's website for UI, UX, and capabilities
 */

const https = require('https');

// Configuration
const BROWSER_AI_API_KEY = process.env.BROWSER_AI_API_KEY || 'YOUR_API_KEY_HERE';
const BROWSER_AI_BASE_URL = 'https://api.browser.ai';

// Colors for console output
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m'
};

function log(message, color = 'reset') {
    console.log(`${colors[color]}${message}${colors.reset}`);
}

function makeRequest(method, endpoint, data = null) {
    return new Promise((resolve, reject) => {
        const url = new URL(endpoint, BROWSER_AI_BASE_URL);
        
        const options = {
            hostname: url.hostname,
            port: url.port || 443,
            path: url.pathname + url.search,
            method: method,
            headers: {
                'Authorization': `apikey ${BROWSER_AI_API_KEY}`,
                'Content-Type': 'application/json'
            }
        };

        if (data) {
            const postData = JSON.stringify(data);
            options.headers['Content-Length'] = Buffer.byteLength(postData);
        }

        const req = https.request(options, (res) => {
            let responseData = '';

            res.on('data', (chunk) => {
                responseData += chunk;
            });

            res.on('end', () => {
                try {
                    const parsed = JSON.parse(responseData);
                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        resolve(parsed);
                    } else {
                        reject(new Error(`HTTP ${res.statusCode}: ${parsed.message || responseData}`));
                    }
                } catch (e) {
                    reject(new Error(`Invalid JSON response: ${responseData}`));
                }
            });
        });

        req.on('error', (error) => {
            reject(error);
        });

        if (data) {
            req.write(JSON.stringify(data));
        }

        req.end();
    });
}

async function createAnalysisTask() {
    log('🚀 Creating Browser AI task for Attio analysis...', 'cyan');
    
    const taskData = {
        prompt: `Analyze the Attio CRM website (https://www.attio.com) and extract comprehensive information about:

1. UI/UX Design Elements:
   - Visual design patterns and aesthetics
   - Navigation structure and user flow
   - Dashboard layouts and data visualization
   - Mobile responsiveness and accessibility
   - Color schemes, typography, and spacing

2. Key Features and Capabilities:
   - Core CRM functionality
   - AI integration and automation features
   - Workflow management tools
   - Reporting and analytics capabilities
   - Integration options and APIs

3. User Experience Patterns:
   - Onboarding flow and user journey
   - Interactive elements and micro-interactions
   - Information architecture
   - Call-to-action placement and design
   - Error handling and feedback mechanisms

4. Technical Implementation:
   - Page load performance indicators
   - Modern web technologies used
   - Security features and compliance mentions
   - Mobile app availability

5. Marketing and Positioning:
   - Value propositions and messaging
   - Pricing information (if available)
   - Customer testimonials and social proof
   - Feature comparisons and competitive positioning

Please provide detailed observations with specific examples and screenshots if possible.`,
        geo: "US"
    };

    try {
        const response = await makeRequest('POST', '/tasks', taskData);
        log(`✅ Task created successfully!`, 'green');
        log(`📋 Session ID: ${response.session_id}`, 'yellow');
        return response.session_id;
    } catch (error) {
        log(`❌ Failed to create task: ${error.message}`, 'red');
        throw error;
    }
}

async function checkTaskStatus(sessionId) {
    try {
        const response = await makeRequest('GET', `/tasks/${sessionId}`);
        return response;
    } catch (error) {
        log(`❌ Failed to check task status: ${error.message}`, 'red');
        throw error;
    }
}

async function getTaskResults(sessionId) {
    try {
        const response = await makeRequest('GET', `/results/${sessionId}`);
        return response;
    } catch (error) {
        log(`❌ Failed to get task results: ${error.message}`, 'red');
        throw error;
    }
}

async function waitForTaskCompletion(sessionId, maxWaitTime = 300000) { // 5 minutes max
    const startTime = Date.now();
    const pollInterval = 10000; // 10 seconds
    
    log('⏳ Waiting for task completion...', 'yellow');
    
    while (Date.now() - startTime < maxWaitTime) {
        try {
            const status = await checkTaskStatus(sessionId);
            
            log(`📊 Task status: ${status.status}`, 'blue');
            
            if (status.status === 'completed') {
                log('✅ Task completed successfully!', 'green');
                return true;
            } else if (status.status === 'failed') {
                log('❌ Task failed!', 'red');
                return false;
            }
            
            // Wait before next poll
            await new Promise(resolve => setTimeout(resolve, pollInterval));
            
        } catch (error) {
            log(`⚠️  Error checking status: ${error.message}`, 'yellow');
            await new Promise(resolve => setTimeout(resolve, pollInterval));
        }
    }
    
    log('⏰ Task timeout reached', 'red');
    return false;
}

function formatAnalysisResults(results) {
    log('\n' + '='.repeat(80), 'bright');
    log('📊 ATTIО COMPETITOR ANALYSIS RESULTS', 'bright');
    log('='.repeat(80), 'bright');
    
    if (results && results.data) {
        log('\n🔍 ANALYSIS DATA:', 'cyan');
        log(results.data, 'reset');
    }
    
    if (results && results.screenshots) {
        log('\n📸 SCREENSHOTS CAPTURED:', 'cyan');
        results.screenshots.forEach((screenshot, index) => {
            log(`Screenshot ${index + 1}: ${screenshot.url || 'N/A'}`, 'blue');
        });
    }
    
    if (results && results.metadata) {
        log('\n📋 METADATA:', 'cyan');
        log(JSON.stringify(results.metadata, null, 2), 'reset');
    }
}

async function main() {
    log('🎯 Attio Competitor Analysis with Browser AI', 'bright');
    log('=' .repeat(50), 'bright');
    
    if (BROWSER_AI_API_KEY === 'YOUR_API_KEY_HERE') {
        log('❌ Please set your Browser AI API key:', 'red');
        log('   export BROWSER_AI_API_KEY="your_actual_api_key"', 'yellow');
        log('   or replace YOUR_API_KEY_HERE in this script', 'yellow');
        process.exit(1);
    }
    
    try {
        // Step 1: Create analysis task
        const sessionId = await createAnalysisTask();
        
        // Step 2: Wait for completion
        const completed = await waitForTaskCompletion(sessionId);
        
        if (completed) {
            // Step 3: Get results
            log('📥 Retrieving analysis results...', 'cyan');
            const results = await getTaskResults(sessionId);
            
            // Step 4: Format and display results
            formatAnalysisResults(results);
            
            // Step 5: Save results to file
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `attio-analysis-${timestamp}.json`;
            
            require('fs').writeFileSync(filename, JSON.stringify(results, null, 2));
            log(`\n💾 Results saved to: ${filename}`, 'green');
            
        } else {
            log('❌ Analysis failed or timed out', 'red');
        }
        
    } catch (error) {
        log(`❌ Analysis failed: ${error.message}`, 'red');
        process.exit(1);
    }
}

// Run the analysis
if (require.main === module) {
    main().catch(console.error);
}

module.exports = {
    createAnalysisTask,
    checkTaskStatus,
    getTaskResults,
    waitForTaskCompletion
};




