#!/usr/bin/env node

/**
 * Simple Attio Competitor Analysis using Browser AI
 * Usage: node analyze-attio.js YOUR_API_KEY
 */

const https = require('https');

const API_KEY = process.argv[2];
const BASE_URL = 'https://api.browser.ai';

if (!API_KEY) {
    console.log('❌ Please provide your Browser AI API key:');
    console.log('   node analyze-attio.js YOUR_API_KEY');
    process.exit(1);
}

function makeRequest(method, endpoint, data = null) {
    return new Promise((resolve, reject) => {
        const url = new URL(endpoint, BASE_URL);
        
        const options = {
            hostname: url.hostname,
            port: 443,
            path: url.pathname + url.search,
            method: method,
            headers: {
                'Authorization': `apikey ${API_KEY}`,
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

async function analyzeAttio() {
    console.log('🚀 Starting Attio competitor analysis...');
    
    // Create task
    const taskData = {
        prompt: `Analyze https://www.attio.com and provide detailed insights on:

1. UI/UX Design:
   - Visual design and layout patterns
   - Navigation structure and user flow
   - Dashboard design and data visualization
   - Mobile responsiveness
   - Color schemes and typography

2. Key Features:
   - Core CRM functionality
   - AI integration and automation
   - Workflow management
   - Reporting capabilities
   - Integration options

3. User Experience:
   - Onboarding process
   - Interactive elements
   - Information architecture
   - Call-to-action design
   - Error handling

4. Technical Details:
   - Performance indicators
   - Technologies used
   - Security features
   - Mobile app availability

5. Marketing:
   - Value propositions
   - Pricing information
   - Customer testimonials
   - Competitive positioning

Provide specific examples and observations.`,
        geo: "US"
    };

    try {
        console.log('📋 Creating analysis task...');
        const taskResponse = await makeRequest('POST', '/tasks', taskData);
        const sessionId = taskResponse.session_id;
        
        console.log(`✅ Task created! Session ID: ${sessionId}`);
        console.log('⏳ Waiting for analysis to complete...');
        
        // Poll for completion
        let completed = false;
        let attempts = 0;
        const maxAttempts = 30; // 5 minutes max
        
        while (!completed && attempts < maxAttempts) {
            await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10 seconds
            
            try {
                const status = await makeRequest('GET', `/tasks/${sessionId}`);
                console.log(`📊 Status: ${status.status}`);
                
                if (status.status === 'completed') {
                    completed = true;
                } else if (status.status === 'failed') {
                    throw new Error('Task failed');
                }
            } catch (error) {
                console.log(`⚠️  Status check error: ${error.message}`);
            }
            
            attempts++;
        }
        
        if (completed) {
            console.log('📥 Retrieving results...');
            const results = await makeRequest('GET', `/results/${sessionId}`);
            
            console.log('\n' + '='.repeat(80));
            console.log('📊 ATTIО COMPETITOR ANALYSIS RESULTS');
            console.log('='.repeat(80));
            
            if (results.data) {
                console.log('\n🔍 ANALYSIS:');
                console.log(results.data);
            }
            
            if (results.screenshots) {
                console.log('\n📸 SCREENSHOTS:');
                results.screenshots.forEach((screenshot, index) => {
                    console.log(`Screenshot ${index + 1}: ${screenshot.url || 'N/A'}`);
                });
            }
            
            // Save results
            const fs = require('fs');
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `attio-analysis-${timestamp}.json`;
            fs.writeFileSync(filename, JSON.stringify(results, null, 2));
            console.log(`\n💾 Results saved to: ${filename}`);
            
        } else {
            console.log('⏰ Analysis timed out');
        }
        
    } catch (error) {
        console.log(`❌ Error: ${error.message}`);
    }
}

analyzeAttio();




