# Chrome DevTools MCP Setup

This document explains how to use Playwright to access Chrome DevTools for your CoreFlow360 application.

## Installation

Playwright has been installed with the following browsers:
- Chromium (for Chrome DevTools)
- Firefox
- WebKit

## Available Scripts

### Basic Chrome DevTools Test
```bash
npm run chrome:devtools
```
This will:
- Launch Chrome with DevTools enabled
- Navigate to your CoreFlow360 app (http://localhost:3000)
- Take a screenshot
- Log console messages and network requests
- Keep the browser open for manual inspection

### Advanced Chrome DevTools Protocol (CDP)
```bash
npm run chrome:cdp
```
This provides:
- Full Chrome DevTools Protocol access
- DOM snapshots and analysis
- Performance metrics
- CSS coverage tracking
- Memory usage monitoring
- Real-time network and console monitoring

### Install/Update Browsers
```bash
npm run chrome:install
```

### Run Playwright Tests
```bash
npm run chrome:test
```

## Usage Examples

### 1. Basic DevTools Access
```bash
# Start your CoreFlow360 app first
npm start

# In another terminal, run the DevTools test
npm run chrome:devtools
```

### 2. Advanced CDP Analysis
```bash
# For detailed analysis with CDP
npm run chrome:cdp
```

### 3. Manual DevTools Access
When running the scripts, you can also access DevTools manually:
- **Local DevTools**: http://localhost:9222
- **Browser DevTools**: Use F12 or right-click → Inspect in the opened browser window

## Features Available

### Chrome DevTools Protocol Domains
- **Runtime**: JavaScript execution and debugging
- **Network**: Request/response monitoring
- **Page**: Navigation and page events
- **DOM**: Document structure analysis
- **CSS**: Stylesheet analysis and coverage
- **Performance**: Performance metrics collection

### Monitoring Capabilities
- Real-time console log capture
- Network request tracking
- Performance metrics
- Memory usage analysis
- DOM structure analysis
- CSS coverage tracking

## Troubleshooting

### Port Already in Use
If port 9222 is already in use:
```bash
# Kill existing Chrome processes
taskkill /f /im chrome.exe
taskkill /f /im chromium.exe
```

### Browser Not Launching
```bash
# Reinstall browsers
npm run chrome:install
```

### DevTools Not Accessible
- Ensure your CoreFlow360 app is running on http://localhost:3000
- Check that no firewall is blocking port 9222
- Try running with `--headless=false` in the script

## Integration with MCP

This setup enables Chrome DevTools MCP by providing:
1. **Remote Debugging**: Chrome accessible via CDP on port 9222
2. **Automated Testing**: Playwright scripts for automated DevTools access
3. **Real-time Monitoring**: Live capture of console, network, and performance data
4. **Advanced Analysis**: DOM snapshots, CSS coverage, and memory profiling

## Next Steps

1. Start your CoreFlow360 application: `npm start`
2. Run the DevTools test: `npm run chrome:devtools`
3. Access DevTools at http://localhost:9222 or use the browser's built-in DevTools
4. Use the advanced CDP script for detailed analysis: `npm run chrome:cdp`

The Chrome DevTools MCP is now ready for use with your CoreFlow360 application!

