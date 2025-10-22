#!/usr/bin/env node

/**
 * Launches the production build locally via `vite preview`, opens it in a headless
 * Chromium browser, and captures any console/page errors along with the router
 * error boundary details. Designed to reproduce the production failure locally
 * and emit actionable diagnostics to stdout.
 */

import { spawn } from 'node:child_process'
import process from 'node:process'
import { setTimeout as wait } from 'node:timers/promises'
import { chromium } from 'playwright'
import path from 'node:path'

const FRONTEND_DIR = process.env.FRONTEND_DIR
  ? path.resolve(process.env.FRONTEND_DIR)
  : path.resolve(process.cwd())
const PREVIEW_PORT = process.env.PREVIEW_PORT || '4173'
const PREVIEW_HOST = process.env.PREVIEW_HOST || '127.0.0.1'

function runPreview() {
  const npmCommand = process.platform === 'win32' ? 'npm' : 'npm'
  const args = ['run', 'preview', '--', '--host', PREVIEW_HOST, '--port', PREVIEW_PORT]
  const baseOptions = {
    cwd: FRONTEND_DIR,
    stdio: 'pipe',
    env: {
      ...process.env,
      NODE_ENV: 'production',
    },
  }

  let preview
  if (process.platform === 'win32') {
    const command = `${npmCommand} ${args.join(' ')}`
    preview = spawn(command, {
      ...baseOptions,
      shell: true,
    })
  } else {
    preview = spawn(npmCommand, args, baseOptions)
  }

  preview.stdout.on('data', data => {
    process.stdout.write(`[preview] ${data}`)
  })

  preview.stderr.on('data', data => {
    process.stderr.write(`[preview:err] ${data}`)
  })

  preview.on('exit', code => {
    if (code !== null && code !== 0) {
      console.error(`vite preview exited unexpectedly with code ${code}`)
    }
  })

  return preview
}

async function captureRuntimeDiagnostics() {
  console.log('ℹ️  Starting local production preview…')
  const preview = runPreview()

  // Allow the preview server to boot
  await wait(4000)

  const browser = await chromium.launch({ headless: true })
  const page = await browser.newPage()

  const consoleLogs = []
  const consoleErrors = []
  const pageErrors = []

  page.on('console', message => {
    const entry = {
      type: message.type(),
      text: message.text(),
    }
    consoleLogs.push(entry)
    if (entry.type === 'error') {
      consoleErrors.push(entry)
    }
  })

  page.on('pageerror', error => {
    pageErrors.push({
      message: error.message,
      stack: error.stack,
    })
  })

  const targetUrl = `http://${PREVIEW_HOST}:${PREVIEW_PORT}/`
  console.log(`ℹ️  Navigating headless browser to ${targetUrl}`)

  try {
    await page.goto(targetUrl, {
      waitUntil: 'networkidle',
      timeout: 30000,
    })
  } catch (error) {
    console.error('❌ Failed to load preview URL:', error)
  }

  // Give the application time to initialise and potentially fail
  await wait(5000)

  const errorBoundaryDetails = await page.evaluate(() => {
    const summary = document.querySelector('details summary')
    const details = document.querySelector('details pre code')

    return {
      summaryOpenByDefault: summary?.getAttribute('open') === '' || summary?.hasAttribute('open') || false,
      detailsText: details?.textContent ?? null,
      bodyText: document.body?.innerText?.slice(0, 500) ?? '',
      rootHtml: document.getElementById('root')?.innerHTML ?? null,
    }
  })

  console.log('──────── Runtime Diagnostics ────────')
  console.log('Console messages:')
  consoleLogs.forEach(entry => {
    console.log(`  [${entry.type}] ${entry.text}`)
  })

  if (pageErrors.length > 0) {
    console.log('Page errors:')
    pageErrors.forEach(err => {
      console.log(`  ${err.message}`)
      if (err.stack) {
        console.log(err.stack)
      }
    })
  } else {
    console.log('No uncaught page errors captured.')
  }

  console.log('\nRouter error details:')
  console.log(errorBoundaryDetails.detailsText || '(none)')
  console.log('\nRoot element HTML preview:')
  console.log(errorBoundaryDetails.rootHtml || '(empty)')
  console.log('Body text preview:')
  console.log(errorBoundaryDetails.bodyText)

  await browser.close()
  preview.kill('SIGINT')
}

captureRuntimeDiagnostics().catch(error => {
  console.error('Fatal failure during runtime diagnostics:', error)
  process.exitCode = 1
})
