#!/usr/bin/env node
/**
 * Lightweight latency sampler for the CoreFlow360 Worker.
 * Polls a configurable set of endpoints and records average / p95 latency.
 */
import { performance } from 'node:perf_hooks'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

const BASE_URL = process.env.CF360_WORKER_BASE_URL ?? 'http://127.0.0.1:8787'
const ITERATIONS = Number.parseInt(process.env.CF360_LATENCY_ITERATIONS ?? '5', 10)
const OUTPUT_DIR = process.env.CF360_AUDIT_OUTPUT ?? path.join('audit-results', 'latency')

const endpoints = [
  { method: 'GET', path: '/health', label: 'Worker health' },
  { method: 'GET', path: '/api/v1/observability/health', label: 'Observability health' },
  { method: 'GET', path: '/api/v1/dashboard/stats?dateRange=30d', label: 'Dashboard stats (default tenant)' },
]

async function measure(endpoint) {
  const latencies = []
  let failures = 0
  const statusCounts = new Map()

  for (let i = 0; i < ITERATIONS; i += 1) {
    const url = new URL(endpoint.path, BASE_URL).toString()
    const start = performance.now()

    try {
      const response = await fetch(url, {
        method: endpoint.method,
        headers: {
          'Content-Type': 'application/json',
        },
      })
      const duration = performance.now() - start
      latencies.push(duration)

      statusCounts.set(response.status, (statusCounts.get(response.status) ?? 0) + 1)

      if (!response.ok) {
        failures += 1
      }
    } catch (error) {
      failures += 1
      console.error(`⚠️  Request to ${endpoint.path} failed`, error)
    }
  }

  latencies.sort((a, b) => a - b)
  const average = latencies.reduce((total, value) => total + value, 0) / (latencies.length || 1)
  const p95 = latencies[Math.max(Math.ceil(latencies.length * 0.95) - 1, 0)] ?? 0

  return {
    ...endpoint,
    sampleSize: latencies.length,
    failures,
    averageMs: Number(average.toFixed(2)),
    p95Ms: Number(p95.toFixed(2)),
    minMs: Number((latencies[0] ?? 0).toFixed(2)),
    maxMs: Number((latencies[latencies.length - 1] ?? 0).toFixed(2)),
    statusCounts: Object.fromEntries(statusCounts),
  }
}

async function main() {
  console.info(`⚙️  Sampling Worker latency (${ITERATIONS} iterations)`)
  console.info(`    Base URL: ${BASE_URL}`)

  const reports = []
  for (const endpoint of endpoints) {
    const report = await measure(endpoint)
    reports.push(report)

    const statusSummary = Object.entries(report.statusCounts)
      .map(([status, count]) => `${status}×${count}`)
      .join(', ')

    console.info(
      `→ ${endpoint.label.padEnd(36)} avg ${report.averageMs} ms | p95 ${report.p95Ms} ms | failures ${report.failures} | status [${statusSummary}]`,
    )
  }

  await mkdir(OUTPUT_DIR, { recursive: true })
  const outputPath = path.join(OUTPUT_DIR, `worker-latency-${Date.now()}.json`)
  await writeFile(outputPath, JSON.stringify({ generatedAt: new Date().toISOString(), reports }, null, 2))

  console.info(`\n📁 Latency report saved to ${outputPath}`)
}

main().catch((error) => {
  console.error('Latency sampling failed', error)
  process.exitCode = 1
})
