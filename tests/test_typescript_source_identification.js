#!/usr/bin/env node

const assert = require('assert')
const childProcess = require('child_process')
const fs = require('fs')
const os = require('os')
const path = require('path')

const repositoryRoot = path.resolve(__dirname, '..')
const fixtureRoot = path.join(__dirname, 'fixtures', 'typescript_sources')
const outputDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'taintp2x-source-test-'))
const outputPath = path.join(outputDirectory, 'analysis.json')

try {
  childProcess.execFileSync(
    process.execPath,
    [path.join(repositoryRoot, 'Source_Identification', 'analyze_typescript_sources.js'), fixtureRoot, outputPath],
    { stdio: 'inherit' }
  )

  const result = JSON.parse(fs.readFileSync(outputPath, 'utf8'))
  const uses = result.attribute_uses
  const functions = uses.map(item => item.method)

  assert(functions.includes('moduleVariable'), 'module-level client use was not found')
  assert(functions.includes('directApi'), 'aliased direct API use was not found')
  assert(functions.includes('reexportedClient'), 're-exported SDK constructor use was not found')
  assert(
    uses.some(item => item.method === 'factoryClient' && item.attribute === 'generateContent'),
    'registered client factory return was not followed'
  )
  assert(uses.some(item => item.class === 'ParameterAgent' && item.method === 'answer'), 'constructor parameter property use was not found')
  assert(!functions.includes('ordinaryCalls'), 'ordinary methods were treated as LLM calls')

  const fieldUses = uses.filter(item => item.class === 'FieldAgent' && item.method === 'answer')
  assert.strictEqual(fieldUses.length, 2, 'each LLM client use must be preserved before confirmation')
  for (const use of uses) {
    assert(use.function_id, 'a stable function identity is required for precise CodeQL source generation')
    assert(use.sdk && use.sdk.package, 'SDK provenance is required for every candidate')
  }

  assert(result.assignments.some(item => item.attribute === 'client' && item.client_type === 'OpenAI'))
  console.log(`source identification regression test passed (${uses.length} uses)`)
} finally {
  fs.rmSync(outputDirectory, { recursive: true, force: true })
}
