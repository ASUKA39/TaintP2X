#!/usr/bin/env node

/*
 * TypeScript source-identification frontend.
 *
 * Usage:
 *   node analyze_typescript_sources.js <project-root> [output-json]
 *
 * It uses the official TypeScript Compiler API rather than a text parser. The
 * output keeps the broad shape consumed by the Python pipeline: assignments
 * and attribute_uses. Each candidate includes a source range and method text,
 * so the confirmation stage does not need language-specific line parsing.
 */

const fs = require('fs')
const path = require('path')
let ts
try {
  ts = require('typescript')
} catch (error) {
  try {
    ts = require(path.join(projectRoot, 'node_modules', 'typescript'))
  } catch (targetError) {
    throw new Error('TypeScript compiler API is not installed; install the target project dependencies before source identification')
  }
}

const projectRoot = path.resolve(process.argv[2] || '.')
const outputPath = path.resolve(process.argv[3] || path.join(projectRoot, 'source', `analysis_source_${path.basename(projectRoot)}.json`))

const ignored = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.turbo'])
const extensions = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'])
const llmPackages = [
  'openai', '@anthropic-ai', '@google/generative-ai', '@langchain', 'langchain',
  'ollama', 'groq', 'mistralai', 'cohere', 'ai', '@aws-sdk/client-bedrock'
]
const llmMethods = new Set([
  'invoke', 'ainvoke', 'generate', 'agenerate', 'complete', 'acomplete',
  'call', 'chat', 'create', 'stream', 'generateContent', 'createChatCompletion'
])

function walk(dir, files = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (ignored.has(entry.name)) continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) walk(full, files)
    else if (extensions.has(path.extname(entry.name))) files.push(full)
  }
  return files
}

function sourceText(sourceFile, node) {
  return node.getText(sourceFile)
}

function packageLooksLikeLLM(name) {
  return llmPackages.some(prefix => name.startsWith(prefix.trim()))
}

function propertyName(node) {
  if (ts.isPropertyAccessExpression(node)) return node.name.text
  if (ts.isElementAccessExpression(node) && ts.isStringLiteral(node.argumentExpression)) return node.argumentExpression.text
  return null
}

function collectImports(sourceFile) {
  const imports = new Set()
  for (const statement of sourceFile.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) {
      if (packageLooksLikeLLM(statement.moduleSpecifier.text)) imports.add(statement.moduleSpecifier.text)
    }
    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (declaration.initializer && ts.isCallExpression(declaration.initializer) &&
            ts.isIdentifier(declaration.initializer.expression) && declaration.initializer.expression.text === 'require' &&
            declaration.initializer.arguments.length === 1 && ts.isStringLiteral(declaration.initializer.arguments[0]) &&
            packageLooksLikeLLM(declaration.initializer.arguments[0].text)) {
          imports.add(declaration.initializer.arguments[0].text)
        }
      }
    }
  }
  return imports
}

function isCandidateCall(node, imports) {
  if (!ts.isCallExpression(node)) return false
  const method = propertyName(node.expression)
  if (!method || !llmMethods.has(method)) return false
  if (imports.size > 0) return true
  const text = node.expression.getText().toLowerCase()
  return /\b(llm|openai|anthropic|gemini|claude|groq|ollama|mistral|cohere|langchain|model)\b/.test(text)
}

function enclosingFunction(node) {
  let current = node.parent
  while (current) {
    if (ts.isFunctionDeclaration(current) || ts.isMethodDeclaration(current) ||
        ts.isArrowFunction(current) || ts.isFunctionExpression(current) || ts.isGetAccessor(current) || ts.isSetAccessor(current)) return current
    current = current.parent
  }
  return null
}

function functionName(fn) {
  if (fn.name && fn.name.getText) return fn.name.getText()
  if (fn.parent && ts.isVariableDeclaration(fn.parent)) return fn.parent.name.getText()
  return '<anonymous>'
}

function className(fn) {
  let current = fn.parent
  while (current) {
    if (ts.isClassDeclaration(current) || ts.isClassExpression(current)) return current.name ? current.name.text : '<anonymous class>'
    current = current.parent
  }
  return ''
}

const assignments = []
const attributeUses = []
const seen = new Set()
for (const file of walk(projectRoot)) {
  const source = fs.readFileSync(file, 'utf8')
  const sourceFile = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const imports = collectImports(sourceFile)
  function visit(node) {
    if (isCandidateCall(node, imports)) {
      const fn = enclosingFunction(node)
      if (fn) {
        const start = sourceFile.getLineAndCharacterOfPosition(fn.getStart(sourceFile)).line + 1
        const end = sourceFile.getLineAndCharacterOfPosition(fn.end).line + 1
        const callLine = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1
        const key = `${file}:${start}:${end}`
        if (!seen.has(key)) {
          seen.add(key)
          const method = functionName(fn)
          const record = {
            file: file,
            class: className(fn),
            method,
            method_start_line: start,
            method_end_line: end,
            method_params: fn.parameters.map(p => p.name.getText(sourceFile)),
            attribute: propertyName(node.expression),
            line: callLine,
            method_code: sourceText(sourceFile, fn),
            module: path.relative(projectRoot, file).split(path.sep).join('/')
          }
          attributeUses.push(record)
          assignments.push({ file, method, line: callLine, attribute: record.attribute, module: record.module })
        }
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(sourceFile)
}

fs.mkdirSync(path.dirname(outputPath), { recursive: true })
fs.writeFileSync(outputPath, JSON.stringify({ assignments, attribute_uses: attributeUses }, null, 2) + '\n')
console.log(`TypeScript source candidates: ${attributeUses.length}`)
console.log(`Wrote ${outputPath}`)
