#!/usr/bin/env node

/*
 * TypeScript source-identification frontend.
 *
 * Usage:
 *   node analyze_typescript_sources.js <project-root> [output-json]
 *
 * This is the language-specific replacement for AssignmentAnalyzer. It starts
 * from exact SDK imports, follows client-object aliases with TypeChecker
 * symbols, and emits one attribute_uses record for every confirmed SDK use.
 * The Python confirmation stage remains responsible for function-level
 * deduplication and deciding whether the function returns model output.
 */

const fs = require('fs')
const path = require('path')

const projectRoot = path.resolve(process.argv[2] || '.')
const outputPath = path.resolve(process.argv[3] || path.join(projectRoot, 'source', `analysis_source_${path.basename(projectRoot)}.json`))

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

const ignoredDirectories = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.turbo', 'source'])
const sourceExtensions = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'])

const sdkDefinitions = [
  { package: 'openai', defaultExport: 'OpenAI', constructors: ['default', 'OpenAI', 'AzureOpenAI'], factories: [], functions: [] },
  { package: '@anthropic-ai/sdk', defaultExport: 'Anthropic', constructors: ['default', 'Anthropic'], factories: [], functions: [] },
  {
    package: '@google/generative-ai',
    constructors: ['GoogleGenerativeAI', 'GenerativeModel'],
    factories: [],
    clientFactories: ['getGenerativeModel'],
    functions: []
  },
  { package: '@google/genai', constructors: ['GoogleGenAI'], factories: [], functions: [] },
  {
    packagePrefix: '@langchain/',
    constructors: ['ChatOpenAI', 'AzureChatOpenAI', 'OpenAI', 'ChatAnthropic', 'ChatGoogleGenerativeAI', 'ChatGroq', 'ChatMistralAI', 'ChatCohere'],
    factories: [],
    functions: []
  },
  {
    packagePrefix: 'langchain/',
    constructors: ['ChatOpenAI', 'AzureChatOpenAI', 'OpenAI', 'ChatAnthropic', 'ChatGoogleGenerativeAI', 'ChatGroq', 'ChatMistralAI', 'ChatCohere'],
    factories: [],
    functions: []
  },
  { package: 'ollama', constructors: ['Ollama'], factories: [], functions: ['chat', 'generate'] },
  { package: 'groq-sdk', defaultExport: 'Groq', constructors: ['default', 'Groq'], factories: [], functions: [] },
  { package: '@mistralai/mistralai', constructors: ['Mistral'], factories: [], functions: [] },
  { package: 'mistralai', constructors: ['MistralClient', 'Mistral'], factories: [], functions: [] },
  { package: 'cohere-ai', constructors: ['CohereClient', 'CohereClientV2', 'Client'], factories: [], functions: [] },
  { package: 'ai', constructors: [], factories: [], functions: ['generateText', 'streamText', 'generateObject', 'streamObject'] },
  { package: '@aws-sdk/client-bedrock-runtime', constructors: ['BedrockRuntimeClient'], factories: [], functions: [] }
]

function walk(directory, files = []) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue
    const fullPath = path.join(directory, entry.name)
    if (entry.isDirectory()) walk(fullPath, files)
    else if (sourceExtensions.has(path.extname(entry.name)) && !entry.name.endsWith('.d.ts')) files.push(fullPath)
  }
  return files
}

function findRootTsconfig() {
  for (const name of ['tsconfig.json', 'jsconfig.json']) {
    const candidate = path.join(projectRoot, name)
    if (fs.existsSync(candidate)) return candidate
  }
  return null
}

function projectConfiguration() {
  const configPath = findRootTsconfig()
  if (!configPath) {
    return {
      fileNames: [],
      options: {
        allowJs: true,
        checkJs: false,
        jsx: ts.JsxEmit.Preserve,
        module: ts.ModuleKind.CommonJS,
        moduleResolution: ts.ModuleResolutionKind.NodeJs,
        target: ts.ScriptTarget.ES2020
      }
    }
  }
  const config = ts.readConfigFile(configPath, ts.sys.readFile)
  if (config.error) throw new Error(ts.flattenDiagnosticMessageText(config.error.messageText, '\n'))
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, path.dirname(configPath))
  return {
    fileNames: parsed.fileNames,
    options: { ...parsed.options, allowJs: true, checkJs: false, noEmit: true }
  }
}

function definitionFor(packageName) {
  return sdkDefinitions.find(definition =>
    definition.package === packageName ||
    (definition.packagePrefix && packageName.startsWith(definition.packagePrefix))
  )
}

function exportInfo(packageName, exportName) {
  const definition = definitionFor(packageName)
  if (!definition) return null
  let kind = null
  if (definition.constructors.includes(exportName)) kind = 'constructor'
  else if (definition.factories.includes(exportName)) kind = 'factory'
  else if (definition.functions.includes(exportName)) kind = 'function'
  if (!kind) return null
  return {
    package: packageName,
    export: exportName === 'default' ? (definition.defaultExport || 'default') : exportName,
    kind
  }
}

function moduleNameFromDeclaration(node) {
  let current = node
  while (current) {
    if (ts.isModuleDeclaration(current) && ts.isStringLiteral(current.name)) return current.name.text
    current = current.parent
  }
  const normalized = node.getSourceFile().fileName.split(path.sep).join('/')
  const marker = '/node_modules/'
  const index = normalized.lastIndexOf(marker)
  if (index === -1) return null
  const remainder = normalized.slice(index + marker.length)
  const parts = remainder.split('/')
  return parts[0].startsWith('@') ? parts.slice(0, 2).join('/') : parts[0]
}

function lineOf(sourceFile, node) {
  return sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1
}

function propertyName(node) {
  if (ts.isPropertyAccessExpression(node)) return node.name.text
  if (ts.isElementAccessExpression(node) && node.argumentExpression && ts.isStringLiteralLike(node.argumentExpression)) return node.argumentExpression.text
  if (ts.isIdentifier(node)) return node.text
  return node.getText(node.getSourceFile())
}

function enclosingFunction(node) {
  let current = node.parent
  while (current) {
    if (ts.isFunctionLike(current) && current.body) return current
    current = current.parent
  }
  return null
}

function enclosingClass(node) {
  let current = node.parent
  while (current) {
    if (ts.isClassLike(current)) return current
    current = current.parent
  }
  return null
}

function functionName(node, sourceFile) {
  if (node.name) return node.name.getText(sourceFile)
  if (ts.isVariableDeclaration(node.parent)) return node.parent.name.getText(sourceFile)
  if (ts.isPropertyDeclaration(node.parent)) return node.parent.name.getText(sourceFile)
  return '<anonymous>'
}

function functionType(node) {
  if (node.modifiers && node.modifiers.some(modifier => modifier.kind === ts.SyntaxKind.AsyncKeyword)) return 'async'
  if (ts.isArrowFunction(node)) return 'arrow'
  return 'sync'
}

function unwrap(expression) {
  let current = expression
  while (ts.isParenthesizedExpression(current) || ts.isAsExpression(current) || ts.isTypeAssertionExpression(current) ||
         ts.isNonNullExpression(current) || ts.isAwaitExpression(current)) current = current.expression
  return current
}

const sourceFiles = walk(projectRoot)
const configuration = projectConfiguration()
const rootNames = [...new Set([...sourceFiles, ...configuration.fileNames])]
const program = ts.createProgram(rootNames, configuration.options)
const checker = program.getTypeChecker()
const importBindings = new Map()
const seededSymbols = new Map()
const assignments = []

function symbolAt(node) {
  if (!node) return null
  return checker.getSymbolAtLocation(node) || null
}

function setBinding(node, info) {
  const symbol = symbolAt(node)
  if (symbol) importBindings.set(symbol, info)
}

function resolveAliasedImport(symbol) {
  if (!symbol) return null
  if (importBindings.has(symbol)) return importBindings.get(symbol)
  if (!(symbol.flags & ts.SymbolFlags.Alias)) return null
  let target
  try {
    target = checker.getAliasedSymbol(symbol)
  } catch (error) {
    return null
  }
  if (!target || target === symbol) return null
  if (importBindings.has(target)) return importBindings.get(target)
  for (const declaration of target.declarations || []) {
    if (ts.isExportSpecifier(declaration)) {
      const localTarget = checker.getExportSpecifierLocalTargetSymbol(declaration)
      const reexported = resolveAliasedImport(localTarget)
      if (reexported) return reexported
    }
    const packageName = moduleNameFromDeclaration(declaration)
    if (!packageName) continue
    const info = exportInfo(packageName, target.getName())
    if (info) return info
  }
  return null
}

function collectImportBindings(sourceFile) {
  for (const statement of sourceFile.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier) && statement.importClause) {
      const packageName = statement.moduleSpecifier.text
      if (statement.importClause.name) {
        const info = exportInfo(packageName, 'default')
        if (info) setBinding(statement.importClause.name, info)
      }
      const bindings = statement.importClause.namedBindings
      if (bindings && ts.isNamedImports(bindings)) {
        for (const element of bindings.elements) {
          const exportedName = element.propertyName ? element.propertyName.text : element.name.text
          const info = exportInfo(packageName, exportedName)
          if (info) setBinding(element.name, info)
        }
      } else if (bindings && ts.isNamespaceImport(bindings) && definitionFor(packageName)) {
        setBinding(bindings.name, { package: packageName, kind: 'namespace' })
      }
    }

    if (!ts.isVariableStatement(statement)) continue
    for (const declaration of statement.declarationList.declarations) {
      const initializer = declaration.initializer && unwrap(declaration.initializer)
      if (!initializer || !ts.isCallExpression(initializer) || !ts.isIdentifier(initializer.expression) ||
          initializer.expression.text !== 'require' || initializer.arguments.length !== 1 ||
          !ts.isStringLiteral(initializer.arguments[0])) continue
      const packageName = initializer.arguments[0].text
      if (!definitionFor(packageName)) continue
      if (ts.isIdentifier(declaration.name)) {
        const info = exportInfo(packageName, 'default') || { package: packageName, kind: 'namespace' }
        setBinding(declaration.name, info)
      } else if (ts.isObjectBindingPattern(declaration.name)) {
        for (const element of declaration.name.elements) {
          if (!ts.isIdentifier(element.name)) continue
          const exportedName = element.propertyName ? element.propertyName.getText(sourceFile) : element.name.text
          const info = exportInfo(packageName, exportedName)
          if (info) setBinding(element.name, info)
        }
      }
    }
  }
}

for (const sourceFile of program.getSourceFiles()) {
  if (sourceFile.isDeclarationFile || !sourceFile.fileName.startsWith(projectRoot + path.sep)) continue
  collectImportBindings(sourceFile)
}

function callableInfo(expression) {
  const current = unwrap(expression)
  const direct = resolveAliasedImport(symbolAt(ts.isPropertyAccessExpression(current) ? current.name : current))
  if (direct) return direct
  if (ts.isPropertyAccessExpression(current)) {
    const namespace = resolveAliasedImport(symbolAt(current.expression))
    if (namespace && namespace.kind === 'namespace') return exportInfo(namespace.package, current.name.text)
  }
  return null
}

function typeInfo(typeNode) {
  const current = ts.isTypeReferenceNode(typeNode) ? typeNode.typeName : typeNode
  return resolveAliasedImport(symbolAt(current))
}

function seedInfo(expression) {
  const current = unwrap(expression)
  if (ts.isIdentifier(current) || ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) {
    const own = seededSymbols.get(symbolAt(ts.isPropertyAccessExpression(current) ? current.name : current))
    if (own) return own
    if (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) return seedInfo(current.expression)
  }
  return null
}

function createdClientInfo(expression) {
  const current = unwrap(expression)
  if (ts.isNewExpression(current)) {
    const info = callableInfo(current.expression)
    return info && info.kind === 'constructor' ? info : null
  }
  if (ts.isCallExpression(current)) {
    const info = callableInfo(current.expression)
    if (info && info.kind === 'factory') return info
    if (ts.isPropertyAccessExpression(current.expression) || ts.isElementAccessExpression(current.expression)) {
      const receiver = seedInfo(current.expression.expression)
      const definition = receiver && definitionFor(receiver.package)
      if (receiver && definition && (definition.clientFactories || []).includes(propertyName(current.expression))) return receiver
    }
  }
  return null
}

function bindingSymbols(name, symbols = []) {
  if (ts.isIdentifier(name)) {
    const symbol = symbolAt(name)
    if (symbol) symbols.push({ symbol, name: name.text, node: name })
  } else if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
    for (const element of name.elements) {
      if (ts.isBindingElement(element)) bindingSymbols(element.name, symbols)
    }
  } else if (ts.isPropertyAccessExpression(name)) {
    const symbol = symbolAt(name.name)
    if (symbol) symbols.push({ symbol, name: name.name.text, node: name })
  }
  return symbols
}

function addSeed(target, info, initializer, sourceFile) {
  let changed = false
  for (const binding of bindingSymbols(target)) {
    if (seededSymbols.has(binding.symbol)) continue
    seededSymbols.set(binding.symbol, info)
    const klass = enclosingClass(binding.node)
    assignments.push({
      file: sourceFile.fileName,
      class: (klass && klass.name && klass.name.text) || '',
      attribute: binding.name,
      client_type: info.export,
      line: lineOf(sourceFile, binding.node),
      code: initializer ? initializer.parent.getText(sourceFile) : binding.node.parent.getText(sourceFile),
      module: path.relative(projectRoot, sourceFile.fileName).split(path.sep).join('/'),
      sdk: { package: info.package, export: info.export }
    })
    changed = true
  }
  return changed
}

function collectSeeds(sourceFile) {
  let changed = false
  function visit(node) {
    if ((ts.isVariableDeclaration(node) || ts.isPropertyDeclaration(node)) && node.initializer) {
      const info = createdClientInfo(node.initializer) || seedInfo(node.initializer)
      if (info) changed = addSeed(node.name, info, node.initializer, sourceFile) || changed
    } else if (ts.isParameter(node) && node.modifiers && node.modifiers.some(modifier =>
      modifier.kind === ts.SyntaxKind.PrivateKeyword || modifier.kind === ts.SyntaxKind.PublicKeyword ||
      modifier.kind === ts.SyntaxKind.ProtectedKeyword || modifier.kind === ts.SyntaxKind.ReadonlyKeyword
    ) && node.type) {
      const info = typeInfo(node.type)
      if (info && info.kind === 'constructor') changed = addSeed(node.name, info, null, sourceFile) || changed
    } else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const info = createdClientInfo(node.right) || seedInfo(node.right)
      if (info) changed = addSeed(node.left, info, node.right, sourceFile) || changed
    }
    ts.forEachChild(node, visit)
  }
  visit(sourceFile)
  return changed
}

let changed = true
while (changed) {
  changed = false
  for (const sourceFile of program.getSourceFiles()) {
    if (sourceFile.isDeclarationFile || !sourceFile.fileName.startsWith(projectRoot + path.sep)) continue
    changed = collectSeeds(sourceFile) || changed
  }
}

const attributeUses = []

function addUse(sourceFile, call, info) {
  const fn = enclosingFunction(call)
  if (!fn) return
  const klass = enclosingClass(fn)
  const start = lineOf(sourceFile, fn)
  const end = sourceFile.getLineAndCharacterOfPosition(fn.end).line + 1
  const method = functionName(fn, sourceFile)
  const className = klass && klass.name ? klass.name.text : ''
  const module = path.relative(projectRoot, sourceFile.fileName).split(path.sep).join('/')
  attributeUses.push({
    file: sourceFile.fileName,
    class: className,
    method,
    method_type: functionType(fn),
    attribute: propertyName(call.expression),
    line: lineOf(sourceFile, call),
    code: call.getText(sourceFile),
    method_start_line: start,
    method_end_line: end,
    method_params: fn.parameters.map(parameter => parameter.name.getText(sourceFile)).join(', '),
    method_code: fn.getText(sourceFile),
    module,
    function_id: `${module}:${className}:${method}:${fn.getStart(sourceFile)}:${fn.end}`,
    sdk: { package: info.package, export: info.export }
  })
}

for (const sourceFile of program.getSourceFiles()) {
  if (sourceFile.isDeclarationFile || !sourceFile.fileName.startsWith(projectRoot + path.sep)) continue
  function visit(node) {
    if (ts.isCallExpression(node)) {
      const direct = callableInfo(node.expression)
      if (direct && direct.kind === 'function') addUse(sourceFile, node, direct)
      else {
        const receiver = ts.isPropertyAccessExpression(node.expression) || ts.isElementAccessExpression(node.expression)
          ? seedInfo(node.expression.expression)
          : null
        if (receiver) addUse(sourceFile, node, receiver)
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
