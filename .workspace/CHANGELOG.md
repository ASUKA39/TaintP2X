# TypeScript Port Development Changelog

## 2026-09-11 (reentrant reproduction runner)

- Added `scripts/reproduce_typescript.py`, a reentrant one-command runner that
  clones and prepares the configured target, invokes the existing TypeScript
  CodeQL/LLM pipeline, preserves human-readable artifacts, and removes only
  the temporary checkout and CodeQL database.
- Added the runner command to `REPRODUCTION_GUIDE.md`; it does not interpret
  SARIF or generate a separate vulnerability verdict.
- Verified the runner twice against Flowise `CVE-2026-41265`; the final run
  completed successfully and confirmed both validation results while leaving
  only results, validation files, queries, and logs in the run workspace.

## 2026-09-11 (complete CodeQL path validation)

- Changed generated rules from problem queries to path-problem queries using the stateful flow module's exported `PathGraph` and `flowPath` interface.
- Renamed the flow library entry to `TaintP2XFlowQuery.qll` so the exported `TaintP2XFlow::PathGraph` resolves without colliding with the library filename.
- Prepared an independent CodeQL 2.23.2 CLI and official QL checkout under this repository's `.workspace/codeql/`; no other tool workspace is used.
- Re-ran Flowise `CVE-2026-41265` end to end. Both findings contain 11-node source-to-sink paths in SARIF and `taint-output.json`; SourceDeterminer retained issue 2 and FullyDeterminer generated the final analysis result.
- Rewrote `REPRODUCTION_GUIDE.md` to contain only the TypeScript/CodeQL reproduction procedure and recorded the verified result.
- Moved validation artifacts under `.workspace/llm-validation/` so all reproduction outputs stay in the documented workspace.
- Unified the legacy batch CodeQL entry point with the same configurable
  `.workspace/llm-validation` directory used by the TypeScript entry point.
- Fixed TypeScript Source/Fully validation context extraction by reusing the
  Compiler API analysis index instead of treating nested object literals as
  function declarations. A fresh Flowise run now confirms both the Airtable
  and CSV source-to-code-execution paths.

## 2026-09-11 (CVE-2026-41265 reproduction)

- Switched the TypeScript reproduction target to Flowise `CVE-2026-41265` at `flowise@2.2.6`, re-cloned the pinned commit, and installed dependencies.
- Added generic `LLMChain` source and Pyodide `runPythonAsync` sink modeling; complete scan produced 61 candidates, 23 confirmed LLM-output functions, and 2 `taintp2x/5001` findings.
- Ran the original Source/Fully LLM validation stages for both findings; responses are preserved under `llm_validation_logs/FlowiseAI__Flowise_CVE-2026-41265_2.2.6/`.

## 2026-09-10

- Established the corrective TDD worklist from `TYPESCRIPT_MIGRATION_COMPLIANCE_AUDIT.md` at commit `f8657e0`.
- Confirmed the active branch is `typescript-port` and the tracked worktree is clean before corrective implementation.
- Replaced package-presence, method-name, and keyword heuristics in TypeScript Source discovery with an exact SDK registry and TypeChecker-backed symbol/alias tracking.
- Added regression fixtures for module and local clients, class fields, constructor parameter properties, aliases, destructuring, optional chaining, direct functions, re-exports, and registered client factories.
- Preserved every concrete SDK use during scanning and restored function-level deduplication to the original `confirm_source.py` stage.
- Verified the Source Identification tests in `taintp2x:typescript`; the Flowise checkout also completed a real scan with 53 exact client uses across 19 functions before the client-factory follow-up.
- Changed the CodeQL branch of `make_pysa_source.py` to preserve confirmed file, class, function, range, and stable function identity instead of exporting a global method name.
- Changed generated `LLMControlled` Sources to match calls whose resolved callee is the exact confirmed project function; removed the confirmed attribute-name merge.
- Added a duplicate-name regression test and compiled the generated query with the pinned CodeQL 2.23.2 JavaScript pack.

## 2026-09-11

- Completed the CodeQL compatibility boundary: SARIF paths now retain ordered
  source/intermediate/sink locations, original trace names, and a structured
  `codeql_path` consumed by the existing validators.
- Restored the FullyDeterminer second-stage whole-chain call after per-function
  analysis; Source-stage `response_output.json` no longer prevents the final
  stage from running. Invalid or failed final LLM responses are not serialized
  as fabricated negative determinations.
- Added balanced-brace TypeScript/JavaScript function extraction for Source and
  Fully validation contexts, plus focused adapter and context regression tests.
- Removed unused heuristic `CodeQL_Models/taintp2x_models.json`, the obsolete
  unified `CodeQL_Queries/TaintP2X.ql`, and their configuration entries.

- Replaced the temporary unified CodeQL query with rule-specific query generation driven by the original `taint.config` rule table, preserving the 500x/600x rule identities and messages.
- Added stateful CodeQL flow with the original `FileOperation` state boundary and restored the literal `FromUrlLLMControlled` URL source expression.
- Removed global property-name Source/Sink fallbacks and retained only precise confirmed project Source calls plus official CodeQL security concepts and package-qualified models.
- Made `LLMClient.chat_completion` preserve message roles/order and caller protocol parameters; removed hardcoded validation model names.
- Verified Python regression tests, CodeQL compilation of all 28 generated rules, and CodeQL database evaluation on the Flowise database. The current Flowise run produced no findings because the checked-in Source confirmation artifact contains no confirmed CodeQL Source predicate for the current database run; SARIF-to-original-artifact integration remains pending.
- Added a SARIF-to-`taint-output.json` compatibility adapter and routed CodeQL findings through the original `SourceDeterminer` and `FullyDeterminer` entry points instead of the independent Markdown validator. The adapter preserves issue numbering, source locations, rule ids, and the original stage gate.
- Corrected CodeQL project-function path matching to use `getRelativePath()`'s actual path form and mapped confirmed function returns to `LLMControlled` Source nodes. A direct database query now confirms four Source return nodes in Flowise's confirmed Airtable agent function.
- Removed the independent SARIF Markdown validator and renamed the TypeScript reproduction configuration to `config.json`.
- Updated `REPRODUCTION_GUIDE.md` to describe the rule-directory driver, SARIF compatibility artifact, and original Source/Fully validation stages; removed stale validator commands and old unified-query claims.
- Removed the dead heuristic CodeQL model generator and the remaining attack-entry-point/`Not-Sure` CodeQL validator fallback. TypeScript Source validation now uses the original `is_vulnerability` contract only.
- Reconciled the compliance audit and reproduction guide with the current
  implementation, including the actual zero-finding Flowise CodeQL run and
  the absence of issue-level validation artifacts when no path is reported.
- Made the legacy code-extraction helper use the same runtime-configured LLM
  client and require `OPENAI_MODEL`, removing its embedded provider key/model.
- Added an explicit final compliance-status section to the migration audit and
  verified Python compilation, unit tests, and whitespace checks.
- Added an offline end-to-end regression for the Source gate and Fully stage,
  asserting that the original trace and analysis artifacts are produced.
- Restored the original sanitizer-implementation supplement into the final
  whole-chain prompt instead of silently dropping it during CodeQL adaptation.
- Rebuilt `taintp2x:typescript` and reran the Flowise example from the mounted
  workspace: all 28 generated CodeQL rules compiled and executed, the database
  was created successfully, and the run produced zero CodeQL findings and zero
  issue-level validation artifacts. This confirms the end-to-end execution
  path; the selected Flowise run does not itself require a finding.
- Removed the TypeScript-only Source confirmation limit and the driver shortcut
  that skipped Source Identification when old artifacts existed. The migrated
  driver now follows an all-or-nothing run and regenerates the complete Source
  analysis, confirmation, and model artifacts before every CodeQL run.
