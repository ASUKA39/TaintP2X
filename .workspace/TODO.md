# TypeScript Port TODO

- [x] Replace heuristic TypeScript Source discovery with Compiler API symbol provenance and preserve per-use records.
- [x] Generate precise project-specific CodeQL Sources from confirmed function identities.
- [x] Replace global name models with precise TypeScript Source/Sink models.
- [x] Restore `FromUrlLLMControlled` literal semantics.
- [x] Implement stateful `FileOperation` transform and original rule combinations.
- [x] Remove invented Sanitizers and determine whether an explicit TypeScript equivalent is necessary.
- [x] Restore original `SourceDeterminer` gating on CodeQL paths.
- [x] Restore the complete original `FullyDeterminer` flow and artifact contract.
- [x] Make LLM transport transparent and remove hardcoded model names.
- [x] Remove independent validation/CLI paths and consolidate configuration naming.
- [x] Add focused regression fixtures for each migrated semantic boundary.
- [x] Rebuild the TypeScript image and reproduce the Flowise example from a clean workspace.
- [x] Reconcile `REPRODUCTION_GUIDE.md`, checklist, and compliance audit with verified behavior.
- [x] Remove embedded provider/model configuration from legacy LLM helper code.
- [x] Remove the migration-only Source candidate limit and artifact-based stage skip.
