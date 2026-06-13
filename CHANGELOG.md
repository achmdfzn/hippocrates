# Changelog

## 1.8.0 (2026-06-14)

### Breaking
- Renumber detection layers to match execution order: old L6 (headers, pre-body) is now L4; old L4 (obfuscation, post-body) is now L5; old L5 (schema, post-body) is now L6. Plugin names referencing old layer numbers must be updated.

### Fixes
- Stable sort for `AnalyzerPlugin` registration order. Plugins with the same priority now preserve insertion order via `_registrationIndex` instead of being randomly ordered.
- Remove `build:python` from `prepublishOnly` script. Python toolchain is no longer a publish dependency.
- Remove static fake coverage badge from README.

### Features
- Real coverage via vitest/v8 (`npm run coverage`), with `lcov.info` output and Codecov upload in CI.
- CI pipeline now has a separate `python-tests` job (independent of Node matrix).
- `npm run coverage` script added.
- Redis-persisted `StatsTracker` example in README.
- Plugin use-case examples: rate-limit mimic + scraper detection.

### Docs
- Rewrite README: zero emoji, zero AI-slop, step-by-step tutorial, pairing guide, codebase structure tree, custom violation messages docs.
- Sync CLAUDE.md: update test counts (177→209), CI pipeline diagram, remove emoji.
- Add serverless stats warning to CLAUDE.md.
- Update GitHub repo description: remove emoji and marketing language.
- Clean up package.json keywords: 25→10, remove AI-slop terms.
