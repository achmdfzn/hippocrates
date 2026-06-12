# Fix Remaining Lint Errors After Refactor

## TL;DR

> **Quick Summary**: Clean up unused imports and types across 4 source files that were left behind during the v1.5 modular refactor.
>
> **Deliverables**:
> - Clean lint output (0 errors) across all `src/` files
> - Remove unused `AnalysisResult`, `DEFAULT_WEIGHTS`, `ZodType`, `z`, `AnalyzerPlugin`, `PipelineResult`
>
> **Estimated Effort**: Quick (5-10 min)
> **Parallel Execution**: YES - 4 parallel edits
> **Critical Path**: Typecheck → Lint → Test

---

## Context

### What's Already Fixed
- `src/engine/analyzers.ts` — All 6 built-in analyzers made into placeholders (fixes **double-counting bug** where L3/L6 scores were counted twice)
- `vitest.config.ts` — Coverage include updated to `src/**/*.ts` excluding tests

### Remaining Lint Errors (12 errors, 3 warnings)

| File | Error | Details |
|------|-------|---------|
| `threat-score-engine.ts` | `AnalysisResult` unused | Imported but never referenced |
| `threat-score-engine.ts` | `DEFAULT_WEIGHTS` unused | Imported but never referenced |
| `types.ts` | `ZodType` unused | Imported but never used in type definitions |
| `index.ts` | `z` unused | Imported on line 87 but re-export is separate `export { z } from "zod"` on line 174 |
| `pipeline.ts` | `AnalyzerPlugin` unused | Imported but never used |
| `pipeline.ts` | `AnalysisResult` unused | Imported but never used |
| `pipeline.ts` | `PipelineResult` unused | Defined private type but never used |
| +3 `no-console` warnings | Console.log/error/warn | Intentional debug logs (suppress) |

### Root Cause
The v1.5 refactor extracted code from `src/index.ts` into `engine/` and `system/` modules. During extraction, some imports remained in the source files but were no longer needed by the extracted code.

---

## Work Objectives

### Core Objective
Clean up 6 unused imports and 1 unused type across 4 source files to achieve zero ESLint errors.

### Definition of Done
- [ ] `npm run lint` → 0 errors (warnings OK)
- [ ] `npm run typecheck` → passes
- [ ] `npm test` → all 123 tests pass

### Must NOT Have
- No behavioral changes — only import/type cleanup
- No console.warn/error removal — those are intentional debug logs

---

## TODOs

- [ ] 1. **threat-score-engine.ts** — Remove unused `AnalysisResult` and `DEFAULT_WEIGHTS`

  **What to do**:
  - Remove `AnalysisResult` from the import list (line 28)
  - Remove `DEFAULT_WEIGHTS` from the import list (line 32)
  - Both are unused in this file after the refactor

  **Files to edit**:
  - `src/engine/threat-score-engine.ts:26-29` (import type block)
  - `src/engine/threat-score-engine.ts:31-32` (import values block)

  **Verification**: `npm run lint` no longer errors on this file

- [ ] 2. **types.ts** — Remove unused `ZodType` import

  **What to do**:
  - Remove `ZodType` from `import type { ZodType } from "zod"` on line 11
  - `NextRequest` and `NextResponse` ARE used, keep them
  - If `ZodType` is the only import from "zod", remove the entire line

  **Files to edit**:
  - `src/engine/types.ts:11`

  **Verification**: `npm run lint` no longer errors on this file

- [ ] 3. **index.ts** — Remove unused `z` import

  **What to do**:
  - Line 87: Change `import { z, ZodType } from "zod"` to `import { ZodType } from "zod"`
  - `ZodType` IS used on line 154 (`schema: ZodType<T>`)
  - The re-export `export { z } from "zod"` on line 174 is a separate import statement, not affected

  **Files to edit**:
  - `src/index.ts:87`

  **Verification**: `npm run lint` no longer errors on this file

- [ ] 4. **pipeline.ts** — Remove unused imports and type

  **What to do**:
  - Remove `AnalyzerPlugin` from the import type block (line 18)
  - Remove `AnalysisResult` from the import type block (line 20)
  - Remove the unused `PipelineResult` type definition (lines 31-33)
  - Keep all other imports (they're used)

  **Files to edit**:
  - `src/system/pipeline.ts:18-22` (import type block)
  - `src/system/pipeline.ts:31-33` (PipelineResult type)

  **Verification**: `npm run lint` no longer errors on this file

---

## Final Verification

- [ ] Run `npm run lint` → 0 errors (warnings may remain for console.log — intentional)
- [ ] Run `npm run typecheck` → clean
- [ ] Run `npm test` → 123/123 pass
- [ ] Run `npm run build` → clean build
