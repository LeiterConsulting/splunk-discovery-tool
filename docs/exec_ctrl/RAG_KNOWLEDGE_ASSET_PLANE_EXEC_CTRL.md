# RAG Knowledge Asset Plane exec-ctrl

## Control Summary

| Field | Value |
| --- | --- |
| Initiative | RAG Knowledge Asset Plane |
| Abbrev | `rag-asset` |
| Control system | `exec-ctrl` |
| Overall state | `completed` |
| Current phase | `Phase 15 Close completed` |
| Started | 2026-04-20 |
| Governs | Making introduced RAG assets operator-usable through import, catalog, search, and context preview controls |
| Primary architecture input | `docs/exec_ctrl/OPTIONAL_CAPABILITIES_EXEC_CTRL.md` |

## Objective

Make optional RAG practically usable for operator-introduced knowledge, not just generated discovery artifacts.

This initiative must let an operator introduce updated Splunk documentation, monitored-system context, connected-system context, and integration notes through a visible management plane that supports:

- import
- catalog and lifecycle visibility
- indexed retrieval readiness
- operator-facing context preview before chat use

## Scope In

- managed knowledge-asset storage for `rag_chromadb`
- text import and text-file upload for supported reference assets
- staged PDF upload with deterministic text extraction and page markers
- staged DOCX upload with deterministic heading, paragraph, and table extraction
- asset catalog and delete lifecycle
- indexed context preview built only from managed knowledge assets
- deterministic asset enrichment for focus terms, key points, and usage guidance
- operator-facing context brief explaining why matched assets matter
- single-asset detail inspection with stored-section and chunk-browser views
- preview-to-chunk traceability between matched preview evidence and asset-detail chunk-browser sections
- capability workspace controls and evidence for imported assets
- regression coverage for managed asset flows
- developer-reference and `exec-ctrl` updates for the slice

## Scope Out

- legacy `.doc` or broader binary-document ingestion beyond staged PDF and DOCX extraction
- multi-collection knowledge governance
- LLM-generated ingestion summaries
- cross-asset deduplication or ontology management
- automatic asset extraction from external systems
- replacing core discovery evidence with user-provided knowledge assets

## Deliverables

1. Managed knowledge-asset persistence under the optional Chroma-backed RAG capability
2. Import endpoints for pasted text, supported text-based files, staged PDF uploads, and staged DOCX uploads
3. Asset catalog and delete controls in the `Capabilities` workspace
4. Context preview endpoint and UI showing what indexed managed assets contribute
5. Deterministic operator context brief for managed-asset preview results
6. Updated developer documentation and control records
7. Regression tests covering managed asset import, indexing metadata, preview, and delete
8. Asset-detail and chunk-browser inspection for individual managed knowledge assets
9. Deterministic PDF extraction that keeps uploaded page content visible to operators and retrieval
10. Deterministic DOCX extraction that keeps headings, paragraph content, and simple table rows visible to operators and retrieval
11. Stable preview-to-chunk traceability so operators can map preview evidence back to highlighted chunk-browser sections

## Must-Pass Success Criteria

1. An operator can import a knowledge asset without editing files manually.
2. Imported assets are visibly listed with type, summary, and basic lifecycle metadata.
3. Imported assets can be deleted from the UI-managed plane.
4. `rag_chromadb` can build a context preview sourced only from managed knowledge assets.
5. If indexed retrieval is already enabled, managed asset changes refresh retrieval readiness without a separate hidden step.
6. Capability state surfaces managed asset summary counts without requiring log inspection.
7. Regression tests cover the managed asset slice.
8. Operators can trace current preview evidence back to specific chunk-browser sections without guessing.

## Should-Pass Success Criteria

1. Asset typing distinguishes at least Splunk documentation, monitored-system context, connected-system context, integration context, runbook context, and general reference documents.
2. The management plane makes deferred limitations explicit instead of hiding them.
3. Context previews explain how matched assets should be used, not just which chunks were returned.
4. The slice preserves future room for richer summarization and broader knowledge governance.

## Completion Conditions

- all must-pass success criteria are satisfied
- targeted regression and live validation evidence cover the managed-asset import, detail, preview, and delete flows
- developer-reference and `exec-ctrl` artifacts capture the delivered operator workflow and deferred follow-ons
- broader ingestion and governance backlog items remain explicitly deferred rather than silently extending this initiative

## Execution Process

### Phase 0. Activate

Outputs:

- control pack created
- current RAG limitations recorded

Status:

- `completed`

### Phase 1. Define

Outputs:

- first-slice scope
- success criteria
- non-goals

Status:

- `completed`

### Phase 2. Design

Outputs:

- managed asset model
- capability-manager integration plan
- UI placement in existing capability workspace

Status:

- `completed`

### Phase 3. Build first usable slice

Outputs:

- managed asset import/list/delete support
- context preview endpoint and UI
- capability-state summary additions

Status:

- `completed`

### Phase 4. Validate first usable slice

Outputs:

- targeted regression validation
- doc updates
- follow-on backlog captured

Status:

- `completed`

### Phase 5. Build context-brief slice

Outputs:

- deterministic asset enrichment for focus terms, key points, and usage guidance
- operator context brief for managed-asset preview results
- richer preview evidence in the capability workspace

Status:

- `completed`

### Phase 6. Validate context-brief slice

Outputs:

- targeted regression validation
- live browser validation of the richer preview workflow
- control-record and developer-reference updates

Status:

- `completed`

### Phase 7. Build asset-detail slice

Outputs:

- asset-detail endpoint and capability action
- shared detail panel in the capability workspace
- chunk-browser view derived from the indexing split logic

Status:

- `completed`

### Phase 8. Validate asset-detail slice

Outputs:

- targeted regression validation for asset detail payloads
- live browser validation of detail open, preview-side inspect, and delete-state clearing
- control-record and developer-reference updates

Status:

- `completed`

### Phase 9. Build staged PDF upload slice

Outputs:

- PDF upload support for managed assets
- deterministic PDF text extraction with page markers
- capability-workspace affordance updates for PDF uploads

Status:

- `completed`

### Phase 10. Validate staged PDF upload slice

Outputs:

- targeted regression validation for PDF uploads
- live browser validation of PDF upload, detail inspection, preview retrieval, and delete cleanup
- control-record and developer-reference updates

Status:

- `completed`

### Phase 11. Build staged DOCX upload slice

Outputs:

- DOCX upload support for managed assets
- deterministic DOCX extraction for headings, paragraphs, and simple tables
- capability-workspace affordance updates for DOCX uploads

Status:

- `completed`

### Phase 12. Validate staged DOCX upload slice

Outputs:

- targeted regression validation for DOCX uploads
- live browser validation of DOCX upload, detail inspection, preview retrieval, and delete cleanup
- control-record and developer-reference updates

Status:

- `completed`

### Phase 13. Build preview traceability slice

Outputs:

- stable `document_id` metadata persisted for indexed managed-asset chunks
- context-preview payloads that expose matched chunk identifiers and traceable matched-chunk summaries
- capability-workspace highlighting for chunk-browser sections that powered the current preview

Status:

- `completed`

### Phase 14. Validate preview traceability slice

Outputs:

- targeted regression validation for preview-to-detail chunk traceability
- live browser validation of matched preview evidence, detail highlighting, delete cleanup, and restored zero-asset state
- control-record and developer-reference updates

Status:

- `completed`

### Phase 15. Close

Outputs:

- completion audit recorded
- initiative state marked complete
- deferred ingestion and governance backlog captured for explicit future reopen only

Status:

- `completed`

## Workstreams

| Workstream | Purpose | Status | Evidence |
| --- | --- | --- | --- |
| WS1 Managed asset persistence | Store imported knowledge assets with metadata and summaries | `completed` | `src/capabilities/rag/asset_manager.py`, `src/capabilities/rag/indexer.py` |
| WS2 Capability orchestration | Route import/list/delete/context-preview through capability controls | `completed` | `src/capabilities/install_manager.py`, `src/web_app.py` |
| WS3 Operator management plane | Add asset import, catalog, and preview controls to the capability workspace | `completed` | `src/web_app.py` |
| WS4 Validation and docs | Add regression coverage and control documentation | `completed` | `tests/test_capability_framework.py`, `docs/DEVELOPER_REFERENCE.md`, this control pack, live browser validation of import/preview/delete |
| WS5 Context briefing | Enrich imported assets and build operator-facing context briefs | `completed` | `src/capabilities/rag/asset_manager.py`, `src/capabilities/rag/indexer.py`, `src/web_app.py`, `tests/test_capability_framework.py`, live browser validation of enriched preview output |
| WS6 Asset detail inspection | Let operators inspect one asset's stored sections and chunk splits inside the capability workspace | `completed` | `src/capabilities/rag/asset_manager.py`, `src/capabilities/rag/indexer.py`, `src/capabilities/install_manager.py`, `src/web_app.py`, `tests/test_capability_framework.py`, live browser validation of detail open, inspect routing, and delete clearing |
| WS7 Staged PDF ingestion | Accept PDF uploads, extract deterministic text, and keep the result visible in asset detail and retrieval preview | `completed` | `src/capabilities/rag/asset_manager.py`, `src/web_app.py`, `requirements.txt`, `tests/test_capability_framework.py`, live browser validation of PDF upload/detail/preview/delete |
| WS8 Staged DOCX ingestion | Accept DOCX uploads, extract deterministic structure, and keep the result visible in asset detail and retrieval preview | `completed` | `src/capabilities/rag/asset_manager.py`, `src/web_app.py`, `requirements.txt`, `tests/test_capability_framework.py`, live browser validation of DOCX upload/detail/preview/delete |
| WS9 Preview traceability | Let operators map preview evidence back to the exact chunk-browser sections used by retrieval | `completed` | `src/capabilities/rag/indexer.py`, `src/web_app.py`, `tests/test_capability_framework.py`, live browser validation of matched chunk badges, highlighted chunk-browser sections, and delete cleanup |

## Risks and Dependencies

1. `src/web_app.py` remains large, so this initiative should continue extending existing capability patterns rather than creating parallel control surfaces.
2. Broader document ingestion beyond staged PDF and DOCX extraction would expand parser and security scope significantly.
3. User trust depends on visible retrieval evidence; hidden indexing alone is not sufficient.
4. Preview traceability depends on index metadata schema staying aligned with UI expectations, so retrieval-facing schema shifts must continue forcing safe reindex behavior.

## Follow-On Backlog

1. Evaluate legacy `.doc`, spreadsheets, and other richer source ingestion only after staged DOCX upload behavior proves stable in real operator use.
2. Consider richer inline section highlighting or per-chunk explanation beyond the current chunk-browser traceability only if operator demand proves it necessary.
3. Consider deeper governance features such as deduplication, ontology tagging, or multi-collection segmentation only if the initiative is intentionally reopened.

## Current Status

What is complete now:

- managed knowledge assets can be imported as pasted text, supported text-based files, staged PDF uploads, and staged DOCX uploads
- imported assets are persisted with metadata and deterministic summaries under the RAG capability plane
- `rag_chromadb` now exposes asset catalog, delete, and context-preview controls in the `Capabilities` workspace
- indexed context previews are operator-visible and limited to managed knowledge assets for this slice
- managed assets now persist deterministic focus terms, key points, and usage guidance to improve retrieval evidence and operator review
- managed asset preview/search flows now self-heal stale derived enrichment by refreshing stored asset sections and reindexing before retrieval when managed asset content drifts from the index
- context previews now include an operator context brief, match rationale, and basic gap signaling instead of raw chunk output alone
- operators can now open a shared asset-detail panel from either the asset catalog or preview matches to inspect stored sections and chunk-browser splits for one managed asset
- uploaded PDFs are converted into deterministic page-marked text so stored sections, chunk-browser output, and preview retrieval all expose the same operator-visible content
- uploaded DOCX files are converted into deterministic heading, paragraph, and table text so stored sections, chunk-browser output, and preview retrieval all expose the same operator-visible content
- targeted regression validation passes for the managed asset flows in `tests/test_capability_framework.py`
- live browser validation confirmed preview-to-chunk traceability, shared asset detail inspection, delete cleanup, and clean zero-asset end state in the running app
- the initiative now satisfies all must-pass success criteria and is closed under `exec-ctrl`

What remains open:

- legacy `.doc`, spreadsheet, and broader binary-document ingestion remain deferred follow-on scope
- richer inline explanation beyond the current chunk-browser traceability remains optional future refinement
- deeper governance features such as deduplication, ontology tagging, or multi-collection segmentation remain future backlog only if the initiative is intentionally reopened

## Validation Evidence

- `c:/Temp/splunk-discovery-tool/.venv/Scripts/python.exe -m unittest tests.test_chat_and_llm_helpers tests.test_capability_framework -v`
- live browser validation of import, preview, asset detail, staged PDF upload, staged DOCX upload, preview-to-chunk traceability, delete cleanup, and restored zero-asset state in the running app
- `docs/DEVELOPER_REFERENCE.md`
- `docs/exec_ctrl/RAG_KNOWLEDGE_ASSET_PLANE_AUDIT_LOG.md`
- `docs/exec_ctrl/RAG_KNOWLEDGE_ASSET_PLANE_DECISION_LOG.md`