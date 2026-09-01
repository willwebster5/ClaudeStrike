# Changelog

## [Unreleased]

## v0.5.11b1 — beta: `apply` verifies its own writes

Pre-release for validation against a live tenant. `pip install talonctl==0.5.11b1`.

### Fixed

- **`apply` no longer reports success for changes it did not make.** A rename was
  planned, deployed, and reported as `✓ Deployed` while the platform object was
  never modified; state then recorded the intended result as ground truth. Three
  bugs stacked: `_prepare_patch_payload` omitted `name` (citing a rename operation
  that does not exist in the codebase) even though `name` is in `CONTENT_FIELDS`,
  so `plan` kept reporting an update the PATCH silently dropped; `apply` never
  re-read the resource, so an accepted-but-inert PATCH was indistinguishable from
  a successful one; and the remote cache was keyed by rule name, which CrowdStrike
  does not keep unique. `apply_create`/`apply_update` now read the rule back by ID
  and fail loudly, naming the diverging fields, when the platform does not converge
  on the template.
- **Duplicate rule names no longer hide rules.** The name-keyed cache collapsed
  4926 remote rules into 680 entries in the affected tenant, so ID lookups missed
  and name lookups resolved to the wrong object — which is why `drift` output was
  byte-identical before and after a deploy. Added a complete `rule_id` index and
  routed identity resolution in the provider, `drift`, and `sync` through it.
  Shared names are now logged rather than silently collapsed.
- **State records the permanent `rule_id`.** The state synchronizer preferred `id`
  (a per-version ULID that changes on every update), producing entries that stop
  addressing their rule. Both `apply` and `sync` now go through
  `StateSynchronizer.select_persisted_id`.
- **`drift` no longer skips a whole resource type on a legacy state key.**
  `ResourceState(**data)` raised `TypeError` on retired fields, which `drift`
  caught per type and reported as `✗ lookup_file: ...` — lookup_file drift was
  never evaluated. Retired keys are dropped during backfill.
- **Redirected output is plain text.** The shared console forced terminal mode
  whenever colour was not explicitly disabled, so `talonctl drift > report.txt`
  captured a mangled fragment. `force_terminal` is now set only for a real TTY,
  and colour settings are read at call time rather than frozen at import.

### Upgrade note

Deployments that previously reported false success will now fail loudly. Expect the
first run against a drifted tenant to surface real failures rather than silent
no-ops. Sending `name` on PATCH is based on observed API behaviour (a description
propagated from the same request that dropped the name) — verify against a
throwaway rule before promoting this beta.

## v0.5.9 — hotfix: accept case management kinds in schema validator

### Fixed

- **`talonctl validate` now accepts `CaseNotificationGroup`, `CaseSla`, and
  `CaseTemplate` envelopes.** The JSON Schema enum in
  `schemas/envelope.schema.json` was never updated when the three case kinds
  were added to `KIND_TO_TYPE`, causing `validate_authored_envelope()` to
  reject all case management templates with an "is not one of" error. The
  Python code (provider registry, template discovery, `VALID_KINDS`) was
  correct; only the JSON Schema enum was stale.
- **Drift-guard test added** (`test_schema_kind_enum_matches_kind_to_type`)
  that asserts the schema's kind enum exactly matches `KIND_TO_TYPE.keys()`,
  so the two sources of truth cannot diverge again.

## v0.5.8 — case management resources (notification groups, SLAs, templates)

### Added

- **Three new resource types for CrowdStrike Case Management**, managed as v2 IaC
  through the standard lifecycle (validate / plan / apply / import / sync /
  destroy): `case_notification_group`, `case_sla`, and `case_template`. They form
  a dependency chain — notification groups → SLAs → templates — and deploy/destroy
  in that order automatically.
- **Cross-resource references by stable `resource_id`.** A template names its SLA
  via `sla_ref`, and an SLA's escalation steps name a notification group via
  `notification_group_ref`. A new shared `RefResolver` (`core/ref_resolver.py`)
  substitutes the live API id (`sla_id`, `notification_group_id`) at apply time,
  and `extract_dependencies` derives the ordering graph from those refs. Content
  hashing uses the stable ref rather than the resolved API id, so redeploying a
  referenced resource never spuriously marks its dependents as drifted.
- **`import` / `sync` support** for all three types via paginated bulk-fetch, with
  API ids reverse-mapped back to `*_ref` (the raw id is preserved and a warning is
  logged when a sibling cannot be resolved).
- **Reference templates** for the three types in `examples/resources/`, plus
  scaffolding of their directories in `talonctl init` and registration in
  `find --type`.

### Notes

- `drift` does not yet cover the case types, consistent with the existing
  `dashboard` type.

## v0.5.5 — lookup `source:` resolves against the template's project root

### Fixed

- **Lookup-file `source:` CSV/JSON paths no longer resolve relative to the
  current working directory.** Relative sources are authored project-root-relative
  (e.g. `resources/lookup_files/x.csv`) and the data file lives next to the
  templates, so resolving against CWD broke `validate`, `plan`, and `apply`
  whenever talonctl ran from anywhere but the project root — most visibly under
  `--path DIR` invoked from an unrelated directory, which reported every
  relative-source lookup as "source file not found". Resolution now anchors to
  the project root walked up from each template's own location
  (`_template_path`), via a single `LookupFileProvider._resolve_source_path`
  helper shared by `validate_template`, `compute_content_hash`, `apply_create`,
  and `apply_update`. Absolute sources are unchanged; when a template's origin is
  unknown (hand-built dicts), it falls back to the previous CWD-relative
  behavior. Closes the follow-up noted in v0.5.4. Content hashes for existing
  lookups are unaffected (same bytes hashed), so no deploy churn.
  
## v0.5.4 — global `--path` to point at any resources directory

### Added

- **Global `--path DIR` option** on the `talonctl` group: discover resources from
  an arbitrary directory instead of the hardwired `<project-root>/resources`.
  Available to every command (`validate`, `plan`, `apply`, `find`, `show`, `drift`,
  `sync`, `import`, `migrate`, `health`, …) via the shared context, so
  `talonctl --path /opt/detections plan` just works. Default is unchanged, so
  existing repos behave identically. State location is independent — set it with
  `--state-file` (or the `.crowdstrike/` project root); `--path` only governs where
  templates are discovered.

  Note: lookup-file `source:` CSV paths are still resolved relative to the current
  working directory, so running with `--path` from an unrelated CWD can report
  "source file not found" for lookups with relative sources — use absolute `source`
  paths or run from the project for now. Anchoring lookup sources to the resources
  directory is a follow-up.
  
## v0.5.3 — discovery routes resources by kind, not directory

### Changed

- **Template discovery is now kind-routed.** It makes a single recursive pass over
  `resources/` and routes each resource by its own type — v2 by `kind`, v1 by its
  top-level directory (v1 carries no kind). Previously discovery scanned per
  type-directory and **skipped** any resource whose `kind` didn't match its
  directory, which meant a **mixed-kind multi-resource file** (e.g. a lookup grouped
  with the detection that uses it) silently dropped its off-type resources on
  plan/apply — even though the loader and `validate` accepted it. Now a file may
  declare resources of any kind regardless of where it lives, and they all deploy.
  v1 directory routing is unchanged (fully backward compatible); standard one-type-
  per-directory layouts produce identical results.

  Removes the `kind/dir mismatch … skipping` warning (a misplaced v2 resource is now
  routed by kind instead of dropped). `find_template_by_id` resolves across all of
  `resources/` too.

## v0.5.2 — validate: block-scalar whitespace hygiene

### Added

- **`validate` now flags block-unsafe whitespace in v2 templates.** Any multiline
  string value (descriptions, CQL filters, queries) with trailing whitespace on a
  line, or an embedded tab, fails validation with the offending field path. These
  force PyYAML to emit an unreadable quoted `"...\n..."` scalar instead of a clean
  `|` literal block, so the check keeps authored v2 files canonical and catches the
  problem at PR time. Implemented as `check_whitespace_hygiene` in
  `core/envelope_validation.py`, wired into `talonctl validate`.

## v0.5.1 — migrate fidelity: preserve labels, emit block scalars

Bug-fix release hardening `talonctl migrate`'s v1→v2 rewrap so it is lossless and
produces readable v2 templates.

### Fixed

- **List-form `labels` are no longer dropped.** `v1_compat` only recognized
  mapping-style labels; saved searches carry `labels` as a list of strings
  (LogScale's native model), which were silently discarded on rewrap. Because the
  same normalization also feeds the engine's loader, the loss made `plan`/`apply`
  see those labels as absent and try to **strip them from deployed resources**.
  Both shapes (list and mapping) now round-trip, and the v2 envelope schema accepts
  either.
- **Multiline strings serialize as `|` literal blocks** instead of double-quoted
  scalars with `\n` escapes. The serializer hints block style for any string
  containing newlines. It stays strictly lossless: strings PyYAML cannot
  block-represent (trailing whitespace or embedded tabs) fall back to a quoted
  scalar rather than being mutated — so content hashes and deployments do not churn.

## v0.5.0 — v2 authoring layer, State v4, provider refactor, and `talonctl migrate`

The foundation for talonctl v2: a unified Kubernetes-style resource envelope,
`resource_id`-keyed state, and an idempotent migration command. **Backward
compatible** — existing v1 templates and v3 state continue to load unchanged; v2
adoption is opt-in via `talonctl migrate`.

### Added

- **Canonical v2 envelope** (`apiVersion: talon/v2` with `kind`/`metadata`/`spec`/`status`)
  as the in-memory model every resource normalizes to. A dual-read loader
  transparently reads both legacy v1 flat templates and v2 envelopes, so no
  template changes are required to upgrade.
- **Multi-resource files** — a single YAML file may declare one or many
  independent resources (multi-doc `---` or a top-level list), each keyed by its
  own `resource_id`. (There is no `kind: Module`; a file is 1..N independent
  resources.)
- **In-package JSON Schema + schema-driven validator** for the v2 envelope;
  `talonctl validate` understands both v1 and v2 files.
- **State v4** — state is keyed by stable `resource_id`; v3 (name-keyed) state
  auto-migrates in memory on load, non-destructively. A read-only `status`
  projection (`server_id`, `rule_id`, `deployed_at`, `content_hash`) is derived
  from existing state fields; authors cannot write `status`.
- **`talonctl migrate`** — idempotent, dry-run-by-default command that rewrites
  v1 templates to v2 in place and reconciles v3 state to v4:
  - `--write` applies changes (dry-run writes nothing — neither templates nor
    state); `--templates-only` / `--state-only` scope each half;
    `--format json -o FILE` emits a machine-readable report.
  - Reports orphans (state with no template), unmanaged templates (template with
    no state), and conflicts — **report-only; never deletes or creates** resources.
  - Content hashes are preserved byte-for-byte through a rewrap, so already-deployed
    resources do not show as changed on the next `plan`.

### Changed

- All seven providers now consume the canonical `Envelope`; `plan`, `apply`,
  `validate`, and `drift` operate on v1 and v2 templates end-to-end through a
  single parse path.
- API-consumed fields (e.g. `_search_domain`) are classified into `spec`; the v1
  top-level `metadata:` block routes to envelope `metadata`.

### Internal

- New modules: `core/envelope.py`, `core/envelope_loader.py`, `core/v1_compat.py`,
  `core/envelope_validation.py`, `core/envelope_serializer.py`,
  `core/status_projection.py`, `core/migrate.py`; `schemas/envelope.schema.json`.
  `TemplateDiscovery` delegates to the shared envelope loader (one parse path).
- Merge-blocking content-hash stability tests guarantee the v1→v2 transform and
  the serializer never alter a deployed resource's content hash.

### Migration

Run `talonctl migrate` (dry-run) to preview, then `talonctl migrate --write` to
convert templates to v2 and re-key state to v4 in place. Git is the rollback. v1
templates and v3 state continue to work unmigrated; a future release will
announce the v1-reader removal deadline.

## v0.4.0 — `find` command + fleet-wide CQL validation

### Added

- `talonctl find QUERY` — offline identifier resolution (rule_id UUID, resource_id, `ngsiem:` / `fcs:` / `thirdparty:` / `cwpp:` composite IDs, display-name substring, glob). Closes #10.
- `talonctl validate --queries` (`-Q`) — after schema validation passes, CQL-parses every query across detections, saved searches, and dashboards against NGSIEM in parallel. Output anchors each failure at its exact location (`search.filter`, `widgets.<id>.queryString`, `parameters.<id>.query`, or `queryString`). Requires credentials; exits 1 with a documented message when missing. Closes #11.

### Changed

- `NGSIEMClient` error messages no longer emit misleading `"Unknown error"` fallbacks. Rejections now read `LogScale rejected query (status=<N>, no detail returned by API)` when the upstream API returns nothing structured, or pass the payload through verbatim when present.
- Detection query-field precedence (`search.filter` wins over `search.query`) is now consistent across `validate`, `validate-query`, and the plan-path query validator.
- `QueryValidationResult` now carries an optional `location` field used by the formatter to point at the exact widget or field path.

### Internal

- New `talonctl.core.query_collection` module (`QueryRef` + `collect_queries_from_templates`) centralises per-resource-type query-field knowledge.
- New `DeploymentOrchestrator.validate_queries()` method. Plan-path detection validation (`_validate_detection_queries`) is unchanged; broadening it to saved searches and dashboards is tracked as a follow-up.

## v0.3.0 — Metadata Namespace Redesign (BREAKING)

### Breaking changes

- Top-level `ads:` block is removed. Move it under `metadata.ads:`.
- Top-level flat `metadata:` with maturity fields at root is removed. Nest
  fields under `metadata.maturity:`.
- All seven resource types now share a reserved top-level `metadata:`
  namespace that is stripped from API payloads and content hashes. Third-party
  frameworks can add sub-namespaces (e.g. `metadata.<team_name>:`) with a
  guarantee they will never leak to the CrowdStrike/Humio API.

### Migration (before → after)

Before:

```yaml
resource_id: my_detection
name: "My Detection"
ads:
  goal: "Detect something"
  mitre_attack: ["TA0011:T1090.003"]
metadata:
  created: "2026-04-14"
  last_tuned: "2026-04-16"
  tune_count: 2
  confidence: high
severity: 50
search: { ... }
```

After:

```yaml
resource_id: my_detection
name: "My Detection"
metadata:
  maturity:
    created: "2026-04-14"
    last_tuned: "2026-04-16"
    tune_count: 2
    confidence: high
  ads:
    goal: "Detect something"
    mitre_attack: ["TA0011:T1090.003"]
severity: 50
search: { ... }
```

Migration rules (mechanical):

- Top-level `ads:` → `metadata.ads:`.
- Top-level flat `metadata:` with `created` / `last_tuned` / `tune_count` /
  `confidence` at root → `metadata.maturity:` with the same fields inside.
- If both were present, merge into a single `metadata:` with `maturity:` and
  `ads:` sub-namespaces.

No `talonctl migrate` command ships — the corpus is small enough to hand-edit
or rewrite with an editor or assistant.

### Fixed

- Dashboard apply no longer leaks `_template_path` into the Humio schema
  validation payload (closes issue #7). The stripping fix is shared across
  all resource types via `core/template_sanitizer` (shipped in v0.2.1) and
  is now exercised by every provider's payload/hash path.
- Reference templates `examples/resources/lookup_file.yaml`,
  `rtr_put_file.yaml`, and `workflow.yaml` had pre-existing schema bugs
  (missing required fields, wrong field names, broken file paths). These
  are fixed and now exercised by a new parity test.

### Added

- `metadata.maturity:` validation now runs on every resource type, not just
  detections. Schema: `created` (YYYY-MM-DD), `last_tuned` (YYYY-MM-DD or
  null), `tune_count` (non-negative int), `confidence` (low/medium/high/
  validated). All four fields optional.
- `metadata.ads:` remains detection-only. Non-detection providers reject it
  with a clear error pointing at the resource type.
- Third-party frameworks may add arbitrary sub-namespaces under `metadata.`
  (e.g. `metadata.acme_corp:`). These are stripped from API payloads and
  ignored by talonctl; users supply their own validators if needed.
- `tests/unit/test_examples.py` parity test ensures reference YAMLs under
  `examples/resources/` do not drift out of spec.
- `tests/unit/test_old_shape_rejection.py` locks every provider's migration
  pointer error string so a silent refactor can never drop it.

## v0.2.1 — 2026-04-16

### Fixed

- Dashboard apply no longer leaks `_template_path` into the Humio schema
  validation payload (closes #7). `DashboardProvider._prepare_yaml_payload`
  and `_normalize_for_hash` now route through a new
  `core/template_sanitizer` helper that strips `_`-prefixed tool-internal
  keys and the universally-IaC field set `{resource_id, type, dependencies,
  metadata}`. Dashboard-specific transforms (`tags → labels`, `description`
  strip) are preserved unchanged.

### Chore

- Added `.pre-commit-config.yaml` with ruff hooks mirroring the CI lint
  gate. Install with `pre-commit install` after `pip install -e .[dev]`.

### Skipped

- **v0.2.0** was never released to PyPI. Its git tag was pushed malformed
  (`v.0.2.0` with an extra dot) and the release job's VCS-versioning could
  not parse it. The malformed tag remains on the remote — a GitHub
  repository rule blocks tag deletion — but it is orphaned: hatchling's
  VCS versioning cannot parse it, so no release will ever be cut from
  it. v0.2.1 is the first working 0.2.x release.
