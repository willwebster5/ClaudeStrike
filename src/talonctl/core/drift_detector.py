"""
Drift Detector

Three-way comparison between templates (IaC source), state (what we think is deployed),
and remote (what's actually in CrowdStrike) to detect configuration drift.

Categories:
- Config drift: Remote differs from template (manual console edit)
- Missing: In state/template but deleted remotely
- Orphaned: Deployed in CrowdStrike but no IaC template
- Stale state: State entry with no template AND no remote resource
- In sync: Template matches remote
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DriftItem:
    """Single drift finding"""

    resource_type: str
    resource_id: str  # Stable IaC identifier (resource_id / template.name)
    display_name: str
    template_hash: Optional[str] = None
    remote_hash: Optional[str] = None
    field_diffs: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # field_diffs format: { "field_name": { "template": value, "remote": value } }


@dataclass
class DriftReport:
    """Categorized drift detection results"""

    config_drift: List[DriftItem] = field(default_factory=list)
    missing: List[DriftItem] = field(default_factory=list)
    orphaned: List[DriftItem] = field(default_factory=list)
    stale_state: List[DriftItem] = field(default_factory=list)
    in_sync_count: int = 0
    errors: List[str] = field(default_factory=list)
    skipped_types: List[str] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return bool(self.config_drift or self.missing or self.orphaned or self.stale_state)

    @property
    def total_checked(self) -> int:
        return (
            len(self.config_drift) + len(self.missing) + len(self.orphaned) + len(self.stale_state) + self.in_sync_count
        )


class DriftDetector:
    """
    Detects drift between IaC templates, local state, and remote CrowdStrike resources.

    Uses existing provider methods for fetching remote resources and computing
    content hashes, keeping drift detection read-only (never modifies state).
    """

    # Resource types that support bulk remote fetch
    FETCHABLE_TYPES = {"detection", "saved_search", "rtr_script", "rtr_put_file", "workflow", "lookup_file"}

    def __init__(self, falcon_client: Any, state_manager: Any, provider_adapter: Any, template_discovery: Any):
        self.falcon = falcon_client
        self.state_manager = state_manager
        self.provider_adapter = provider_adapter
        self.template_discovery = template_discovery

    def detect(
        self,
        resource_types: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        names: Optional[List[str]] = None,
    ) -> DriftReport:
        """
        Run drift detection across resource types.

        Args:
            resource_types: Filter by resource types (None = all)
            tags: Filter by tags
            names: Filter by name patterns

        Returns:
            DriftReport with categorized findings
        """
        report = DriftReport()

        # Discover templates (respecting filters)
        discovered = self.template_discovery.discover_all(resource_types=resource_types, tags=tags, names=names)

        types_to_check = resource_types if resource_types else list(discovered.keys())

        for resource_type in types_to_check:
            templates = discovered.get(resource_type, [])
            provider = self.provider_adapter.providers.get(resource_type)

            if not provider:
                logger.warning(f"No provider for resource type: {resource_type}")
                report.errors.append(f"No provider for {resource_type}")
                continue

            if resource_type not in self.FETCHABLE_TYPES:
                logger.info(f"Skipping {resource_type} - no bulk remote fetch available")
                report.skipped_types.append(resource_type)
                continue

            try:
                self._detect_for_type(
                    resource_type=resource_type, templates=templates, provider=provider, report=report
                )
            except Exception as e:
                logger.error(f"Error during drift detection for {resource_type}: {e}")
                report.errors.append(f"{resource_type}: {e}")

        return report

    def _detect_for_type(self, resource_type: str, templates: List[Any], provider: Any, report: DriftReport) -> None:
        """
        Three-way drift detection for a single resource type.

        Uses rule_id from state entries to reliably match templates to remote
        resources, with display_name as fallback.
        """
        # 1. Fetch all remote resources (normalized, keyed by name/display_name)
        remote_resources = self._fetch_all_remote(provider, resource_type)
        logger.info(f"Fetched {len(remote_resources)} remote {resource_type} resources")

        # Get raw API data for hash comparison (detections have raw cache)
        # Raw data preserves the original API structure needed for accurate hashing
        remote_raw = {}
        if hasattr(provider, "get_raw_remote_rules"):
            remote_raw = provider.get_raw_remote_rules()

        # Build remote lookup by rule_id for reliable matching.
        # Prefer the provider's complete rule_id index: `remote_resources` is keyed
        # by name, and CrowdStrike names are not unique, so rules sharing a name
        # overwrite each other there. Deriving identity from that index made
        # collapsed duplicates invisible and matched templates to the wrong object.
        remote_by_rule_id = {}
        has_id_index = False
        provider_id_index = getattr(provider, "get_remote_rules_by_id", None)
        if callable(provider_id_index):
            candidate = provider_id_index()
            if isinstance(candidate, dict):
                remote_by_rule_id = candidate
                has_id_index = True
        if not has_id_index:
            for remote_name, remote_data in remote_resources.items():
                rid = remote_data.get("rule_id", "")
                if rid:
                    remote_by_rule_id[rid] = remote_data

        # 2. Get state entries for this type
        state_entries = self.state_manager.get_all_resources(resource_type)
        state_by_name = {}
        for full_id, state in state_entries.items():
            name = full_id.split(".", 1)[1] if "." in full_id else full_id
            state_by_name[name] = state

        # 3. Build template lookups
        template_by_id = {t.name: t for t in templates}
        template_by_display = {t.display_name: t for t in templates if t.display_name and t.display_name != t.name}

        # Track which remote rule_ids are matched (for orphan detection)
        matched_remote_rule_ids = set()

        # 4. Check each template against remote
        for template in templates:
            resource_id = template.name
            display_name = template.display_name or resource_id

            # Compute template hash
            template_hash = provider.compute_content_hash(template.template_data)

            # Find state entry (may be keyed by resource_id or display_name)
            state_entry = state_by_name.get(resource_id)
            if not state_entry:
                state_entry = state_by_name.get(display_name)

            remote_data = None
            raw_data = None

            # Strategy 1: Match via rule_id from state entry (most reliable)
            if state_entry:
                pm = state_entry.provider_metadata if isinstance(state_entry.provider_metadata, dict) else {}
                state_rule_id = pm.get("rule_id", "") or state_entry.id
                if state_rule_id and state_rule_id in remote_by_rule_id:
                    remote_data = remote_by_rule_id[state_rule_id]
                    # The rule_id index holds raw API data; use it directly rather
                    # than re-resolving by name, which is ambiguous.
                    raw_data = remote_data

            # Strategy 2: Match via display_name (fallback)
            if not remote_data:
                remote_data = remote_resources.get(display_name)
                if remote_data:
                    # Use raw API data for hash comparison (same structure as templates)
                    # Fall back to normalized data for non-detection types
                    remote_name = remote_data.get("name", "")
                    raw_data = remote_raw.get(remote_name, remote_data) if remote_raw else remote_data

            if remote_data:
                # Found remotely - track matched rule_id
                rid = remote_data.get("rule_id", "")
                if rid:
                    matched_remote_rule_ids.add(rid)

                # Compare hashes
                remote_hash = provider.compute_content_hash(raw_data)

                if template_hash == remote_hash:
                    report.in_sync_count += 1
                else:
                    # Config drift detected - use raw data for field diffs too
                    diffs = self._compute_field_diffs(template.template_data, raw_data, resource_type)
                    report.config_drift.append(
                        DriftItem(
                            resource_type=resource_type,
                            resource_id=resource_id,
                            display_name=display_name,
                            template_hash=template_hash,
                            remote_hash=remote_hash,
                            field_diffs=diffs,
                        )
                    )
            else:
                # Not found remotely
                if state_entry:
                    # In state but not remote -> missing (deleted from CrowdStrike)
                    report.missing.append(
                        DriftItem(
                            resource_type=resource_type,
                            resource_id=resource_id,
                            display_name=display_name,
                            template_hash=template_hash,
                        )
                    )
                else:
                    # Not in state, not remote -> never deployed (not drift, skip)
                    logger.debug(f"Template {resource_id} not deployed and not in state - skipping")

        # 5. Check for orphaned resources (remote but no template).
        # Walk the complete rule_id index where one exists, so duplicates that the
        # name index dropped are still accounted for. Orphans are identified by
        # rule_id because names are ambiguous — that is what makes them orphans.
        if has_id_index:
            for rid, raw in remote_by_rule_id.items():
                if rid not in matched_remote_rule_ids:
                    report.orphaned.append(
                        DriftItem(
                            resource_type=resource_type,
                            resource_id=rid,
                            display_name=raw.get("name", rid),
                        )
                    )
        else:
            for remote_name, remote_data in remote_resources.items():
                rid = remote_data.get("rule_id", "")
                if rid and rid not in matched_remote_rule_ids:
                    report.orphaned.append(
                        DriftItem(resource_type=resource_type, resource_id=remote_name, display_name=remote_name)
                    )
                elif not rid and remote_name not in template_by_id and remote_name not in template_by_display:
                    report.orphaned.append(
                        DriftItem(resource_type=resource_type, resource_id=remote_name, display_name=remote_name)
                    )

        # 6. Check for stale state entries (in state, no template, no remote)
        remote_rule_ids = set(remote_by_rule_id.keys())
        for state_name, state_entry in state_by_name.items():
            has_template = state_name in template_by_id
            if not has_template and state_entry.display_name:
                has_template = state_entry.display_name in template_by_display

            if has_template:
                continue

            # Check by rule_id first
            pm = state_entry.provider_metadata if isinstance(state_entry.provider_metadata, dict) else {}
            state_rule_id = pm.get("rule_id", "") or state_entry.id
            has_remote = state_rule_id in remote_rule_ids if state_rule_id else False

            if not has_remote:
                has_remote = state_name in remote_resources
            if not has_remote and state_entry.display_name:
                has_remote = state_entry.display_name in remote_resources

            if not has_remote:
                report.stale_state.append(
                    DriftItem(
                        resource_type=resource_type,
                        resource_id=state_name,
                        display_name=state_entry.display_name or state_name,
                    )
                )

    def _fetch_all_remote(self, provider: Any, resource_type: str) -> Dict[str, Dict[str, Any]]:
        """
        Fetch all remote resources of a given type from CrowdStrike.

        Delegates to provider-specific paginated fetch methods.

        Returns:
            Dictionary mapping resource name to remote data
        """
        deployed = {}

        if resource_type == "detection":
            if hasattr(provider, "_fetch_all_remote_rules"):
                deployed = provider._fetch_all_remote_rules()
            else:
                logger.warning("Detection provider missing _fetch_all_remote_rules method")

        elif resource_type == "saved_search":
            if hasattr(provider, "_fetch_all_remote_searches"):
                deployed = provider._fetch_all_remote_searches()
            else:
                logger.warning("Saved search provider missing _fetch_all_remote_searches")

        elif resource_type == "rtr_script":
            if hasattr(provider, "_fetch_all_remote_scripts"):
                deployed = provider._fetch_all_remote_scripts()
            else:
                logger.warning("RTR script provider missing _fetch_all_remote_scripts")

        elif resource_type == "rtr_put_file":
            if hasattr(provider, "_fetch_all_remote_put_files"):
                deployed = provider._fetch_all_remote_put_files()
            else:
                logger.warning("RTR put file provider missing _fetch_all_remote_put_files")

        elif resource_type == "workflow":
            if hasattr(provider, "_fetch_all_remote_workflows"):
                deployed = provider._fetch_all_remote_workflows()
            else:
                logger.warning("Workflow provider missing _fetch_all_remote_workflows")

        elif resource_type == "lookup_file":
            if hasattr(provider, "_fetch_all_remote_lookup_files"):
                deployed = provider._fetch_all_remote_lookup_files()
            else:
                logger.warning("Lookup file provider missing _fetch_all_remote_lookup_files")

        else:
            logger.warning(f"No remote fetch implementation for {resource_type}")

        return deployed

    # Fields that matter for drift comparison per resource type.
    # Only these fields are compared - everything else is API/system metadata.
    DRIFT_FIELDS = {
        "detection": {"name", "description", "severity", "type", "search", "operation", "mitre_attack"},
        "saved_search": {
            "name",
            "description",
            "queryString",
        },
        "rtr_script": {
            "name",
            "description",
            "content",
            "platform",
            "permission_type",
        },
        "rtr_put_file": {
            "name",
            "description",
        },
    }

    # Sub-fields of search that we control via templates
    SEARCH_SUBFIELDS = {"filter", "lookback", "outcome", "trigger_mode", "use_ingest_time", "execution_mode"}

    def _compute_field_diffs(
        self, template_data: Dict[str, Any], remote_data: Dict[str, Any], resource_type: str
    ) -> Dict[str, Dict[str, Any]]:
        """
        Compute field-level differences between template and remote data.

        Only compares explicitly defined content fields (allowlist approach).
        For nested dicts like 'search', compares only IaC-managed sub-fields.

        Returns:
            Dict of { field_name: { "template": value, "remote": value } }
        """
        diffs = {}
        fields_to_check = self.DRIFT_FIELDS.get(resource_type, set(template_data.keys()))

        for field_name in fields_to_check:
            template_value = template_data.get(field_name)
            remote_value = remote_data.get(field_name)

            # Skip if template doesn't define this field
            if template_value is None:
                continue

            # For search dict, compare only IaC-managed sub-fields
            if field_name == "search" and isinstance(template_value, dict) and isinstance(remote_value, dict):
                search_diffs = {}
                for subfield in self.SEARCH_SUBFIELDS:
                    tv = template_value.get(subfield)
                    rv = remote_value.get(subfield)
                    if tv is None:
                        continue
                    t_norm = self._normalize_value(tv)
                    r_norm = self._normalize_value(rv)
                    if t_norm != r_norm:
                        search_diffs[subfield] = {"template": tv, "remote": rv}
                if search_diffs:
                    diffs["search"] = {
                        "template": {k: template_value.get(k) for k in self.SEARCH_SUBFIELDS if k in template_value},
                        "remote": {k: remote_value.get(k) for k in self.SEARCH_SUBFIELDS if k in remote_value},
                        "_sub_diffs": search_diffs,
                    }
                continue

            # For operation dict, compare only schedule
            if field_name == "operation" and isinstance(template_value, dict) and isinstance(remote_value, dict):
                t_sched = template_value.get("schedule")
                r_sched = remote_value.get("schedule") if remote_value else None
                if t_sched and t_sched != r_sched:
                    diffs["operation.schedule"] = {"template": t_sched, "remote": r_sched}
                continue

            # For mitre_attack, normalize both string and dict formats to canonical form
            if field_name == "mitre_attack":
                from talonctl.providers.detection_provider import DetectionProvider

                t_norm = DetectionProvider._normalize_mitre_for_hash(template_value or [])
                r_norm = DetectionProvider._normalize_mitre_for_hash(remote_value or [])
                if t_norm != r_norm:
                    diffs[field_name] = {"template": template_value, "remote": remote_value}
                continue

            # Standard comparison
            t_val = self._normalize_value(template_value)
            r_val = self._normalize_value(remote_value)

            if t_val != r_val and remote_value is not None:
                diffs[field_name] = {"template": template_value, "remote": remote_value}

        return diffs

    @staticmethod
    def _normalize_value(value: Any) -> Any:
        """Normalize a value for comparison (strip whitespace from strings, etc.)"""
        if isinstance(value, str):
            return value.strip()
        return value
