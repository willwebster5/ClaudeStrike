"""
Detection Provider - CrowdStrike NGSIEM Detection Rules

This provider implements the BaseResourceProvider interface for managing
CrowdStrike NGSIEM detection rules as Infrastructure as Code resources.
"""

import json
import hashlib
import logging
import time
from typing import Dict, List, Optional, Any, Tuple, TYPE_CHECKING
from datetime import datetime, timezone

from talonctl.core.base_provider import BaseResourceProvider, ResourceAction, ResourceChange

if TYPE_CHECKING:
    from talonctl.core.envelope import Envelope
from talonctl.core.deployment_strategies import DeploymentStrategyFactory
from talonctl.core.metadata_validators import reject_old_shape, validate_maturity
from talonctl.core.template_sanitizer import strip_for_api, strip_for_hash
from talonctl.utils.mitre_processor import MitreProcessor

logger = logging.getLogger(__name__)

# Backoff schedule (seconds) for post-apply read-back verification. The API is
# eventually consistent, so a write may not be visible on the first re-read.
VERIFY_BACKOFF = [0.5, 1, 2, 4]


class DetectionProvider(BaseResourceProvider):
    """
    Provider for CrowdStrike NGSIEM Detection Rules

    Manages detection rules as IaC resources with support for:
    - Template validation
    - Remote state fetching from CrowdStrike API
    - Change detection and planning
    - Rule creation and updates
    - Dependency extraction from FQL queries
    """

    def __init__(self, falcon_client: Any, config: Optional[Dict[str, Any]] = None):
        """
        Initialize detection provider

        Args:
            falcon_client: Authenticated FalconPy APIHarnessV2 instance
            config: Optional provider configuration (including credentials with customer_id)
        """
        self.falcon = falcon_client
        self.config = config or {}
        self.timeout = self.config.get("timeout", 30)
        self._remote_rules_cache: Optional[Dict[str, Dict[str, Any]]] = None
        self._remote_rules_raw_cache: Optional[Dict[str, Dict[str, Any]]] = None
        # Complete raw index keyed by rule_id. Rule names are NOT unique in
        # CrowdStrike, so the name-keyed caches above lose every duplicate.
        self._remote_rules_by_id: Optional[Dict[str, Dict[str, Any]]] = None

        # Extract customer_id from credentials if available
        creds = self.config.get("credentials", {})
        self.customer_id = creds.get("customer_id") if creds else None

    def get_resource_type(self) -> str:
        """Return resource type identifier"""
        return "detection"

    def _validate_ads_ref_dict(self, ref: Dict[str, Any], field_path: str) -> List[str]:
        """
        Validate a {path, label?} ref dict used inside ads.false_positives,
        ads.validation, and ads.response.

        Args:
            ref: The dict to validate.
            field_path: Breadcrumb for error messages (e.g. "ads.false_positives[2]").

        Returns:
            List of error message strings (empty if valid).
        """
        errs: List[str] = []
        unknown = set(ref.keys()) - self.ADS_REF_ALLOWED_KEYS
        if unknown:
            errs.append(
                f"Unknown ref dict key(s) in {field_path}: {', '.join(sorted(unknown))}. Known keys: path, label"
            )
        if "path" not in ref:
            errs.append(f"{field_path} ref dict missing required 'path' key")
        else:
            path = ref["path"]
            if not isinstance(path, str):
                errs.append(f"{field_path}.path must be a string (got {type(path).__name__})")
            elif not path.strip():
                errs.append(f"{field_path}.path must be a non-empty string")
            elif any(c.isspace() for c in path):
                errs.append(f"{field_path}.path must not contain whitespace (got {path!r})")
        if "label" in ref:
            label = ref["label"]
            if not isinstance(label, str):
                errs.append(f"{field_path}.label must be a string (got {type(label).__name__})")
            elif not label.strip():
                errs.append(f"{field_path}.label must be a non-empty string")
        return errs

    def validate_template(self, env: "Envelope") -> List[str]:
        """
        Validate detection rule template

        Supports both legacy and new template formats:
        - Legacy: search.filter, lookback, trigger_mode, tactic/technique top-level
        - New: search.query, search_window, mitre_attack array

        Args:
            env: Detection rule Envelope

        Returns:
            List of validation error messages (empty if valid)
        """
        template = env.to_working_dict()
        errors = []

        # v0.3.0: reject pre-v0.3.0 shapes before running relocated validators so users
        # see the migration pointer instead of a cascade of format errors.
        errors.extend(reject_old_shape(template))

        # v0.3.0: universal maturity validation (reads template["metadata"]["maturity"]).
        errors.extend(validate_maturity(template))

        # Required fields
        required_fields = ["name", "description", "severity", "search"]
        for field in required_fields:
            if field not in template:
                errors.append(f"Missing required field: {field}")

        # Validate severity
        severity = template.get("severity")
        valid_severities = [10, 30, 50, 70, 90]
        if severity and severity not in valid_severities:
            errors.append(f"Invalid severity: {severity}. Must be one of {valid_severities}")

        # Validate search section (supports both legacy and new formats)
        search = template.get("search", {})
        if not isinstance(search, dict):
            errors.append("'search' must be a dictionary")
        else:
            # Check for query OR filter (legacy format uses 'filter')
            has_query = "query" in search or "filter" in search
            if not has_query:
                errors.append("Missing 'query' or 'filter' in search section")

            # Validate search fields (accept both legacy and new format fields)
            valid_search_fields = [
                # New format fields
                "query",
                "query_id",
                "use_ingest_time",
                "search_window",
                "search_window_unit",
                "group_by",
                "having",
                # Legacy format fields
                "filter",
                "lookback",
                "trigger_mode",
                "outcome",
                # Behavioral/correlate rule fields
                "execution_mode",
            ]
            invalid_fields = [k for k in search.keys() if k not in valid_search_fields]
            if invalid_fields:
                errors.append(f"Invalid search fields: {', '.join(invalid_fields)}")

        # Validate status if present
        status = template.get("status", "active")
        if status not in ["active", "inactive"]:
            errors.append(f"Invalid status: {status}. Must be 'active' or 'inactive'")

        # Validate MITRE ATT&CK (supports string format, dict format, and legacy top-level fields)
        mitre = template.get("mitre_attack")
        if mitre:
            if not isinstance(mitre, list):
                errors.append("'mitre_attack' must be a list")
            else:
                for idx, entry in enumerate(mitre):
                    if isinstance(entry, str):
                        # String format: "Tactic (TAxxxx):Technique (Txxxx)" - valid
                        pass
                    elif isinstance(entry, dict):
                        if (
                            "tactic" not in entry
                            and "technique" not in entry
                            and "tactic_id" not in entry
                            and "technique_id" not in entry
                        ):
                            errors.append(
                                f"mitre_attack[{idx}] must have 'tactic', 'technique', 'tactic_id', or 'technique_id'"
                            )
                    else:
                        errors.append(f"mitre_attack[{idx}] must be a string or dictionary")

        # Legacy format: top-level tactic/technique fields are also valid
        # No validation needed - these are optional

        # v0.3.0: ADS metadata relocated to template["metadata"]["ads"] (was top-level ads:).
        # Internal shape rules (goal required, ref-dict vs inline-FP, etc.) unchanged.
        # Schema: docs/superpowers/specs/2026-04-16-metadata-namespace-redesign-design.md.
        metadata_block = template.get("metadata")
        ads = metadata_block.get("ads") if isinstance(metadata_block, dict) else None
        if ads is not None:
            if not isinstance(ads, dict):
                errors.append("'metadata.ads' must be a dictionary")
            else:
                # Required fields (goal) when ads: is present.
                for field in self.ADS_REQUIRED_FIELDS:
                    val = ads.get(field)
                    if not val or (isinstance(val, str) and not val.strip()):
                        errors.append(f"ads.{field} is required when ads block is present")

                # Reject unknown top-level ads keys.
                unknown = set(ads.keys()) - self.ADS_ALLOWED_FIELDS
                if unknown:
                    errors.append(f"Unknown ads fields: {', '.join(sorted(unknown))}")

                # Type-check pure list fields (must be lists).
                for field in self.ADS_LIST_FIELDS:
                    if field in ads and not isinstance(ads[field], list):
                        errors.append(f"ads.{field} must be a list")

                # Type-check pure string fields.
                for field in self.ADS_STRING_FIELDS:
                    if field in ads and not isinstance(ads[field], str):
                        errors.append(f"ads.{field} must be a string")

                # Per-entry validation for false_positives (list of string | inline-FP-dict | ref-dict).
                fp_list = ads.get("false_positives")
                if isinstance(fp_list, list):
                    for idx, entry in enumerate(fp_list):
                        path_tag = f"ads.false_positives[{idx}]"
                        if isinstance(entry, str):
                            # Legacy/current inline-string ref form; accepted.
                            continue
                        if isinstance(entry, dict):
                            if "path" in entry or (entry.keys() & self.ADS_REF_ALLOWED_KEYS):
                                # Ref-dict form: has 'path', or uses any ref-dict key
                                # (e.g. {'label': 'orphan'} — missing 'path'). This is
                                # safe because ADS_REF_ALLOWED_KEYS {path, label} and
                                # ADS_FP_INLINE_ALLOWED_KEYS {pattern, characteristics,
                                # tuning, status} are disjoint, so no dict is ambiguous.
                                errors.extend(self._validate_ads_ref_dict(entry, path_tag))
                            else:
                                # Inline FP dict form — strict key set.
                                unknown_inline = set(entry.keys()) - self.ADS_FP_INLINE_ALLOWED_KEYS
                                if unknown_inline:
                                    known = ", ".join(sorted(self.ADS_FP_INLINE_ALLOWED_KEYS))
                                    errors.append(
                                        f"Unknown inline FP dict key(s) in {path_tag}: "
                                        f"{', '.join(sorted(unknown_inline))}. Known keys: {known}"
                                    )
                        else:
                            errors.append(
                                f"{path_tag} must be a string, inline FP dict, or ref dict ({{path, label?}})"
                            )

                # Per-entry validation for validation (list of string | ref-dict; no inline-dict form).
                val_list = ads.get("validation")
                if isinstance(val_list, list):
                    for idx, entry in enumerate(val_list):
                        path_tag = f"ads.validation[{idx}]"
                        if isinstance(entry, str):
                            continue
                        if isinstance(entry, dict):
                            # Only ref-dict form allowed. _validate_ads_ref_dict reports
                            # missing-path and unknown-key errors; no inline-dict form is
                            # defined for this field, so those errors are sufficient.
                            errors.extend(self._validate_ads_ref_dict(entry, path_tag))
                        else:
                            errors.append(f"{path_tag} must be a string or ref dict ({{path, label?}})")

                # Type-union validation for response (string | ref-dict).
                if "response" in ads:
                    response = ads["response"]
                    if isinstance(response, str):
                        pass  # string form is fine
                    elif isinstance(response, dict):
                        errors.extend(self._validate_ads_ref_dict(response, "ads.response"))
                    else:
                        errors.append("ads.response must be a string or ref dict ({path, label?})")

        return errors

    def fetch_remote_state(self, resource_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch current state of a detection rule from CrowdStrike API

        Args:
            resource_id: The rule_id of the detection

        Returns:
            Current rule state or None if not found
        """
        try:
            # Use cached rules if available
            if self._remote_rules_cache is None:
                self._fetch_all_remote_rules()

            # Resolve against the complete rule_id index. The name index is lossy:
            # rules sharing a name overwrite each other, which previously made
            # collapsed rules invisible and sent lookups to the wrong object.
            raw = (self._remote_rules_by_id or {}).get(resource_id)
            if raw is not None:
                return self._normalize_rule(raw)

            # If not found in cache, try direct fetch
            response = self.falcon.command("entities_rules_get_v1", ids=[resource_id])

            if response["status_code"] == 200 and response["body"]["resources"]:
                rule = response["body"]["resources"][0]
                return self._normalize_rule(rule)

            return None

        except Exception as e:
            logger.error(f"Failed to fetch rule {resource_id}: {e}")
            return None

    def _fetch_all_remote_rules(self) -> Dict[str, Dict[str, Any]]:
        """Fetch all deployed detection rules from CrowdStrike API with pagination.

        Stores both normalized (for plan/apply) and raw (for drift/hash comparison)
        caches. The normalized cache is returned and used as the primary cache.
        """
        try:
            all_rules = {}
            all_rules_raw = {}
            all_rules_by_id = {}
            duplicate_names = {}
            offset = 0
            limit = 1000  # API max per page
            total_fetched = 0

            # Pagination loop to fetch ALL rules (handles 2000+ rules)
            while True:
                response = self.falcon.command("combined_rules_get_v2", limit=limit, offset=offset, sort="name.asc")

                if response["status_code"] != 200:
                    logger.error(f"Failed to query rules at offset {offset}: {response}")
                    break

                rules = response["body"]["resources"]
                if not rules:
                    break  # No more rules to fetch

                # Index by rule_id (complete) and by name (lossy — names are not
                # unique in CrowdStrike, so the name index keeps only the last rule
                # of each name and MUST NOT be used to resolve an ID).
                for rule in rules:
                    rule_id = rule.get("rule_id") or rule.get("id")
                    if rule_id:
                        all_rules_by_id[rule_id] = rule

                    rule_name = rule.get("name", "")
                    if rule_name:
                        if rule_name in all_rules_raw:
                            duplicate_names[rule_name] = duplicate_names.get(rule_name, 1) + 1
                        all_rules_raw[rule_name] = rule
                        all_rules[rule_name] = self._normalize_rule(rule)

                # Check pagination metadata
                pagination = response["body"].get("meta", {}).get("pagination", {})
                total = pagination.get("total", 0)
                offset += len(rules)
                total_fetched += len(rules)

                logger.debug(f"Fetched {total_fetched}/{total} rules from CrowdStrike")

                # Stop if we've fetched all rules
                if total > 0 and offset >= total:
                    break

                # Safety check: if this page returned fewer rules than limit, we're done
                if len(rules) < limit:
                    break

            logger.info(
                f"Cached {len(all_rules)} rules by name, {len(all_rules_by_id)} by ID "
                f"from CrowdStrike (fetched {total_fetched} total)"
            )
            if duplicate_names:
                shared = sum(duplicate_names.values())
                worst = sorted(duplicate_names.items(), key=lambda kv: -kv[1])[:5]
                logger.warning(
                    f"{len(duplicate_names)} rule name(s) are shared by {shared} rules in this tenant. "
                    f"Name-based matching is ambiguous for these; resolve rules by ID. "
                    f"Most duplicated: {', '.join(f'{n} x{c}' for n, c in worst)}"
                )
            self._remote_rules_cache = all_rules
            self._remote_rules_raw_cache = all_rules_raw
            self._remote_rules_by_id = all_rules_by_id
            return all_rules

        except Exception as e:
            logger.error(f"Failed to fetch deployed rules: {e}")
            self._remote_rules_cache = {}
            self._remote_rules_raw_cache = {}
            self._remote_rules_by_id = {}
            return {}

    def get_remote_rules_by_id(self) -> Dict[str, Dict[str, Any]]:
        """Get raw API data for all remote rules, keyed by rule_id.

        Unlike the name-keyed cache this index is complete: CrowdStrike allows
        duplicate rule names, so the name index silently drops every rule but the
        last of each name. Anything matching on identity must use this.
        """
        if self._remote_rules_by_id is None:
            self._fetch_all_remote_rules()
        return self._remote_rules_by_id or {}

    def get_raw_remote_rules(self) -> Dict[str, Dict[str, Any]]:
        """Get raw (un-normalized) API data for all remote rules.

        Must be called after _fetch_all_remote_rules() has populated the cache.
        Raw data preserves the original API structure (search dict, operation dict, etc.)
        which is needed for accurate hash comparison in drift detection.
        """
        if self._remote_rules_raw_cache is None:
            self._fetch_all_remote_rules()
        return self._remote_rules_raw_cache or {}

    def _normalize_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize rule from API response format"""
        # DEBUG: Log raw API response
        logger.debug(f"[DEBUG] _normalize_rule input keys: {list(rule.keys())}")
        logger.debug(f"[DEBUG] Raw status field: '{rule.get('status')}'")
        logger.debug(f"[DEBUG] Raw rule_id field: '{rule.get('rule_id')}', id field: '{rule.get('id')}'")

        # Extract search config
        search_config = {}
        if "query" in rule:
            search_config["query"] = rule["query"]
        if "query_id" in rule:
            search_config["query_id"] = rule["query_id"]
        if "use_ingest_time" in rule:
            search_config["use_ingest_time"] = rule["use_ingest_time"]
        if "search_window" in rule:
            search_config["search_window"] = rule["search_window"]
        if "search_window_unit" in rule:
            search_config["search_window_unit"] = rule["search_window_unit"]
        if "group_by" in rule:
            search_config["group_by"] = rule["group_by"]
        if "having" in rule:
            search_config["having"] = rule["having"]

        # CRITICAL: Always use rule_id (permanent identifier), never version_id
        # rule_id is permanent and doesn't change across rule updates
        # id/version_id changes with each update and causes "not found" errors
        rule_id = rule.get("rule_id") or rule.get("id")

        normalized = {
            "name": rule.get("name", ""),
            "description": rule.get("description", ""),
            "severity": rule.get("severity", 10),
            "status": rule.get("status", "active"),
            "search": search_config,
            "rule_id": rule_id,  # PERMANENT identifier
        }

        # Add rule type if present (e.g., 'behavioral' for correlate rules)
        if "type" in rule:
            normalized["type"] = rule["type"]

        # Add MITRE ATT&CK if present
        if "mitre_attack" in rule:
            normalized["mitre_attack"] = rule["mitre_attack"]

        # DEBUG: Log normalized output
        logger.debug(f"[DEBUG] Normalized status: '{normalized['status']}'")
        logger.debug(f"[DEBUG] Normalized rule_id (PERMANENT): '{normalized['rule_id']}'")

        return normalized

    def plan_create(self, env: "Envelope", template_path: str) -> ResourceChange:
        """
        Plan creation of a new detection rule

        Args:
            env: Rule Envelope
            template_path: Path to template file

        Returns:
            ResourceChange describing the creation
        """
        template = env.to_working_dict()
        return ResourceChange(
            action=ResourceAction.CREATE,
            resource_type=self.get_resource_type(),
            resource_name=template["name"],
            resource_id=None,
            old_value=None,
            new_value=template,
            changes=None,
            template_path=template_path,
            envelope=env,
        )

    def plan_update(self, env: "Envelope", current_state: Dict[str, Any], template_path: str) -> ResourceChange:
        """
        Plan update of an existing detection rule

        Args:
            env: New rule Envelope
            current_state: Current deployed rule state
            template_path: Path to template file

        Returns:
            ResourceChange describing the update or no-change
        """
        template = env.to_working_dict()
        # Calculate hashes to detect changes
        template_hash = self.compute_content_hash(template)
        current_hash = self.compute_content_hash(current_state)

        if template_hash == current_hash:
            return ResourceChange(
                action=ResourceAction.NO_CHANGE,
                resource_type=self.get_resource_type(),
                resource_name=template["name"],
                resource_id=current_state.get("rule_id"),
                old_value=current_state,
                new_value=template,
                changes=None,
                template_path=template_path,
                envelope=env,
            )

        # Detect specific field changes
        changes = self._detect_field_changes(template, current_state)

        return ResourceChange(
            action=ResourceAction.UPDATE,
            resource_type=self.get_resource_type(),
            resource_name=template["name"],
            resource_id=current_state.get("rule_id"),
            old_value=current_state,
            new_value=template,
            changes=changes,
            template_path=template_path,
            envelope=env,
        )

    def _detect_field_changes(self, new: Dict[str, Any], old: Dict[str, Any]) -> Dict[str, Any]:
        """Detect specific field changes between templates"""
        changes = {}

        # Check simple fields
        simple_fields = ["name", "description", "severity", "status", "type"]
        for field in simple_fields:
            new_val = new.get(field)
            old_val = old.get(field)
            if new_val != old_val:
                changes[field] = {"old": old_val, "new": new_val}

        # Check search config
        new_search = new.get("search", {})
        old_search = old.get("search", {})
        search_changes = {}

        for key in set(new_search.keys()) | set(old_search.keys()):
            new_val = new_search.get(key)
            old_val = old_search.get(key)
            if new_val != old_val:
                search_changes[key] = {"old": old_val, "new": new_val}

        if search_changes:
            changes["search"] = search_changes

        # Check MITRE ATT&CK
        new_mitre = new.get("mitre_attack")
        old_mitre = old.get("mitre_attack")
        if new_mitre != old_mitre:
            changes["mitre_attack"] = {"old": old_mitre, "new": new_mitre}

        return changes

    def requires_replacement(self, template: Dict[str, Any], current_state: Dict[str, Any]) -> Optional[str]:
        """
        Check if a template change requires delete+recreate instead of update.

        Some fields are immutable in the CrowdStrike API (e.g., rule 'type').
        Changing these requires deleting the existing rule and creating a new one.

        Returns:
            Reason string if replacement is needed, None otherwise
        """
        for field in self.IMMUTABLE_FIELDS:
            new_val = template.get(field)
            # Look in provider_metadata for the actual API rule type.
            # current_state['type'] is the resource category ('detection'),
            # NOT the rule type ('behavioral'/'correlation').
            old_val = current_state.get("provider_metadata", {}).get(field)
            # Only trigger replacement when both values are explicitly set and differ.
            # If the template doesn't set 'type', or provider_metadata is missing, skip.
            if new_val and old_val and new_val != old_val:
                return f"'{field}' changed from '{old_val}' to '{new_val}' (immutable, requires replacement)"
        return None

    def plan_delete(self, resource_id: str, resource_name: str) -> ResourceChange:
        """
        Plan deletion of a detection rule

        Args:
            resource_id: Rule ID to delete
            resource_name: Rule name

        Returns:
            ResourceChange describing the deletion
        """
        # Fetch current state for context
        current_state = self.fetch_remote_state(resource_id)

        return ResourceChange(
            action=ResourceAction.DELETE,
            resource_type=self.get_resource_type(),
            resource_name=resource_name,
            resource_id=resource_id,
            old_value=current_state,
            new_value=None,
            changes=None,
            template_path=None,
        )

    def apply_create(self, env: "Envelope") -> Dict[str, Any]:
        """
        Create a detection rule in CrowdStrike

        Args:
            env: Rule Envelope

        Returns:
            Created rule metadata including rule_id (PERMANENT identifier)
        """
        template = env.to_working_dict()
        # Prepare payload
        payload = self._prepare_rule_payload(template)

        # Create rule
        response = self.falcon.command("entities_rules_post_v1", body=payload)

        if response["status_code"] not in (200, 201):
            raise RuntimeError(f"Failed to create rule '{template['name']}': {response}")

        rule_info = response["body"]["resources"][0]

        # CRITICAL: Extract rule_id (permanent), not id (version_id)
        rule_id = rule_info.get("rule_id") or rule_info.get("id")

        logger.info(f"Created rule '{template['name']}' with rule_id: {rule_id}")
        logger.debug(f"[DEBUG] Create response rule_id: {rule_info.get('rule_id')}, id: {rule_info.get('id')}")

        verified = self._verify_applied(rule_id, template, "create")
        self._refresh_cache_entry(verified)

        return {
            "rule_id": rule_id,  # PERMANENT identifier
            "name": verified.get("name", ""),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "verified": True,
            "response": verified,
        }

    def _wait_for_rule_status(self, resource_id: str, expected_status: str, max_wait: int = 30) -> bool:
        """
        Poll for rule status change with exponential backoff

        Args:
            resource_id: Rule ID to check
            expected_status: Expected status (active/inactive/stopped/running)
            max_wait: Maximum wait time in seconds (default: 30)

        Returns:
            True if status reached, False if timeout
        """
        import time

        wait_times = [0.5, 1, 2, 4, 8]  # Exponential backoff
        total_waited = 0
        expected_normalized = expected_status.lower()

        for wait in wait_times:
            if total_waited >= max_wait:
                logger.warning(
                    f"Timeout waiting for rule {resource_id} to reach status '{expected_status}' "
                    f"(waited {total_waited}s)"
                )
                return False

            # Fetch current rule state
            rule = self.fetch_remote_state(resource_id)
            if rule:
                current_status = rule.get("status", "").lower()
                if current_status == expected_normalized:
                    logger.debug(f"Rule {resource_id} reached status '{expected_status}' after {total_waited}s")
                    return True

                logger.debug(
                    f"Rule {resource_id} status is '{current_status}', "
                    f"waiting for '{expected_status}' (waited {total_waited}s)..."
                )

            time.sleep(wait)
            total_waited += wait

        # Final check after all retries
        rule = self.fetch_remote_state(resource_id)
        if rule:
            current_status = rule.get("status", "").lower()
            if current_status == expected_normalized:
                logger.debug(f"Rule {resource_id} reached status '{expected_status}' after {total_waited}s")
                return True

        logger.warning(f"Rule {resource_id} did not reach status '{expected_status}' within {max_wait}s timeout")
        return False

    def apply_update(self, resource_id: str, env: "Envelope", current_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update a detection rule in CrowdStrike.

        Uses deployment strategies to handle multi-phase deployments required
        by CrowdStrike API restrictions (e.g., activating with schedule changes,
        deactivating, or updating stopped rules with schedule changes).

        Args:
            resource_id: Rule ID to update
            env: New rule Envelope
            current_state: Current rule state (for comparison)

        Returns:
            Updated rule metadata
        """
        template = env.to_working_dict()
        # IMPORTANT: current_state from orchestrator contains state file metadata,
        # NOT actual rule data from API. We MUST fetch actual rule state from API.
        # State file has: type, id, content_hash, template_path, etc.
        # API rule has: name, description, severity, status, search, etc.
        current_rule = self.fetch_remote_state(resource_id)

        # Handle "not found" with fallback name lookup
        if not current_rule:
            rule_name = template.get("name")
            logger.warning(f"Rule ID {resource_id} not found in CrowdStrike, attempting lookup by name: {rule_name}")

            # Try to find by name in remote cache
            if self._remote_rules_cache is None:
                self._fetch_all_remote_rules()

            # Search cache by name
            if self._remote_rules_cache and rule_name in self._remote_rules_cache:
                current_rule = self._remote_rules_cache[rule_name]
                new_id = current_rule.get("rule_id")
                logger.info(f"Found rule '{rule_name}' with different ID: {new_id} (state had: {resource_id})")
                logger.info(f"Updating with new ID {new_id}. Note: State file should be updated after deployment.")
                # Use the new ID for this update
                resource_id = new_id
            else:
                # Rule truly doesn't exist - was deleted from CrowdStrike
                raise RuntimeError(
                    f"Cannot update rule '{rule_name}' (ID: {resource_id}): not found in CrowdStrike. "
                    f"Rule may have been manually deleted. Consider removing from templates or running drift detection."
                )

        # Get current status
        current_status = current_rule.get("status", "")

        # DEBUG: Log update context
        logger.debug(f"[DEBUG] Updating rule: {template['name']}")
        logger.debug(f"[DEBUG] Current status: {current_status}, Target: {template.get('status', 'active')}")

        # Select and execute appropriate deployment strategy
        strategy = DeploymentStrategyFactory.create_strategy(
            resource_id=resource_id,
            template=template,
            current_status=current_status,
            falcon_command=self.falcon.command,
            wait_for_status=self._wait_for_rule_status,
        )

        logger.info(f"Updating rule '{template['name']}' using: {strategy.get_name()}")

        # Execute deployment strategy. Its response is deliberately discarded: a
        # 200 only means the API accepted the request, which is exactly the signal
        # that proved untrustworthy. The read-back below is the source of truth.
        strategy.execute(self._prepare_patch_payload)

        # The API accepting a PATCH does not mean the PATCH changed anything.
        # Read the rule back and prove it before calling this a success.
        verified = self._verify_applied(resource_id, template, "update")
        self._refresh_cache_entry(verified)

        return {
            "rule_id": resource_id,
            "name": verified.get("name", ""),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "verified": True,
            "response": verified,
        }

    def fetch_remote_raw(self, resource_id: str) -> Optional[Dict[str, Any]]:
        """Fetch one rule's raw API representation by ID, bypassing the cache.

        The bulk cache is keyed by rule *name* and is populated before a deploy,
        so it cannot be used to confirm a write: it is both stale and, when two
        rules share a name, pointing at the wrong object.
        """
        try:
            response = self.falcon.command("entities_rules_get_v1", ids=[resource_id])
            if response["status_code"] == 200 and response["body"].get("resources"):
                return response["body"]["resources"][0]
            logger.debug(f"Read-back for rule {resource_id} returned no resources: {response.get('status_code')}")
            return None
        except Exception as e:
            logger.error(f"Failed to read back rule {resource_id}: {e}")
            return None

    def _verify_applied(self, resource_id: str, template: Dict[str, Any], operation: str) -> Dict[str, Any]:
        """Confirm the platform actually holds what we just wrote.

        Re-reads the rule by ID and compares the canonical IaC-managed content
        against the template - the same comparison `plan` and `drift` use. Polls
        with backoff because the API is eventually consistent.

        Returns:
            The raw API rule, once it matches the template.

        Raises:
            RuntimeError: If the platform never converges on the template. A write
                that does not land MUST fail loudly: reporting success here is what
                let a rename silently no-op for two months while state recorded it
                as deployed.
        """
        expected = self._canonical_content(template)
        actual = None

        for attempt, wait in enumerate([0.0] + list(VERIFY_BACKOFF)):
            if wait:
                time.sleep(wait)

            raw = self.fetch_remote_raw(resource_id)
            if raw is None:
                logger.debug(f"Read-back attempt {attempt + 1} for {resource_id}: rule not returned")
                continue

            actual = self._canonical_content(raw)
            if actual == expected:
                if attempt:
                    logger.debug(f"Read-back for {resource_id} converged after {attempt + 1} attempts")
                return raw

        if actual is None:
            raise RuntimeError(
                f"Verification failed after {operation} of rule '{template.get('name')}' "
                f"(ID: {resource_id}): the rule could not be read back from CrowdStrike. "
                f"The deployment cannot be confirmed and has NOT been recorded as successful."
            )

        diverged = sorted(k for k in set(expected) | set(actual) if expected.get(k) != actual.get(k))
        details = "; ".join(f"{k}: sent {expected.get(k)!r}, platform holds {actual.get(k)!r}" for k in diverged)
        raise RuntimeError(
            f"Verification failed after {operation} of rule '{template.get('name')}' "
            f"(ID: {resource_id}): the CrowdStrike API accepted the request but the rule "
            f"still differs on {diverged}. {details}"
        )

    def apply_delete(self, resource_id: str) -> Dict[str, Any]:
        """
        Delete a detection rule from CrowdStrike

        Args:
            resource_id: Rule ID to delete

        Returns:
            Deletion metadata
        """
        response = self.falcon.command("entities_rules_delete_v1", ids=[resource_id])

        if response["status_code"] not in (200, 204):
            raise RuntimeError(f"Failed to delete rule ID {resource_id}: {response}")

        return {"rule_id": resource_id, "deleted_at": datetime.now(timezone.utc).isoformat()}

    # Immutable fields that require delete+recreate if changed.
    # The CrowdStrike API rejects PATCH operations that change these fields.
    IMMUTABLE_FIELDS = {"type"}

    def _enforce_behavioral_constraints(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enforce API constraints for behavioral rules.

        The CrowdStrike API requires behavioral rules to have:
        - trigger_mode: "" (empty string) — 'summary'/'each'/'silent' are rejected
        - use_ingest_time: true
        These are auto-enforced to prevent silent miscreation where the API
        downgrades a behavioral rule to correlation due to invalid field values.
        """
        if payload.get("type") != "behavioral":
            return payload

        search = payload.get("search", {})
        if search.get("trigger_mode") not in ("", None):
            logger.warning(
                f"Behavioral rule '{payload.get('name', '?')}' has trigger_mode="
                f"'{search['trigger_mode']}', forcing to '' (required by API)"
            )
            search["trigger_mode"] = ""
        if not search.get("use_ingest_time"):
            search["use_ingest_time"] = True
        payload["search"] = search
        return payload

    def _prepare_rule_payload(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare API payload from template for POST (create) operations

        Supports both legacy and new template formats.
        The CrowdStrike API accepts the search config as-is, so we pass it through.
        """
        # v0.3.0: single source of truth for reserved/internal key stripping.
        template = strip_for_api(template)
        payload = {
            "name": template["name"],
            "description": template.get("description", ""),
            "severity": template.get("severity", 50),
            "status": template.get("status", "active"),
        }

        # Add customer_id if available (required for multi-tenant environments)
        if self.customer_id:
            payload["customer_id"] = self.customer_id

        # Add rule type if specified (e.g., 'behavioral' for correlate() rules)
        if "type" in template:
            payload["type"] = template["type"]

        # Add template_id for lineage tracking (preserves origin in CrowdStrike UI)
        if "template_id" in template:
            payload["template_id"] = template["template_id"]

        # Add search configuration - pass through as-is
        # The API accepts both legacy format (filter, lookback, trigger_mode, outcome)
        # and new format (query, search_window, search_window_unit)
        payload["search"] = template.get("search", {})

        # Add MITRE ATT&CK fields if present
        # Extract ID codes from full names like "Exfiltration (TA0010)" -> "TA0010"
        # Skip invalid/placeholder values like "Not Specified"
        mitre_fields = MitreProcessor.normalize_template_mitre(template)
        if mitre_fields:
            payload.update(mitre_fields)

        # Add operation settings if present
        if "operation" in template:
            payload["operation"] = template["operation"]

        return self._enforce_behavioral_constraints(payload)

    def _prepare_patch_payload(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare API payload from template for PATCH (update) operations

        IMPORTANT: PATCH has different requirements than POST:
        - Must include 'id' field
        - Payload must be wrapped in an ARRAY when calling the API

        'name' MUST be included. It is part of CONTENT_FIELDS, so a rename makes
        compute_content_hash differ and `plan` reports an update. Omitting it here
        made that update a silent no-op that still reported success.

        This method creates a payload suitable for entities_rules_patch_v1 endpoint.
        """
        # v0.3.0: single source of truth for reserved/internal key stripping.
        template = strip_for_api(template)
        payload = {
            "name": template["name"],
            "description": template.get("description", ""),
            "severity": template.get("severity", 50),
            "status": template.get("status", "active"),
        }

        # Add rule type if specified (e.g., 'behavioral' for correlate() rules)
        if "type" in template:
            payload["type"] = template["type"]

        # Add search configuration - pass through as-is
        # The API accepts all search fields including use_ingest_time for PATCH
        payload["search"] = template.get("search", {})

        # Add MITRE ATT&CK fields if present
        # Extract ID codes from full names like "Exfiltration (TA0010)" -> "TA0010"
        # Skip invalid/placeholder values like "Not Specified"
        mitre_fields = MitreProcessor.normalize_template_mitre(template)
        if mitre_fields:
            payload.update(mitre_fields)

        # Add operation settings if present
        if "operation" in template:
            payload["operation"] = template["operation"]

        return self._enforce_behavioral_constraints(payload)

    # Fields that define detection behavior - used for hashing and drift comparison.
    # These are the fields we control via IaC templates.
    CONTENT_FIELDS = ("name", "description", "severity", "status", "type")
    SEARCH_FIELDS = ("filter", "lookback", "outcome", "trigger_mode", "use_ingest_time", "execution_mode")

    # ADS (Alerting and Detection Strategy) metadata fields.
    # Optional block on detection templates — strict validation when present.
    ADS_ALLOWED_FIELDS = {
        "goal",
        "mitre_attack",
        "strategy_abstract",
        "technical_context",
        "blind_spots",
        "false_positives",
        "validation",
        "priority_rationale",
        "response",
        "ads_created",
        "ads_updated",
        "ads_author",
    }
    ADS_REQUIRED_FIELDS = {"goal"}
    ADS_LIST_FIELDS = {"mitre_attack", "blind_spots", "false_positives", "validation"}
    ADS_STRING_FIELDS = {
        "goal",
        "strategy_abstract",
        "technical_context",
        "priority_rationale",
        "ads_created",
        "ads_updated",
        "ads_author",
    }

    # v0.3.0: METADATA_* constants removed — now owned by core/metadata_validators.py.

    # Ref-dict shape accepted by ads.false_positives / ads.response / ads.validation.
    # See docs/superpowers/specs/2026-04-16-metadata-schema-and-ads-refs-design.md §2.
    ADS_REF_ALLOWED_KEYS = {"path", "label"}

    # Inline false_positives dict keys (existing convention — now strictly enforced).
    ADS_FP_INLINE_ALLOWED_KEYS = {"pattern", "characteristics", "tuning", "status"}

    def compute_content_hash(self, template: Dict[str, Any]) -> str:
        """
        Calculate deterministic hash of rule content.

        Only includes fields that affect detection behavior.
        Works on both template data and raw API response data by
        extracting the same canonical set of fields from either format.
        """
        content_str = json.dumps(self._canonical_content(template), sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()

    def _canonical_content(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """Reduce a template or raw API rule to the canonical IaC-managed content.

        This is the single definition of "what talonctl controls" — compute_content_hash
        hashes it, and post-apply verification diffs it. Sharing one definition keeps
        the verifier's verdict identical to the hash comparison plan and drift use.
        """
        # v0.3.0: strip universal IaC-only + internal fields first for consistency
        # with other providers. The allowlist build below is the effective filter,
        # but this call locks in the single-source-of-truth for reserved keys.
        template = strip_for_hash(template)
        # Extract only the fields we care about
        normalized_content = {
            "name": template.get("name", ""),
            "description": (template.get("description", "") or "").strip(),
            "severity": template.get("severity", 10),
            "status": template.get("status", "active"),
        }

        # Include rule type if specified (behavioral rules)
        if template.get("type"):
            normalized_content["type"] = template["type"]

        # Normalize search config - extract only IaC-managed fields
        raw_search = template.get("search", {}) or {}
        search_config = {}
        for field in self.SEARCH_FIELDS:
            if field in raw_search:
                val = raw_search[field]
                # Normalize filter whitespace
                if field == "filter" and isinstance(val, str):
                    val = val.strip()
                search_config[field] = val
        # Remove use_ingest_time if it's false (default)
        if search_config.get("use_ingest_time") is False:
            search_config.pop("use_ingest_time", None)

        normalized_content["search"] = search_config

        # Include operation schedule if present (IaC-managed)
        operation = template.get("operation", {}) or {}
        if "schedule" in operation:
            normalized_content["operation"] = {"schedule": operation["schedule"]}

        # Normalize MITRE ATT&CK to canonical form.
        # Templates use string format: ["Tactic (TAxxxx):Technique (Txxxx)"]
        # API returns dict format: [{"tactic_id": "TAxxxx", "technique_id": "Txxxx"}]
        # We normalize both to sorted list of "tactic_id:technique_id" strings.
        normalized_content["mitre_attack"] = self._normalize_mitre_for_hash(template.get("mitre_attack") or [])

        return normalized_content

    @staticmethod
    def _normalize_mitre_for_hash(mitre_attack: list) -> list:
        """Normalize mitre_attack to canonical sorted form for hashing.

        Handles both template string format and API dict format:
        - String: "Tactic Name (TA0005):Technique Name (T1562.001)" -> "TA0005:T1562.001"
        - Dict: {"tactic_id": "TA0005", "technique_id": "T1562.001"} -> "TA0005:T1562.001"

        Returns sorted list of "tactic_id:technique_id" strings.
        """
        canonical = []
        for entry in mitre_attack:
            if isinstance(entry, str):
                # String format: "Tactic (TAxxxx):Technique (Txxxx)" or "TAxxxx:Txxxx"
                tactic_id = ""
                technique_id = ""
                if ":" in entry:
                    tactic_part, technique_part = entry.split(":", 1)
                    tactic_id = MitreProcessor.extract_id(tactic_part.strip())
                    technique_id = MitreProcessor.extract_id(technique_part.strip())
                else:
                    tactic_id = MitreProcessor.extract_id(entry.strip())
                canonical.append(f"{tactic_id}:{technique_id}")
            elif isinstance(entry, dict):
                # Dict format from API: {"tactic_id": "TAxxxx", "technique_id": "Txxxx"}
                tactic_id = MitreProcessor.extract_id(str(entry.get("tactic_id", entry.get("tactic", ""))))
                technique_id = MitreProcessor.extract_id(str(entry.get("technique_id", entry.get("technique", ""))))
                canonical.append(f"{tactic_id}:{technique_id}")
        return sorted(canonical)

    def extract_dependencies(self, template: Dict[str, Any]) -> List[str]:
        """
        Extract resource dependencies from FQL query

        Detects references to:
        - Saved searches (via query_id or readFile())
        - Lookup files (via in() function or readFile())

        Supports both legacy (filter) and new (query) formats.

        Returns:
            List of dependency resource IDs in "type.name" format
        """
        dependencies = []

        # Check for saved search reference
        search = template.get("search", {})
        if "query_id" in search:
            query_id = search["query_id"]
            # Convert query_id to resource ID
            # Format: "saved_search.{sanitized_name}"
            dependencies.append(f"saved_search.{query_id}")

        # Parse FQL query for readFile() and in() references
        # Support both 'query' (new format) and 'filter' (legacy format)
        query = search.get("query") or search.get("filter", "")
        if query:
            # Look for readFile() calls
            # Example: readFile(fileName="aws_service_accounts")
            import re

            # Match readFile(fileName="...")
            readfile_pattern = r'readFile\s*\(\s*fileName\s*=\s*["\']([^"\']+)["\']'
            for match in re.finditer(readfile_pattern, query):
                filename = match.group(1)
                dependencies.append(f"lookup_file.{filename}")

            # Match in() function with array name
            # Example: | srcIpAddr in(name="trusted_ips")
            in_pattern = r'in\s*\(\s*name\s*=\s*["\']([^"\']+)["\']'
            for match in re.finditer(in_pattern, query):
                array_name = match.group(1)
                dependencies.append(f"lookup_file.{array_name}")

            # Match $function_name() calls - saved search dependencies
            # Example: $aws_service_account_detector() or $trusted_network_detector()
            # These are LogScale saved searches called as functions in the query
            function_call_pattern = r"\$([a-z_][a-z0-9_]*)\s*\(\)"
            for match in re.finditer(function_call_pattern, query, re.IGNORECASE):
                function_name = match.group(1)
                dependencies.append(f"saved_search.{function_name}")

        return dependencies

    def _refresh_cache_entry(self, raw_rule: Dict[str, Any]) -> None:
        """Update the bulk caches in place for one rule we just wrote.

        Keeps the cache honest after an apply without paying for a full re-fetch.
        Because the caches are keyed by name, a rename leaves the rule filed under
        its old key — that stale entry is removed by rule_id so a later lookup
        cannot resolve to a name the platform no longer uses.
        """
        if self._remote_rules_cache is None or self._remote_rules_raw_cache is None:
            return

        if self._remote_rules_by_id is not None:
            refreshed_id = raw_rule.get("rule_id") or raw_rule.get("id")
            if refreshed_id:
                self._remote_rules_by_id[refreshed_id] = raw_rule

        name = raw_rule.get("name", "")
        if not name:
            return

        rule_id = raw_rule.get("rule_id") or raw_rule.get("id")
        if rule_id:
            for cache in (self._remote_rules_cache, self._remote_rules_raw_cache):
                stale = [
                    key
                    for key, value in cache.items()
                    if key != name and (value.get("rule_id") or value.get("id")) == rule_id
                ]
                for key in stale:
                    del cache[key]

        self._remote_rules_raw_cache[name] = raw_rule
        self._remote_rules_cache[name] = self._normalize_rule(raw_rule)

    def clear_cache(self):
        """Clear the remote rules cache"""
        self._remote_rules_cache = None
        self._remote_rules_raw_cache = None
        self._remote_rules_by_id = None

    def publish(self, resource_ids: Optional[List[str]] = None) -> Tuple[List[str], List[Tuple[str, str]]]:
        """
        Publish inactive (staged) detection rules to production by activating them

        Args:
            resource_ids: Optional list of specific resource IDs to publish (e.g., ['detection.aws_root_login'])
                         If None, all inactive managed rules will be published

        Returns:
            Tuple of (successful_ids, failed_items) where failed_items is [(resource_id, error_msg)]
        """
        logger.info("Finding inactive detection rules to publish")

        try:
            # Fetch all inactive rules from CrowdStrike
            response = self.falcon.command(
                "combined_rules_get_v2", filter='status:"inactive"', limit=1000, sort="name.asc"
            )

            if response["status_code"] != 200:
                error_msg = f"Failed to fetch inactive rules: {response}"
                logger.error(error_msg)
                return ([], [(resource_ids[0] if resource_ids else "all", error_msg)])

            all_inactive = response["body"]["resources"]

        except Exception as e:
            error_msg = f"Error fetching inactive rules: {e}"
            logger.error(error_msg)
            return ([], [(resource_ids[0] if resource_ids else "all", error_msg)])

        # Filter to specified resource IDs if provided
        rules_to_publish = []
        if resource_ids:
            # Extract names from resource IDs (format: detection.rule_name)
            target_names = [rid.split(".", 1)[1] if "." in rid else rid for rid in resource_ids]
            for rule in all_inactive:
                if rule["name"] in target_names:
                    rules_to_publish.append(rule)
        else:
            # Publish all inactive rules
            rules_to_publish = all_inactive

        if not rules_to_publish:
            logger.info("No inactive rules found to publish")
            return ([], [])

        logger.info(f"Found {len(rules_to_publish)} inactive rules to publish")

        # Activate each rule
        successful = []
        failed = []

        for rule in rules_to_publish:
            try:
                rule_name = rule["name"]
                rule_id = rule.get("rule_id", rule["id"])
                resource_id = f"detection.{rule_name}"

                logger.info(f"Activating rule: {rule_name}")

                # Update rule status to active
                update_payload = {"id": rule_id, "status": "active"}

                response = self.falcon.command("entities_rules_patch_v1", body=[update_payload])

                if response["status_code"] == 200:
                    logger.info(f"Successfully activated: {rule_name}")
                    successful.append(resource_id)
                else:
                    error_msg = f"API returned status {response['status_code']}: {response}"
                    logger.error(f"Failed to activate {rule_name}: {error_msg}")
                    failed.append((resource_id, error_msg))

            except Exception as e:
                error_msg = f"Error activating rule: {e}"
                logger.error(f"Failed to activate {rule_name}: {error_msg}")
                failed.append((resource_id, error_msg))

        logger.info(f"Publish complete: {len(successful)} succeeded, {len(failed)} failed")
        return (successful, failed)

    def to_template(self, remote_resource: dict) -> dict:
        """
        Convert a normalized remote detection rule into a YAML template dict.

        Maps the normalized API format (search.query, search.search_window)
        to the template format (search.filter, search.lookback).

        Args:
            remote_resource: Normalized detection dict from _fetch_all_remote_rules()

        Returns:
            Template dict ready for YAML serialization
        """
        name = remote_resource.get("name", "")
        resource_id = self._name_to_resource_id(name)

        template = {
            "resource_id": resource_id,
            "name": name,
            "description": (remote_resource.get("description", "") or "").strip(),
            "severity": remote_resource.get("severity", 10),
            "status": remote_resource.get("status", "active"),
        }

        # Map MITRE ATT&CK if present
        mitre = remote_resource.get("mitre_attack")
        if mitre:
            template["mitre_attack"] = mitre

        # Map rule type if present (e.g., 'behavioral')
        rule_type = remote_resource.get("type")
        if rule_type:
            template["type"] = rule_type

        # Map search config: normalized format -> template format
        # Normalized: search.query, search.search_window, search.use_ingest_time, etc.
        # Template:   search.filter, search.lookback, search.trigger_mode, search.outcome, etc.
        norm_search = remote_resource.get("search", {})
        search = {}

        # query -> filter
        query = norm_search.get("query") or norm_search.get("filter", "")
        if query:
            search["filter"] = query

        # search_window -> lookback
        lookback = norm_search.get("search_window") or norm_search.get("lookback")
        if lookback:
            search["lookback"] = lookback

        # Pass through fields that have the same name in both formats
        for field in ("trigger_mode", "outcome", "use_ingest_time", "execution_mode"):
            if field in norm_search:
                search[field] = norm_search[field]

        if search:
            template["search"] = search

        # Map operation if present
        operation = remote_resource.get("operation")
        if operation and isinstance(operation, dict):
            template["operation"] = operation

        return template

    def suggest_path(self, template: dict) -> str:
        """
        Suggest a file path for a detection template.

        Uses the triple-underscore convention to infer a platform subdirectory
        from the resource_id (e.g., 'aws___cloudtrail___...' -> 'detections/aws/').

        Args:
            template: Template dict from to_template()

        Returns:
            Relative path string like 'detections/aws/aws___cloudtrail___console_root_login.yaml'
        """
        resource_id = template.get("resource_id", "")
        if not resource_id:
            resource_id = self._name_to_resource_id(template.get("name", "unknown"))

        # Extract platform from resource_id using triple-underscore convention
        # e.g., 'aws___cloudtrail___console_root_login' -> platform = 'aws'
        parts = resource_id.split("___")
        if len(parts) >= 2:
            platform = parts[0]
        else:
            platform = "uncategorized"

        return f"detections/{platform}/{resource_id}.yaml"
