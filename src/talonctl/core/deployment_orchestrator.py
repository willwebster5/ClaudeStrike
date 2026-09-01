"""
Deployment Orchestrator

Coordinates deployment of all resource types with dependency resolution,
parallel execution, and comprehensive error handling.
"""

import logging
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from talonctl.core.template_discovery import TemplateDiscovery, DiscoveredTemplate
from talonctl.core.resource_graph import ResourceGraph
from talonctl.core.state_manager import StateManager, ResourceState
from talonctl.core.provider_adapter import ProviderAdapter
from talonctl.core.state_synchronizer import StateSynchronizer
from talonctl.core.drift_detector import DriftDetector, DriftReport
from talonctl.core.base_provider import ResourceAction, ResourceChange
from talonctl.core.envelope import Envelope, TYPE_TO_KIND
from talonctl.core.status_projection import attach_status
from talonctl.core.query_collection import collect_queries_from_templates

# Try to import NGSIEMClient for query validation
try:
    from talonctl.utils.ngsiem_client import NGSIEMClient

    NGSIEM_CLIENT_AVAILABLE = True
except ImportError:
    NGSIEM_CLIENT_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class QueryValidationResult:
    """Result of FQL query validation."""

    resource_id: str
    resource_name: str
    is_valid: bool
    error_message: Optional[str] = None
    query_snippet: Optional[str] = None  # First 100 chars of query
    location: Optional[str] = None  # Field path within template, e.g. 'search.filter'


@dataclass
class DeploymentPlan:
    """Complete deployment plan with changes and execution order"""

    changes: List[ResourceChange]
    waves: List[List[str]]  # Deployment waves (resource IDs)
    statistics: Dict[str, int]
    graph: ResourceGraph
    query_validation_results: Optional[List[QueryValidationResult]] = None


@dataclass
class DeploymentResult:
    """Result of a deployment operation"""

    success: bool
    deployed: List[str]  # Successfully deployed resource IDs
    failed: List[tuple]  # (resource_id, error_message)
    skipped: List[str]  # Skipped due to dependency failures
    duration: float  # Seconds


class DeploymentOrchestrator:
    """
    Orchestrates deployment across all resource providers

    Responsibilities:
    - Template discovery and filtering
    - Dependency graph construction
    - Plan generation
    - Parallel deployment in waves
    - State management
    - Error handling and rollback
    """

    def __init__(
        self,
        falcon_client: Any,
        state_file_path: Path,
        resources_dir: Optional[Path] = None,
        project_root: Optional[Path] = None,
        remote_state_enabled: bool = False,
        remote_state_search_domain: str = "falcon",
        remote_state_filename: str = "unified_deployment_state.json",
        credentials: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize orchestrator

        Args:
            falcon_client: Authenticated FalconPy client
            state_file_path: Path to state file
            resources_dir: Resources directory (auto-detected if not provided)
            project_root: Project root (auto-detected if not provided)
            remote_state_enabled: Whether to sync state with NGSIEM lookup files
            remote_state_search_domain: NGSIEM search domain for remote state (falcon, all, third-party, etc.)
            remote_state_filename: Filename for remote state in NGSIEM
            credentials: Optional credentials dict (required for RTR providers to use service class)
        """
        self.falcon = falcon_client
        self.state_manager = StateManager(
            state_file_path,
            falcon_client=falcon_client,
            remote_state_enabled=remote_state_enabled,
            remote_state_search_domain=remote_state_search_domain,
            remote_state_filename=remote_state_filename,
        )
        self.provider_adapter = ProviderAdapter(falcon_client, state_file_path, credentials=credentials)
        self.template_discovery = TemplateDiscovery(resources_dir, project_root)
        self.state_synchronizer = StateSynchronizer(self.state_manager, self.provider_adapter)

    def plan(
        self,
        resource_types: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        names: Optional[List[str]] = None,
        skip_query_validation: bool = False,
        validation_workers: int = 20,
    ) -> DeploymentPlan:
        """
        Generate deployment plan

        Args:
            resource_types: Filter by resource types
            tags: Filter by tags
            names: Filter by name patterns

        Returns:
            DeploymentPlan with changes and execution order
        """
        logger.info("Generating deployment plan...")

        # Discover templates
        discovered = self.template_discovery.discover_all(resource_types=resource_types, tags=tags, names=names)

        # Load current state
        state = self.state_manager.export_to_dict()

        # Build resource graph for dependency resolution
        graph = self._build_dependency_graph(discovered)

        # Detect cycles
        cycles = graph.detect_cycles()
        if cycles:
            cycle_str = str(cycles[0])
            raise ValueError(f"Circular dependency detected: {cycle_str}")

        # Calculate deployment waves
        waves = graph.get_deployment_waves()

        # Plan changes for each resource
        changes = []
        for resource_type, templates in discovered.items():
            for template in templates:
                change = self._plan_resource(template, state)
                if change:
                    changes.append(change)

        # Calculate statistics
        statistics = self._calculate_statistics(changes)

        replace_msg = f", {statistics['replace']} to replace" if statistics.get("replace") else ""
        logger.info(
            f"Plan complete: {statistics['create']} to create, "
            f"{statistics['update']} to update{replace_msg}, {statistics['delete']} to delete"
        )

        # Validate detection queries if requested
        query_validation_results = None
        if not skip_query_validation and "detection" in discovered:
            query_validation_results = self._validate_detection_queries(
                discovered["detection"], changes, validation_workers
            )

        return DeploymentPlan(
            changes=changes,
            waves=waves,
            statistics=statistics,
            graph=graph,
            query_validation_results=query_validation_results,
        )

    def _build_dependency_graph(self, discovered: Dict[str, List[DiscoveredTemplate]]) -> ResourceGraph:
        """
        Build dependency graph from discovered templates

        Args:
            discovered: Discovered templates grouped by type

        Returns:
            Resource graph with dependencies
        """
        graph = ResourceGraph()

        # Add all nodes first
        for resource_type, templates in discovered.items():
            for template in templates:
                graph.add_node(template.resource_id)

        # Add dependency edges
        for resource_type, templates in discovered.items():
            provider = self.provider_adapter.providers.get(resource_type)
            if not provider:
                continue

            for template in templates:
                # Extract dependencies from template
                dependencies = provider.extract_dependencies(template.template_data)

                for dep in dependencies:
                    # Add dependency edge (template depends on dep)
                    graph.add_dependency(template.resource_id, dep)

        return graph

    def _plan_resource(self, template: DiscoveredTemplate, state: Dict[str, Any]) -> Optional[ResourceChange]:
        """
        Plan changes for a single resource

        Args:
            template: Discovered template
            state: Current state

        Returns:
            ResourceChange or None
        """
        resource_type = template.resource_type
        provider = self.provider_adapter.providers.get(resource_type)

        if not provider:
            logger.warning(f"No provider for resource type: {resource_type}")
            return None

        # Get current state for this resource
        # Support migration from name-based keys to resource_id-based keys
        # Try resource_id first (new), then fall back to display_name (legacy)
        resources_state = state.get("resources", {}).get(resource_type, {})
        current_state = resources_state.get(template.name)

        # Migration fallback: if not found by resource_id, try display_name
        # This handles the transition period where state has name-based keys
        # but templates now have resource_id-based identifiers
        if not current_state and template.display_name and template.display_name != template.name:
            current_state = resources_state.get(template.display_name)
            if current_state:
                logger.debug(f"Found state for '{template.name}' using legacy key '{template.display_name}'")

        # Validate template (flipped providers consume the Envelope directly)
        errors = provider.validate_template(template.envelope)
        if errors:
            logger.error(f"Template validation errors for {template.resource_id}:")
            for error in errors:
                logger.error(f"  - {error}")
            raise ValueError(f"Invalid template: {template.resource_id}")

        # Attach the read-only status projection from on-disk state (None == unmanaged)
        # before planning, so providers see server-assigned fields on the Envelope.
        attach_status(template.envelope, current_state, resource_type)

        # Determine action
        if not current_state:
            # Resource doesn't exist - create
            action = "create"
            changes_dict = None
            old_state = None
        else:
            # Resource exists - check if update needed
            template_hash = provider.compute_content_hash(template.template_data)
            state_hash = current_state.get("content_hash", "")

            if template_hash != state_hash:
                # Check if any immutable fields changed (requires delete+recreate)
                replace_reason = None
                if hasattr(provider, "requires_replacement"):
                    replace_reason = provider.requires_replacement(template.template_data, current_state)

                if replace_reason:
                    action = "replace"
                    logger.info(f"Resource {template.resource_id} requires replacement: {replace_reason}")
                else:
                    action = "update"

                # Compute detailed changes
                changes_dict = self._compute_changes(template.template_data, current_state)
                old_state = current_state
            else:
                action = "no-change"
                changes_dict = None
                old_state = current_state

        return ResourceChange(
            action=ResourceAction(action),  # Convert string to enum
            resource_type=resource_type,
            resource_id=template.resource_id,
            resource_name=template.name,
            old_value=old_state,
            new_value=template.template_data,
            changes=changes_dict,
            template_path=str(template.file_path),
            envelope=template.envelope,
        )

    def _compute_changes(self, new_template: Dict[str, Any], old_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compute detailed changes between template and state

        Args:
            new_template: New template data
            old_state: Current state

        Returns:
            Dictionary of changes
        """
        changes = {}

        # Only compare fields if old_state contains them (i.e., from remote state fetch)
        # Otherwise, rely on content_hash for change detection
        # Local state only stores metadata (content_hash, id, etc.), not actual resource fields
        compare_fields = ["name", "description", "severity", "enabled", "version"]

        # Check if old_state has any of the comparison fields
        has_resource_fields = any(field in old_state for field in compare_fields)

        if has_resource_fields:
            # Old state has resource fields - do detailed comparison
            for field in compare_fields:
                new_val = new_template.get(field)
                old_val = old_state.get(field)

                if new_val != old_val:
                    changes[field] = {"old": old_val, "new": new_val}
        # Otherwise, skip field comparison - content_hash handles change detection

        return changes

    def _validate_detection_queries(
        self, templates: List[DiscoveredTemplate], changes: List[ResourceChange], max_workers: int = 20
    ) -> List[QueryValidationResult]:
        """
        Validate NGSIEM queries in detection templates

        Args:
            templates: List of discovered detection templates
            changes: List of planned changes
            max_workers: Maximum parallel validation workers

        Returns:
            List of query validation results
        """
        validation_results = []

        if not NGSIEM_CLIENT_AVAILABLE:
            logger.warning("NGSIEM client not available - skipping query validation")
            return validation_results

        try:
            # Collect queries from templates that will be deployed
            # Only validate queries for create/update changes
            change_resource_ids = {c.resource_id for c in changes if c.action in ["create", "update"]}

            queries_to_validate = []
            for template in templates:
                # Only validate if this template has changes
                if template.resource_id not in change_resource_ids:
                    continue

                # Extract query from search config (supports both 'query' and 'filter')
                search_config = template.template_data.get("search", {})
                query = search_config.get("filter") or search_config.get("query")

                if query:
                    # Clean query for display
                    query_snippet = query.strip().replace("\n", " ")[:100]
                    if len(query_snippet) == 100:
                        query_snippet += "..."

                    queries_to_validate.append(
                        {
                            "resource_id": template.resource_id,
                            "resource_name": template.name,
                            "query": query,
                            "query_snippet": query_snippet,
                        }
                    )

            total_queries = len(queries_to_validate)
            if total_queries == 0:
                # No queries to validate - skip silently
                return validation_results

            # Initialize NGSIEM client only when needed
            logger.info(f"Validating {total_queries} detection queries with up to {max_workers} workers...")
            ngsiem_client = NGSIEMClient()

            # Validate queries in parallel
            def validate_single(query_info):
                try:
                    result = ngsiem_client.test_query_syntax(query_info["query"])
                    return QueryValidationResult(
                        resource_id=query_info["resource_id"],
                        resource_name=query_info["resource_name"],
                        is_valid=result["valid"],
                        error_message=None if result["valid"] else result.get("message"),
                        query_snippet=query_info["query_snippet"],
                    )
                except Exception as e:
                    return QueryValidationResult(
                        resource_id=query_info["resource_id"],
                        resource_name=query_info["resource_name"],
                        is_valid=False,
                        error_message=f"Validation error: {str(e)}",
                        query_snippet=query_info["query_snippet"],
                    )

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(validate_single, q) for q in queries_to_validate]
                for future in as_completed(futures):
                    validation_results.append(future.result())

            # Log summary
            valid_count = sum(1 for r in validation_results if r.is_valid)
            invalid_count = total_queries - valid_count

            if invalid_count == 0:
                logger.info(f"Query validation complete: {valid_count} queries valid")
            else:
                logger.warning(f"Query validation complete: {valid_count} valid, {invalid_count} invalid")

        except Exception as e:
            logger.error(f"Query validation failed: {e}")

        return validation_results

    def _calculate_statistics(self, changes: List[ResourceChange]) -> Dict[str, int]:
        """
        Calculate statistics from changes

        Args:
            changes: List of resource changes

        Returns:
            Statistics dictionary
        """
        stats = {"create": 0, "update": 0, "replace": 0, "delete": 0, "no-change": 0}

        for change in changes:
            # Convert enum to string value for dictionary key
            action_key = change.action.value if isinstance(change.action, ResourceAction) else change.action
            stats[action_key] = stats.get(action_key, 0) + 1

        return stats

    def apply(
        self, plan: DeploymentPlan, parallel: int = 10, auto_approve: bool = False, enable_rollback: bool = False
    ) -> DeploymentResult:
        """
        Execute deployment plan

        Args:
            plan: Deployment plan to execute
            parallel: Maximum parallel workers
            auto_approve: Skip confirmation prompts
            enable_rollback: Enable automatic rollback on wave failure

        Returns:
            Deployment result
        """
        start_time = datetime.now(timezone.utc)

        # Filter out no-change resources
        changes_to_apply = [c for c in plan.changes if c.action != ResourceAction.NO_CHANGE]

        if not changes_to_apply:
            logger.info("No changes to apply")
            return DeploymentResult(success=True, deployed=[], failed=[], skipped=[], duration=0.0)

        logger.info(f"Applying {len(changes_to_apply)} changes in {len(plan.waves)} waves...")

        deployed = []
        failed = []
        skipped = []
        skipped_set = set()  # Track skipped resources to filter them out
        rolled_back = []

        # Track all changes applied for rollback (need full change objects for rollback)
        deployed_changes = []  # List of ResourceChange objects that were deployed

        # Execute each wave
        for wave_idx, wave in enumerate(plan.waves, 1):
            logger.info(f"Deploying wave {wave_idx}/{len(plan.waves)} ({len(wave)} resources)...")

            # Get changes for this wave, excluding already skipped resources
            wave_changes = [c for c in changes_to_apply if c.resource_id in wave and c.resource_id not in skipped_set]

            if not wave_changes:
                continue

            # Deploy wave in parallel
            wave_result = self._deploy_wave(wave_changes, parallel)

            # Add wave results to overall results
            deployed.extend(wave_result["deployed"])
            failed.extend(wave_result["failed"])

            # Track deployed changes for potential rollback
            for resource_id in wave_result["deployed"]:
                change = next((c for c in wave_changes if c.resource_id == resource_id), None)
                if change:
                    deployed_changes.append(change)

            # If wave failed and rollback is enabled, rollback ALL deployed resources
            if wave_result["failed"] and enable_rollback:
                if deployed:
                    logger.warning(
                        f"Wave {wave_idx} had {len(wave_result['failed'])} failures. "
                        f"Rolling back ALL {len(deployed)} previously deployed resources..."
                    )

                    # Rollback all deployed resources (from all waves)
                    rollback_result = self._rollback_wave(deployed, deployed_changes, parallel)

                    rolled_back.extend(rollback_result["rolled_back"])

                    # Remove rolled back resources from deployed list
                    for resource_id in rollback_result["rolled_back"]:
                        if resource_id in deployed:
                            deployed.remove(resource_id)

                    # Log rollback failures
                    if rollback_result["failed_rollback"]:
                        logger.error(
                            f"Failed to rollback {len(rollback_result['failed_rollback'])} resources. "
                            f"Manual cleanup may be required."
                        )

                # If rollback is enabled and wave failed, abort deployment
                logger.error(
                    f"Aborting deployment due to wave {wave_idx} failure "
                    f"(rollback enabled). Remaining waves will not be deployed."
                )

                # Skip dependent resources
                failed_ids = {res_id for res_id, _ in wave_result["failed"]}
                newly_skipped = self._get_dependent_resources(failed_ids, plan.graph)
                skipped.extend(newly_skipped)
                skipped_set.update(newly_skipped)

                # Mark all remaining resources as skipped
                deployed_ids = {c.resource_id for c in deployed_changes}
                failed_ids_set = {fid for fid, _ in failed}
                for remaining_wave in plan.waves[wave_idx:]:
                    for resource_id in remaining_wave:
                        if resource_id not in deployed_ids and resource_id not in failed_ids_set:
                            skipped.append(resource_id)
                            skipped_set.add(resource_id)
                break

            # If any resource in wave failed but rollback is disabled, skip dependents
            if wave_result["failed"] and not enable_rollback:
                failed_ids = {res_id for res_id, _ in wave_result["failed"]}
                newly_skipped = self._get_dependent_resources(failed_ids, plan.graph)
                skipped.extend(newly_skipped)
                skipped_set.update(newly_skipped)

            # Save state after each wave completes (batch save optimization)
            # This reduces I/O overhead compared to saving after each resource,
            # while minimizing data loss risk compared to saving only at the end
            if wave_result["deployed"]:
                wave_results = wave_result.get("results", {})
                self.state_synchronizer.update_after_deployment(wave_result["deployed"], changes_to_apply, wave_results)
                logger.debug(f"State saved after wave {wave_idx} ({len(wave_result['deployed'])} resources)")

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        success = len(failed) == 0

        logger.info(f"Deployment complete: {len(deployed)} deployed, {len(failed)} failed, {len(skipped)} skipped")

        return DeploymentResult(success=success, deployed=deployed, failed=failed, skipped=skipped, duration=duration)

    def _deploy_wave(self, changes: List[ResourceChange], parallel: int) -> Dict[str, List]:
        """
        Deploy a wave of resources in parallel

        Args:
            changes: Changes to deploy
            parallel: Max parallel workers

        Returns:
            Dictionary with 'deployed' and 'failed' lists
        """
        deployed = []
        failed = []
        results: Dict[str, Any] = {}  # resource_id -> result dict from provider

        with ThreadPoolExecutor(max_workers=parallel) as executor:
            # Submit all tasks
            future_to_change = {executor.submit(self._deploy_resource, change): change for change in changes}

            # Collect results as they complete
            for future in as_completed(future_to_change):
                change = future_to_change[future]
                try:
                    result = future.result()
                    if result is not None:
                        deployed.append(change.resource_id)
                        results[change.resource_id] = result
                        logger.info(f"✓ Deployed {change.resource_id}")
                    else:
                        failed.append((change.resource_id, "Deployment returned None"))
                        logger.error(f"✗ Failed to deploy {change.resource_id}")
                except Exception as e:
                    failed.append((change.resource_id, str(e)))
                    logger.error(f"✗ Error deploying {change.resource_id}: {e}")

        return {"deployed": deployed, "failed": failed, "results": results}

    def _rollback_wave(self, deployed_ids: List[str], changes: List[ResourceChange], parallel: int) -> Dict[str, List]:
        """
        Rollback successfully deployed resources from a failed wave

        Args:
            deployed_ids: List of resource IDs that were deployed
            changes: All changes in the wave
            parallel: Max parallel workers

        Returns:
            Dictionary with 'rolled_back' and 'failed_rollback' lists
        """
        logger.warning(f"Rolling back {len(deployed_ids)} resources from failed wave...")

        rolled_back = []
        failed_rollback = []

        # Build lookup of changes by resource_id
        change_lookup = {c.resource_id: c for c in changes}

        with ThreadPoolExecutor(max_workers=parallel) as executor:
            # Submit rollback tasks
            future_to_resource_id = {}

            for resource_id in deployed_ids:
                change = change_lookup.get(resource_id)
                if not change:
                    continue

                future = executor.submit(self._rollback_resource, change)
                future_to_resource_id[future] = resource_id

            # Collect results
            for future in as_completed(future_to_resource_id):
                resource_id = future_to_resource_id[future]
                try:
                    result = future.result()
                    if result:
                        rolled_back.append(resource_id)
                        logger.info(f"↶ Rolled back {resource_id}")
                    else:
                        failed_rollback.append((resource_id, "Rollback returned False"))
                        logger.error(f"✗ Failed to rollback {resource_id}")
                except Exception as e:
                    failed_rollback.append((resource_id, str(e)))
                    logger.error(f"✗ Error rolling back {resource_id}: {e}")

        return {"rolled_back": rolled_back, "failed_rollback": failed_rollback}

    def _rollback_resource(self, change: ResourceChange) -> bool:
        """
        Rollback a single resource

        Args:
            change: Resource change to rollback

        Returns:
            True if successful
        """
        provider = self.provider_adapter.providers.get(change.resource_type)
        if not provider:
            raise ValueError(f"No provider for {change.resource_type}")

        try:
            if change.action == ResourceAction.CREATE:
                # Delete the created resource
                # For newly created resources, we need to get the ID from provider
                # Since we just created it, we can try to find it by name
                logger.info(f"Rolling back create: deleting {change.resource_id}")
                # Provider needs to implement a way to find resource by name
                # For now, we'll log a warning and skip
                logger.warning("Rollback of create not fully implemented - manual cleanup may be needed")
                return True

            elif change.action == ResourceAction.UPDATE:
                # Restore previous state
                if not change.old_value:
                    logger.warning(f"No old state to restore for {change.resource_id}")
                    return False

                resource_id = change.old_value.get("id")
                logger.info(f"Rolling back update: restoring {change.resource_id} to previous state")

                # Reconstruct a minimal old-state Envelope from old_value.
                # This is a simplified approach - ideally the old template would be
                # preserved; the flipped providers consume Envelopes, so wrap the
                # state dict to match the new apply_update signature.
                rollback_env = Envelope(
                    api_version="talon/v2",
                    kind=TYPE_TO_KIND[change.resource_type],
                    metadata={"resource_id": change.resource_id},
                    spec=dict(change.old_value or {}),
                )
                result = provider.apply_update(resource_id, rollback_env, change.old_value)
                return bool(result)

            elif change.action == ResourceAction.DELETE:
                # Recreate the deleted resource
                logger.info(f"Rolling back delete: recreating {change.resource_id}")
                if not change.old_value:
                    logger.warning(f"No old state to recreate {change.resource_id}")
                    return False

                rollback_env = Envelope(
                    api_version="talon/v2",
                    kind=TYPE_TO_KIND[change.resource_type],
                    metadata={"resource_id": change.resource_id},
                    spec=dict(change.old_value or {}),
                )
                result = provider.apply_create(rollback_env)
                return bool(result)

            return False

        except Exception as e:
            logger.error(f"Error rolling back {change.resource_id}: {e}")
            raise

    def _deploy_resource(self, change: ResourceChange) -> Optional[Dict[str, Any]]:
        """
        Deploy a single resource

        Args:
            change: Resource change to apply

        Returns:
            True if successful
        """
        provider = self.provider_adapter.providers.get(change.resource_type)
        if not provider:
            raise ValueError(f"No provider for {change.resource_type}")

        try:
            if change.action == ResourceAction.CREATE:
                result = provider.apply_create(change.envelope)
                return result if result else None

            elif change.action == ResourceAction.UPDATE:
                # CRITICAL: For detections, use rule_id from provider_metadata (permanent)
                resource_id = None
                if change.old_value and "provider_metadata" in change.old_value:
                    resource_id = change.old_value["provider_metadata"].get("rule_id")
                    logger.debug(f"Using rule_id from provider_metadata for update: {resource_id}")

                # Fallback to 'id' field
                if not resource_id and change.old_value:
                    resource_id = change.old_value.get("id")
                    logger.debug(f"Using id from old_value for update: {resource_id}")

                if not resource_id:
                    raise ValueError(f"No resource ID found for update of {change.resource_id}")

                result = provider.apply_update(resource_id, change.envelope, change.old_value)
                return result if result else None

            elif change.action == ResourceAction.REPLACE:
                # Delete + recreate (immutable field changed, e.g., type)
                resource_id = None
                if change.old_value and "provider_metadata" in change.old_value:
                    resource_id = change.old_value["provider_metadata"].get("rule_id")
                if not resource_id and change.old_value:
                    resource_id = change.old_value.get("id")

                if not resource_id:
                    raise ValueError(f"No resource ID found for replacement of {change.resource_id}")

                logger.info(f"Replacing {change.resource_id}: deleting {resource_id}")
                provider.apply_delete(resource_id)

                import time

                time.sleep(2)  # Allow API to process deletion before recreate

                logger.info(f"Replacing {change.resource_id}: recreating")
                result = provider.apply_create(change.envelope)
                return result if result else None

            elif change.action == ResourceAction.DELETE:
                # CRITICAL: For detections, use rule_id from provider_metadata (permanent)
                resource_id = None
                if change.old_value and "provider_metadata" in change.old_value:
                    resource_id = change.old_value["provider_metadata"].get("rule_id")
                    logger.debug(f"Using rule_id from provider_metadata for delete: {resource_id}")

                # Fallback to 'id' field
                if not resource_id and change.old_value:
                    resource_id = change.old_value.get("id")
                    logger.debug(f"Using id from old_value for delete: {resource_id}")

                if not resource_id:
                    raise ValueError(f"No resource ID found for deletion of {change.resource_id}")

                result = provider.apply_delete(resource_id)
                return result if result is not None else None

            return None

        except Exception as e:
            logger.error(f"Error applying {change.action} for {change.resource_id}: {e}")
            raise

    def _get_dependent_resources(self, failed_ids: Set[str], graph: ResourceGraph) -> List[str]:
        """
        Get all resources that depend on failed resources

        Args:
            failed_ids: Set of failed resource IDs
            graph: Resource graph

        Returns:
            List of dependent resource IDs to skip
        """
        dependent = []

        for node in graph.nodes:
            dependencies = graph.edges.get(node, set())
            if dependencies & failed_ids:  # Intersection
                dependent.append(node)

        return dependent

    def validate(
        self,
        resource_types: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        names: Optional[List[str]] = None,
    ) -> Dict[str, List[str]]:
        """
        Validate all templates without deploying

        Args:
            resource_types: Filter by resource types
            tags: Filter by tags
            names: Filter by name patterns

        Returns:
            Dictionary mapping resource ID to list of errors
        """
        logger.info("Validating templates...")

        discovered = self.template_discovery.discover_all(resource_types=resource_types, tags=tags, names=names)

        results = {}

        for resource_type, templates in discovered.items():
            provider = self.provider_adapter.providers.get(resource_type)
            if not provider:
                continue

            for template in templates:
                # Flipped providers consume the Envelope directly.
                errors = provider.validate_template(template.envelope)
                results[template.resource_id] = errors

        valid_count = sum(1 for errors in results.values() if not errors)
        total_count = len(results)

        logger.info(f"Validation complete: {valid_count}/{total_count} templates valid")

        return results

    def validate_queries(
        self,
        resource_types: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        names: Optional[List[str]] = None,
        max_workers: int = 20,
    ) -> List[QueryValidationResult]:
        """
        Parse every CQL query in every query-bearing template against NGSIEM.

        Does NOT run schema validation — caller is responsible for that.
        Raises ValueError (from NGSIEMClient) if credentials are missing.
        """
        if not NGSIEM_CLIENT_AVAILABLE:
            raise RuntimeError("NGSIEM client unavailable — cannot validate queries")

        discovered = self.template_discovery.discover_all(resource_types=resource_types, tags=tags, names=names)
        refs = collect_queries_from_templates(discovered)
        if not refs:
            return []

        logger.info(f"Validating {len(refs)} queries across {len(discovered)} resource types")
        ngsiem_client = NGSIEMClient()

        def validate_one(ref):
            try:
                result = ngsiem_client.test_query_syntax(ref.query)
                return QueryValidationResult(
                    resource_id=ref.resource_id,
                    resource_name=ref.resource_name,
                    is_valid=result["valid"],
                    error_message=None if result["valid"] else result.get("message"),
                    query_snippet=ref.query_snippet,
                    location=ref.location,
                )
            except Exception as e:
                return QueryValidationResult(
                    resource_id=ref.resource_id,
                    resource_name=ref.resource_name,
                    is_valid=False,
                    error_message=f"Validation error: {e}",
                    query_snippet=ref.query_snippet,
                    location=ref.location,
                )

        results: List[QueryValidationResult] = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(validate_one, r) for r in refs]
            for future in as_completed(futures):
                results.append(future.result())

        valid = sum(1 for r in results if r.is_valid)
        invalid = len(results) - valid
        if invalid:
            logger.warning(f"Query validation: {valid} valid, {invalid} invalid")
        else:
            logger.info(f"Query validation: all {valid} queries valid")

        return results

    def sync(
        self,
        resource_types: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        names: Optional[List[str]] = None,
    ) -> Dict[str, int]:
        """
        Sync state with currently deployed resources in CrowdStrike

        Fetches all deployed resources from CrowdStrike and rebuilds state.
        Useful after manual changes or when state is lost.

        Args:
            resource_types: Filter by resource types
            tags: Filter by tags
            names: Filter by name patterns

        Returns:
            Dictionary with sync statistics
        """
        logger.info("Syncing state with CrowdStrike...")

        # Discover templates to match against
        discovered = self.template_discovery.discover_all(resource_types=resource_types, tags=tags, names=names)

        stats = {
            "total_fetched": 0,
            "matched_templates": 0,
            "unmatched": 0,
            "unmatched_names": [],
            "updated": 0,
            "stale_removed": 0,
            "stale_names": [],
        }

        # Process each resource type (only those with templates or explicitly requested)
        types_to_sync = resource_types if resource_types else list(discovered.keys())
        for resource_type, templates in discovered.items():
            # Skip resource types not in the filter
            if resource_type not in types_to_sync:
                continue

            provider = self.provider_adapter.providers.get(resource_type)
            if not provider:
                logger.warning(f"No provider for resource type: {resource_type}")
                continue

            logger.info(f"Syncing {resource_type} resources...")

            # Fetch all deployed resources of this type from CrowdStrike
            deployed = self._fetch_all_deployed(provider, resource_type)
            stats["total_fetched"] += len(deployed)

            # Build remote lookups: by rule_id and by name.
            # Identity comes from the provider's complete rule_id index where one
            # exists — `deployed` is keyed by name, and CrowdStrike names are not
            # unique, so rules sharing a name overwrite each other there.
            remote_by_rule_id = {}
            remote_by_name = {}
            provider_id_index = getattr(provider, "get_remote_rules_by_id", None)
            if callable(provider_id_index):
                candidate = provider_id_index()
                if isinstance(candidate, dict):
                    remote_by_rule_id = dict(candidate)
            for remote_name, remote_data in deployed.items():
                rid = remote_data.get("rule_id", "")
                if rid:
                    remote_by_rule_id.setdefault(rid, remote_data)
                remote_by_name[remote_name] = remote_data

            # Track which remote resources get matched (for unmatched reporting)
            matched_remote_rule_ids = set()

            # For each template, find its remote resource using the best available key:
            # 1. State entry's rule_id (most reliable - immutable API ID)
            # 2. Template display_name matched against remote name (fallback)
            for template in templates:
                resource_id = template.name  # Stable IaC key (resource_id)
                display_name = template.display_name or resource_id

                # Try to find existing state entry (may be keyed by resource_id or display_name)
                state_entry = self.state_manager.get_resource(resource_type, resource_id)
                if not state_entry:
                    state_entry = self.state_manager.get_resource(resource_type, display_name)

                remote_state = None
                match_method = None

                # Strategy 1: Match via rule_id from existing state entry
                if state_entry:
                    pm = state_entry.provider_metadata if isinstance(state_entry.provider_metadata, dict) else {}
                    state_rule_id = pm.get("rule_id", "") or state_entry.id
                    if state_rule_id and state_rule_id in remote_by_rule_id:
                        remote_state = remote_by_rule_id[state_rule_id]
                        match_method = f"rule_id={state_rule_id}"

                # Strategy 2: Match via display_name against remote resource names
                if not remote_state:
                    if display_name in remote_by_name:
                        remote_state = remote_by_name[display_name]
                        match_method = f"display_name='{display_name}'"

                if remote_state:
                    stats["matched_templates"] += 1
                    rid = remote_state.get("rule_id", "")
                    if rid:
                        matched_remote_rule_ids.add(rid)

                    # Preserve existing content_hash if the resource is already in state.
                    # The content_hash represents what was last DEPLOYED (set by apply).
                    # If sync overwrites it with the current template hash, pending
                    # template changes become invisible to plan() (hash matches template).
                    existing_state = self.state_manager.get_resource(resource_type, resource_id)
                    if existing_state and existing_state.content_hash:
                        content_hash = existing_state.content_hash
                    else:
                        # New resource not yet in state - seed hash from template
                        content_hash = provider.compute_content_hash(template.template_data)
                    template_path = str(template.file_path)

                    # Create ResourceState object
                    resource_state = ResourceState(
                        type=resource_type,
                        # rule_id is permanent; `id` is a per-version ULID that stops
                        # addressing the rule after its next update.
                        id=StateSynchronizer.select_persisted_id(remote_state) or "",
                        content_hash=content_hash,
                        template_path=template_path,
                        deployed_at=datetime.now(timezone.utc).isoformat(),
                        last_modified=datetime.now(timezone.utc).isoformat(),
                        provider_metadata=remote_state,
                        dependencies=[],
                        display_name=display_name,
                    )

                    # Write state using resource_id as the key
                    state_key = resource_id
                    self.state_manager.set_resource(
                        resource_type=resource_type, resource_name=state_key, resource_state=resource_state
                    )
                    stats["updated"] += 1

                    # Clean up old display_name key if migrating to resource_id key
                    if state_key != display_name:
                        old_state = self.state_manager.export_to_dict()
                        old_resources = old_state.get("resources", {}).get(resource_type, {})
                        if display_name in old_resources:
                            del old_resources[display_name]
                            logger.info(f"Migrated state key: '{display_name}' -> '{state_key}'")

                    logger.debug(f"Synced {resource_type}.{state_key} via {match_method}")
                else:
                    logger.debug(f"Template {resource_id} ({display_name}) has no matching remote resource")

            # Count unmatched remote resources (deployed but no template)
            for remote_name, remote_data in deployed.items():
                rid = remote_data.get("rule_id", "")
                if rid and rid not in matched_remote_rule_ids:
                    stats["unmatched"] += 1
                    stats["unmatched_names"].append(remote_name)
                elif not rid and remote_name not in {t.display_name for t in templates}:
                    stats["unmatched"] += 1
                    stats["unmatched_names"].append(remote_name)

            # Verify state entries - remove stale ones (no template AND no remote)
            verify_stats = self._verify_state_entries(resource_type, deployed, templates)
            stats["stale_removed"] += verify_stats["stale_removed"]
            stats["stale_names"].extend(verify_stats["stale_names"])

        # Save updated state
        self.state_manager.save()

        logger.info(
            f"Sync complete: {stats['total_fetched']} fetched, "
            f"{stats['matched_templates']} matched, {stats['unmatched']} unmatched"
        )

        return stats

    def drift(
        self,
        resource_types: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        names: Optional[List[str]] = None,
    ) -> DriftReport:
        """
        Detect drift between IaC templates, local state, and remote CrowdStrike resources.

        Read-only operation - never modifies state.

        Args:
            resource_types: Filter by resource types
            tags: Filter by tags
            names: Filter by name patterns

        Returns:
            DriftReport with categorized findings
        """
        detector = DriftDetector(
            falcon_client=self.falcon,
            state_manager=self.state_manager,
            provider_adapter=self.provider_adapter,
            template_discovery=self.template_discovery,
        )
        return detector.detect(resource_types=resource_types, tags=tags, names=names)

    def import_resources(
        self, resource_types: Optional[List[str]] = None, names: Optional[List[str]] = None, plan_only: bool = False
    ) -> Dict[str, Any]:
        """
        Import existing CrowdStrike resources as YAML template files.

        Fetches all remote resources, converts them to template format using
        each provider's to_template() method, and writes YAML files to the
        resources/ directory.

        Args:
            resource_types: Filter by resource types (None = all importable types)
            names: Filter by name patterns (glob syntax)
            plan_only: If True, show what would be imported without writing files

        Returns:
            Dictionary with import statistics:
            {
                'total_fetched': int,
                'imported': int,
                'skipped_existing': int,
                'skipped_unsupported': int,
                'errors': list[str],
                'imported_files': list[str],
            }
        """
        import fnmatch

        stats = {
            "total_fetched": 0,
            "imported": 0,
            "skipped_existing": 0,
            "skipped_unsupported": 0,
            "errors": [],
            "imported_files": [],
        }

        # Determine which resource types to import
        importable_types = []
        for rt, provider in self.provider_adapter.providers.items():
            # Check if provider supports import (has to_template that isn't the base NotImplementedError)
            try:
                # Test if the method raises NotImplementedError
                if (
                    hasattr(provider, "to_template")
                    and provider.__class__.to_template is not provider.__class__.__mro__[-2].to_template
                ):
                    importable_types.append(rt)
            except (AttributeError, IndexError):
                # Safer check: try calling with empty dict and catch NotImplementedError
                pass

        # Simpler approach: just check each provider
        importable_types = []
        for rt, provider in self.provider_adapter.providers.items():
            try:
                provider.to_template({"name": "__test__"})
                importable_types.append(rt)
            except NotImplementedError:
                continue
            except Exception:
                # Other errors mean the method exists but failed on test data — that's OK
                importable_types.append(rt)

        if resource_types:
            types_to_import = [t for t in resource_types if t in importable_types]
            unsupported = [t for t in resource_types if t not in importable_types]
            for t in unsupported:
                logger.warning(f"Resource type '{t}' does not support import")
                stats["skipped_unsupported"] += 1
        else:
            types_to_import = importable_types

        if not types_to_import:
            logger.warning("No importable resource types found")
            return stats

        logger.info(f"Importing resource types: {', '.join(types_to_import)}")

        # Resolve project root for writing files
        resources_dir = self.template_discovery.resources_dir

        for resource_type in types_to_import:
            provider = self.provider_adapter.providers[resource_type]

            logger.info(f"Fetching remote {resource_type} resources...")

            # Fetch all remote resources using the same pattern as _fetch_all_deployed
            remote_resources = self._fetch_all_deployed(provider, resource_type)
            stats["total_fetched"] += len(remote_resources)

            if not remote_resources:
                logger.info(f"No remote {resource_type} resources found")
                continue

            logger.info(f"Found {len(remote_resources)} remote {resource_type} resources")

            for remote_name, remote_data in remote_resources.items():
                # Apply name filter if specified
                if names:
                    matched = False
                    for pattern in names:
                        if fnmatch.fnmatch(remote_name, pattern) or fnmatch.fnmatch(
                            remote_name.lower(), pattern.lower()
                        ):
                            matched = True
                            break
                    if not matched:
                        continue

                try:
                    # Convert to template
                    template = provider.to_template(remote_data)

                    # Get suggested path
                    relative_path = provider.suggest_path(template)
                    full_path = resources_dir / relative_path

                    # Skip if file already exists
                    if full_path.exists():
                        logger.debug(f"Skipping existing: {relative_path}")
                        stats["skipped_existing"] += 1
                        continue

                    if plan_only:
                        logger.info(f"[plan] Would import: {relative_path}")
                        stats["imported"] += 1
                        stats["imported_files"].append(str(relative_path))
                        continue

                    # Create directory if needed
                    full_path.parent.mkdir(parents=True, exist_ok=True)

                    # Write YAML file
                    with open(full_path, "w") as f:
                        yaml.dump(template, f, default_flow_style=False, allow_unicode=True, sort_keys=False, width=120)

                    logger.info(f"Imported: {relative_path}")
                    stats["imported"] += 1
                    stats["imported_files"].append(str(relative_path))

                    # Register in state
                    resource_id_key = template.get("resource_id", self._name_to_resource_id(remote_name))
                    display_name = template.get("name", remote_name)
                    content_hash = provider.compute_content_hash(template)

                    resource_state = ResourceState(
                        type=resource_type,
                        id=remote_data.get("rule_id", remote_data.get("id", remote_name)),
                        content_hash=content_hash,
                        template_path=str(relative_path),
                        deployed_at=datetime.now(timezone.utc).isoformat(),
                        last_modified=datetime.now(timezone.utc).isoformat(),
                        provider_metadata={
                            "imported": True,
                            "rule_id": remote_data.get("rule_id", ""),
                            "id": remote_data.get("id", ""),
                        },
                        dependencies=[],
                        display_name=display_name,
                    )

                    self.state_manager.set_resource(resource_type, resource_id_key, resource_state)

                except NotImplementedError:
                    stats["skipped_unsupported"] += 1
                except Exception as e:
                    error_msg = f"Failed to import {resource_type}.{remote_name}: {e}"
                    logger.error(error_msg)
                    stats["errors"].append(error_msg)

        # Save state after import
        if not plan_only and stats["imported"] > 0:
            self.state_manager.save()
            logger.info(f"State saved with {stats['imported']} imported resources")

        return stats

    @staticmethod
    def _name_to_resource_id(name: str) -> str:
        """Convert display name to snake_case resource_id (delegated to BaseResourceProvider)."""
        from talonctl.core.base_provider import BaseResourceProvider

        return BaseResourceProvider._name_to_resource_id(name)

    def _verify_state_entries(
        self, resource_type: str, deployed: Dict[str, Dict[str, Any]], templates: List[Any]
    ) -> Dict[str, Any]:
        """
        Verify state entries against remote resources and remove stale ones.

        A state entry is considered stale if:
        - It has no matching template AND
        - It has no matching remote resource (checked by rule_id and by name)

        Args:
            resource_type: The resource type being verified
            deployed: Dict of remote resources keyed by name
            templates: List of DiscoveredTemplate for this type

        Returns:
            Dict with verification stats: {verified, stale_removed, stale_names}
        """
        stats = {"verified": 0, "stale_removed": 0, "stale_names": []}

        # Get all state entries for this type
        state_entries = self.state_manager.get_all_resources(resource_type)
        template_names = {t.name for t in templates}
        template_display_names = {t.display_name for t in templates if t.display_name and t.display_name != t.name}

        # Build remote lookup by rule_id for robust matching
        remote_rule_ids = set()
        for remote_data in deployed.values():
            rid = remote_data.get("rule_id", "")
            if rid:
                remote_rule_ids.add(rid)

        for full_id, state_entry in state_entries.items():
            # Extract resource name from "type.name"
            name = full_id.split(".", 1)[1] if "." in full_id else full_id

            # Check if template exists for this state entry
            has_template = name in template_names
            if not has_template and state_entry.display_name:
                has_template = state_entry.display_name in template_display_names

            if has_template:
                stats["verified"] += 1
                continue

            # No template - check if resource still exists remotely
            # Check by rule_id first (most reliable)
            pm = state_entry.provider_metadata if isinstance(state_entry.provider_metadata, dict) else {}
            state_rule_id = pm.get("rule_id", "") or state_entry.id
            has_remote = state_rule_id in remote_rule_ids if state_rule_id else False

            # Fall back to name matching
            if not has_remote:
                has_remote = name in deployed
            if not has_remote and state_entry.display_name:
                has_remote = state_entry.display_name in deployed

            if has_remote:
                stats["verified"] += 1
                continue

            # Stale: no template AND no remote resource -> remove
            display = state_entry.display_name or name
            logger.info(f"Removing stale state entry: {resource_type}.{name} ({display})")
            self.state_manager.delete_resource(resource_type, name)
            stats["stale_removed"] += 1
            stats["stale_names"].append(display)

        return stats

    def _fetch_all_deployed(self, provider: Any, resource_type: str) -> Dict[str, Dict[str, Any]]:
        """
        Fetch all deployed resources of a given type from CrowdStrike

        Args:
            provider: Resource provider
            resource_type: Type of resource to fetch

        Returns:
            Dictionary mapping resource name to remote state
        """
        deployed = {}

        try:
            if resource_type == "detection":
                # Use provider's paginated fetch method
                if hasattr(provider, "_fetch_all_remote_rules"):
                    deployed = provider._fetch_all_remote_rules()
                    logger.info(f"Fetched {len(deployed)} detection rules from CrowdStrike")
                else:
                    logger.warning("Detection provider missing _fetch_all_remote_rules method")

            elif resource_type == "workflow":
                # Fetch all workflows via provider method
                if hasattr(provider, "_fetch_all_remote_workflows"):
                    deployed = provider._fetch_all_remote_workflows()
                    logger.info(f"Fetched {len(deployed)} workflows from CrowdStrike")
                else:
                    logger.warning("Workflow provider missing _fetch_all_remote_workflows method")

            elif resource_type == "rtr_script":
                # Fetch all RTR scripts via provider method
                if hasattr(provider, "_fetch_all_remote_scripts"):
                    deployed = provider._fetch_all_remote_scripts()
                    logger.info(f"Fetched {len(deployed)} RTR scripts from CrowdStrike")
                else:
                    logger.warning("RTR script provider missing _fetch_all_remote_scripts method")

            elif resource_type == "rtr_put_file":
                # Fetch all RTR put files via provider method
                if hasattr(provider, "_fetch_all_remote_put_files"):
                    deployed = provider._fetch_all_remote_put_files()
                    logger.info(f"Fetched {len(deployed)} RTR put files from CrowdStrike")
                else:
                    logger.warning("RTR put file provider missing _fetch_all_remote_put_files method")

            elif resource_type == "saved_search":
                # Fetch all saved searches via provider method
                if hasattr(provider, "_fetch_all_remote_searches"):
                    deployed = provider._fetch_all_remote_searches()
                    logger.info(f"Fetched {len(deployed)} saved searches from CrowdStrike")
                else:
                    logger.warning("Saved search provider missing _fetch_all_remote_searches method")

            elif resource_type == "lookup_file":
                # Fetch all lookup files via provider method
                if hasattr(provider, "_fetch_all_remote_lookup_files"):
                    deployed = provider._fetch_all_remote_lookup_files()
                    logger.info(f"Fetched {len(deployed)} lookup files from CrowdStrike")
                else:
                    logger.warning("Lookup file provider missing _fetch_all_remote_lookup_files method")

            elif resource_type == "dashboard":
                if hasattr(provider, "_fetch_all_remote_dashboards"):
                    deployed = provider._fetch_all_remote_dashboards()
                    logger.info(f"Fetched {len(deployed)} dashboards from CrowdStrike")
                else:
                    logger.warning("Dashboard provider missing _fetch_all_remote_dashboards method")

            elif resource_type == "case_notification_group":
                if hasattr(provider, "_fetch_all_remote_notification_groups"):
                    deployed = provider._fetch_all_remote_notification_groups()
                    logger.info(f"Fetched {len(deployed)} case notification groups from CrowdStrike")
                else:
                    logger.warning(
                        "Case notification group provider missing _fetch_all_remote_notification_groups method"
                    )

            elif resource_type == "case_sla":
                if hasattr(provider, "_fetch_all_remote_slas"):
                    deployed = provider._fetch_all_remote_slas()
                    logger.info(f"Fetched {len(deployed)} case SLAs from CrowdStrike")
                else:
                    logger.warning("Case SLA provider missing _fetch_all_remote_slas method")

            elif resource_type == "case_template":
                if hasattr(provider, "_fetch_all_remote_templates"):
                    deployed = provider._fetch_all_remote_templates()
                    logger.info(f"Fetched {len(deployed)} case templates from CrowdStrike")
                else:
                    logger.warning("Case template provider missing _fetch_all_remote_templates method")

        except Exception as e:
            logger.error(f"Error fetching {resource_type} resources: {e}")

        return deployed
