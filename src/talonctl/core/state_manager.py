"""
State Manager v4.0

Manages the deployment state file for all resources across all providers.
Supports optional remote state sync to CrowdStrike NGSIEM lookup files.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict, fields
import logging

from talonctl.core.resource_graph import ResourceGraph

logger = logging.getLogger(__name__)


@dataclass
class ResourceState:
    """Represents the state of a single deployed resource"""

    type: str  # Resource type (detection, workflow, saved_search, etc.)
    id: str  # Unique ID from CrowdStrike
    content_hash: str  # SHA256 hash for change detection
    template_path: str  # Path to the template file
    deployed_at: str  # ISO8601 timestamp
    last_modified: str  # ISO8601 timestamp
    provider_metadata: Dict[str, Any]  # Provider-specific data
    dependencies: List[str]  # Resource IDs this depends on (format: "type.name")
    display_name: Optional[str] = None  # Human-readable display name (from template 'name' field)


class StateManager:
    """
    Manages the unified state file for all deployed resources.

    State file format v4.0:
    {
        "version": "4.0",
        "last_updated": "ISO8601",
        "metadata": {
            "deployed_by": "user@example.com",
            "deployment_id": "abc123",
            "environment": "production"
        },
        "resources": {
            "detection": {
                "aws_root_login": { ResourceState },
                ...
            },
            "workflow": {
                "aws_root_login_notify": { ResourceState },
                ...
            },
            ...
        },
        "resource_graph": {
            "nodes": [...],
            "edges": [["source", "target"], ...]
        }
    }
    """

    STATE_VERSION = "4.0"

    def __init__(
        self,
        state_file_path: Path,
        falcon_client=None,
        remote_state_enabled: bool = False,
        remote_state_search_domain: str = "falcon",
        remote_state_filename: str = "unified_deployment_state.json",
    ):
        """
        Initialize state manager.

        Args:
            state_file_path: Path to the state file
            falcon_client: Optional FalconPy APIHarnessV2 instance for remote state sync
            remote_state_enabled: Whether to sync state with NGSIEM lookup files
            remote_state_search_domain: NGSIEM search domain for remote state (falcon, all, third-party, etc.)
            remote_state_filename: Filename for remote state in NGSIEM
        """
        self.state_file_path = state_file_path
        self.state_file_path.parent.mkdir(parents=True, exist_ok=True)

        # Remote state configuration
        self.falcon_client = falcon_client
        self.remote_state_enabled = remote_state_enabled
        self.remote_state_search_domain = remote_state_search_domain
        self.remote_state_filename = remote_state_filename

        # Override from environment
        if os.getenv("REMOTE_STATE_ENABLED", "").lower() in ("true", "1", "yes"):
            self.remote_state_enabled = True
        if os.getenv("NGSIEM_SEARCH_DOMAIN"):
            self.remote_state_search_domain = os.getenv("NGSIEM_SEARCH_DOMAIN")

        self._state = self._migrate_to_v4(self._load_state())

    def _load_state(self) -> Dict[str, Any]:
        """
        Load state from disk.
        If remote state is enabled, merges remote state with local state.

        Returns:
            State dictionary
        """
        # Load local state from disk first
        local_state = None

        if self.state_file_path.exists() and self.state_file_path.stat().st_size > 0:
            try:
                with open(self.state_file_path, "r") as f:
                    local_state = json.load(f)

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse state file: {e}")
                raise ValueError(f"Corrupt state file: {e}")
            except Exception as e:
                logger.error(f"Error loading local state: {e}")
                raise
        else:
            logger.info("No local state file found")

        # Try to sync from remote state if enabled
        if self.remote_state_enabled and self.falcon_client:
            remote_state = self._sync_from_remote()
            if remote_state:
                if local_state:
                    # Merge remote state with local state
                    logger.info("Merging remote state with local state")
                    merged_state = self._merge_remote_state(local_state, remote_state)
                    # Save merged state to local disk
                    self._save_state(merged_state)
                    return merged_state
                else:
                    # No local state - use remote state as-is
                    logger.info("Using remote state (no local state found)")
                    self._save_state(remote_state)
                    return remote_state
            elif local_state:
                # Remote sync failed but we have local state
                logger.info("Remote sync failed, using local state")
                return local_state

        # Return local state if we have it, otherwise initialize
        if local_state:
            return local_state
        else:
            logger.info("Initializing new state")
            return self._initialize_state()

    def _migrate_to_v4(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Lazily, non-destructively upgrade a pre-v4 state dict to v4 in memory.

        Runs AFTER the local/remote load+merge (a remote file can re-inject an
        older version via _merge_remote_state, so this must run last). Stamps the
        current STATE_VERSION and reports — but never moves, re-keys, or deletes —
        any ambiguous space-containing keys. Persistence is deferred to save().
        """
        if state.get("version") == self.STATE_VERSION:
            return state

        resources = state.get("resources", {})
        ambiguous: List[str] = []
        if isinstance(resources, dict):
            for rtype, entries in resources.items():
                if isinstance(entries, dict):
                    ambiguous.extend(f"{rtype}.{k}" for k in entries if " " in k)

        state["version"] = self.STATE_VERSION
        if ambiguous:
            logger.warning(
                "State upgraded to v%s with %d ambiguous display-name key(s) left "
                "untouched; a future `talonctl migrate` will reconcile them against "
                "templates: %s",
                self.STATE_VERSION,
                len(ambiguous),
                ", ".join(sorted(ambiguous)),
            )
        return state

    def _initialize_state(self) -> Dict[str, Any]:
        """
        Initialize a new empty state.

        Returns:
            New state dictionary
        """
        return {
            "version": self.STATE_VERSION,
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "metadata": {},
            "resources": {},
            "resource_graph": {"nodes": [], "edges": []},
        }

    def _sync_from_remote(self) -> Optional[Dict[str, Any]]:
        """
        Sync state from NGSIEM cloud storage (lookup file).

        Returns:
            State dictionary from remote, or None if not available
        """
        if not self.falcon_client:
            logger.debug("No falcon client available for remote state sync")
            return None

        try:
            # Import here to avoid circular dependency
            from talonctl.utils.ngsiem_files import download_json

            logger.info(
                f"Syncing state from NGSIEM lookup file "
                f"(search_domain={self.remote_state_search_domain}, "
                f"filename={self.remote_state_filename})"
            )

            remote_state, error = download_json(
                self.falcon_client, filename=self.remote_state_filename, search_domain=self.remote_state_search_domain
            )

            if error:
                if "not found" in error.lower():
                    logger.debug("No remote state found (expected for first deployment)")
                else:
                    logger.warning(f"Remote state sync failed: {error}")
                    logger.info("Falling back to local state")
                return None

            if not remote_state:
                logger.debug("No remote state found (expected for first deployment)")
                return None

            if not isinstance(remote_state, dict):
                logger.warning(f"Remote state has unexpected type: {type(remote_state)}, ignoring")
                return None

            # Validate it's a valid state file
            if "version" in remote_state and "resources" in remote_state:
                logger.info("Successfully loaded remote state")
                return remote_state
            else:
                logger.warning(
                    f"Remote state has invalid format (missing keys), ignoring. Keys: {list(remote_state.keys())}"
                )
                return None

        except ImportError as e:
            logger.warning(f"Remote state sync disabled: ngsiem_files module not available ({e})")
            return None
        except Exception as e:
            logger.warning(f"Remote state sync failed: {e}")
            logger.info("Falling back to local state")
            return None

    @staticmethod
    def _get_resource_unique_id(resource: Dict[str, Any]) -> Optional[str]:
        """
        Extract the unique CrowdStrike resource ID from a state entry.

        Checks provider_metadata.rule_id first (most reliable for detections),
        then falls back to the top-level 'id' field.

        Returns:
            The unique resource ID, or None if not found
        """
        pm = resource.get("provider_metadata", {})
        if isinstance(pm, dict):
            rid = pm.get("rule_id")
            if rid:
                return rid
        top_id = resource.get("id", "")
        return top_id if top_id else None

    def _merge_remote_state(self, local_state: Dict[str, Any], remote_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge remote state with local state, preserving local template tracking.

        Remote state provides source of truth for deployed resources (IDs, provider metadata).
        Local state provides template tracking (template_path, content_hash).

        Deduplicates stale display-name keys from remote state that refer to the same
        underlying CrowdStrike resource as a resource_id key in local state. This prevents
        the sync() migration from running on every invocation.

        Args:
            local_state: State from local disk
            remote_state: State from NGSIEM lookup file

        Returns:
            Merged state dictionary
        """
        logger.info("Merging remote state with local state...")

        # Start with remote state structure (version, metadata, graph)
        merged = {
            "version": remote_state.get("version", self.STATE_VERSION),
            "last_updated": remote_state.get("last_updated", datetime.now(timezone.utc).isoformat()),
            "metadata": remote_state.get("metadata", {}),
            "resource_graph": remote_state.get("resource_graph", {"nodes": [], "edges": []}),
            "resources": {},
        }

        # Get resources from both states
        local_resources = local_state.get("resources", {})
        remote_resources = remote_state.get("resources", {})

        # Merge resources by type
        all_resource_types = set(local_resources.keys()) | set(remote_resources.keys())

        dedup_count = 0

        for resource_type in all_resource_types:
            merged["resources"][resource_type] = {}

            local_type_resources = local_resources.get(resource_type, {})
            remote_type_resources = remote_resources.get(resource_type, {})

            # Build a map of unique CrowdStrike resource IDs -> all state keys
            # that reference them. When the same resource ID appears under multiple
            # state keys (e.g. both a display-name key and a resource_id key), we
            # can identify and skip the stale duplicate.
            #
            # We combine local + remote to catch duplicates in both sources.
            all_entries: Dict[str, Dict[str, Any]] = {}
            for key, resource in local_type_resources.items():
                all_entries.setdefault(key, {}).update(resource)
            for key, resource in remote_type_resources.items():
                if key not in all_entries:
                    all_entries[key] = dict(resource)

            # Map: unique_id -> list of state keys referencing it
            uid_to_keys: Dict[str, List[str]] = {}
            for key, resource in all_entries.items():
                uid = self._get_resource_unique_id(resource)
                if uid:
                    uid_to_keys.setdefault(uid, []).append(key)

            # For each unique_id with multiple keys, determine the canonical key.
            # The canonical key is the one that exists in local state AND looks like
            # a resource_id (not a human-readable display name with spaces/parens).
            stale_keys: Set[str] = set()
            for uid, keys in uid_to_keys.items():
                if len(keys) <= 1:
                    continue
                # Prefer keys that exist in local state and don't contain spaces
                # (resource_id keys are slugified, display-name keys have spaces)
                canonical = None
                for k in keys:
                    if k in local_type_resources and " " not in k:
                        canonical = k
                        break
                if not canonical:
                    # Fallback: prefer any key without spaces
                    for k in keys:
                        if " " not in k:
                            canonical = k
                            break
                if canonical:
                    for k in keys:
                        if k != canonical:
                            stale_keys.add(k)
                            logger.debug(f"Marking stale key '{k}' (duplicate of '{canonical}' via id={uid})")

            # Get all resource names from both local and remote
            all_resource_names = set(local_type_resources.keys()) | set(remote_type_resources.keys())

            for resource_name in all_resource_names:
                # Skip stale display-name keys that duplicate a resource_id key
                if resource_name in stale_keys:
                    dedup_count += 1
                    continue

                local_resource = local_type_resources.get(resource_name)
                remote_resource = remote_type_resources.get(resource_name)

                if local_resource and remote_resource:
                    # Resource exists in BOTH - merge with local template tracking
                    merged["resources"][resource_type][resource_name] = {
                        "type": resource_type,
                        "id": remote_resource.get("id", local_resource.get("id", "")),
                        "content_hash": local_resource.get("content_hash", ""),  # Keep local hash
                        "template_path": local_resource.get("template_path", ""),  # Keep local path
                        "deployed_at": remote_resource.get("deployed_at", local_resource.get("deployed_at", "")),
                        "last_modified": remote_resource.get("last_modified", local_resource.get("last_modified", "")),
                        "provider_metadata": remote_resource.get("provider_metadata", {}),  # Use remote metadata
                        "dependencies": local_resource.get("dependencies", []),
                    }
                    logger.debug(f"Merged {resource_type}.{resource_name} (kept local tracking)")

                elif remote_resource:
                    # Resource exists in REMOTE only - skip if no template tracking
                    # IaC state only tracks resources with templates
                    if remote_resource.get("template_path") or remote_resource.get("content_hash"):
                        # Has some template tracking - preserve it
                        merged["resources"][resource_type][resource_name] = remote_resource
                        logger.debug(f"Added {resource_type}.{resource_name} from remote (has template tracking)")
                    else:
                        # No template tracking - skip (not IaC-managed)
                        logger.debug(f"Skipping {resource_type}.{resource_name} from remote (no IaC template)")

                elif local_resource:
                    # Resource exists in LOCAL only - keep as-is (newly added template not yet deployed)
                    merged["resources"][resource_type][resource_name] = local_resource
                    logger.debug(f"Kept {resource_type}.{resource_name} from local (not yet deployed)")

        if dedup_count:
            logger.info(f"Deduplicated {dedup_count} stale display-name keys from remote state")

        logger.info(
            f"State merge complete: {len([r for t in merged['resources'].values() for r in t.keys()])} total resources"
        )

        return merged

    def _sync_to_remote(self) -> bool:
        """
        Upload current state to NGSIEM cloud storage (lookup file).

        Returns:
            True if successful, False otherwise
        """
        if not self.falcon_client:
            logger.debug("No falcon client available for remote state sync")
            return False

        try:
            # Import here to avoid circular dependency
            from talonctl.utils.ngsiem_files import upload_json_data

            logger.info(
                f"Uploading state to NGSIEM lookup file "
                f"(search_domain={self.remote_state_search_domain}, "
                f"filename={self.remote_state_filename})"
            )

            response = upload_json_data(
                self.falcon_client,
                data=self._state,
                search_domain=self.remote_state_search_domain,
                filename=self.remote_state_filename,
            )

            # Check response
            if isinstance(response, dict):
                status_code = response.get("status_code")
                if status_code in (200, 201):
                    logger.info("Successfully uploaded state to remote")
                    return True
                elif "errors" in response and response["errors"]:
                    errors = response.get("errors", [])
                    error_msg = (
                        errors[0].get("message", str(errors[0])) if isinstance(errors[0], dict) else str(errors[0])
                    )
                    logger.warning(f"Failed to upload state: {error_msg}")
                    return False
                else:
                    # No explicit error, assume success
                    logger.info("State uploaded to remote")
                    return True

            logger.info("State uploaded to remote")
            return True

        except ImportError as e:
            logger.warning(f"Remote state sync disabled: ngsiem_files module not available ({e})")
            return False
        except Exception as e:
            logger.warning(f"Could not upload state to NGSIEM cloud: {e}")
            logger.info("State saved locally only")
            return False

    def _save_state(self, state: Optional[Dict[str, Any]] = None) -> None:
        """
        Save state to disk with atomic write guarantees.

        Uses temp file + fsync + rename pattern to ensure state file
        integrity even in case of power loss or system crash.

        Args:
            state: State to save (defaults to self._state)
        """
        state = state or self._state
        state["last_updated"] = datetime.now(timezone.utc).isoformat()

        try:
            # Write atomically via temp file with fsync for durability
            temp_path = self.state_file_path.with_suffix(".tmp")
            with open(temp_path, "w") as f:
                json.dump(state, f, indent=2, sort_keys=True)
                f.flush()  # Flush to OS buffer
                os.fsync(f.fileno())  # Force write to disk

            # Atomic rename (POSIX guarantee)
            temp_path.replace(self.state_file_path)
            logger.debug(f"State saved atomically to {self.state_file_path}")

        except Exception as e:
            logger.error(f"Failed to save state: {e}")
            # Clean up temp file if it exists
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            raise

    def save(self) -> None:
        """
        Save the current state to disk and optionally sync to remote.
        """
        self._save_state()

        # Sync to remote state if enabled
        if self.remote_state_enabled and self.falcon_client:
            self._sync_to_remote()

    @staticmethod
    def _backfill_state_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Reconcile a raw state entry with the current ResourceState schema.

        Older state entries may be missing fields that were added in later versions
        (e.g., provider_metadata, display_name), and may still carry fields that have
        since been retired (e.g., last_deployed). Both directions must be handled so
        ResourceState(**data) always succeeds: a retired key used to raise TypeError,
        which drift caught per resource type and reported as an error, silently
        skipping drift detection for that entire type.
        """
        data.setdefault("provider_metadata", {})

        known = {f.name for f in fields(ResourceState)}
        retired = set(data) - known
        if retired:
            logger.debug(f"Dropping retired state field(s) {sorted(retired)} from entry (schema drift)")
            data = {k: v for k, v in data.items() if k in known}

        return data

    def get_resource(self, resource_type: str, resource_name: str) -> Optional[ResourceState]:
        """
        Get the state for a specific resource.

        Args:
            resource_type: Type of resource (detection, workflow, etc.)
            resource_name: Stable resource identifier (from template 'resource_id' field,
                          or fallback to 'name' for backward compatibility)

        Returns:
            ResourceState or None if not found
        """
        resources = self._state.get("resources", {}).get(resource_type, {})
        resource_data = resources.get(resource_name)

        if not resource_data:
            return None

        return ResourceState(**self._backfill_state_data(resource_data))

    def set_resource(self, resource_type: str, resource_name: str, resource_state: ResourceState) -> None:
        """
        Update or create a resource in state.

        Args:
            resource_type: Type of resource
            resource_name: Stable resource identifier (from template 'resource_id' field,
                          or fallback to 'name' for backward compatibility)
            resource_state: State to save
        """
        if resource_type not in self._state["resources"]:
            self._state["resources"][resource_type] = {}

        self._state["resources"][resource_type][resource_name] = asdict(resource_state)

    def delete_resource(self, resource_type: str, resource_name: str) -> bool:
        """
        Remove a resource from state.

        Args:
            resource_type: Type of resource
            resource_name: Name of the resource

        Returns:
            True if resource was deleted, False if not found
        """
        resources = self._state.get("resources", {}).get(resource_type, {})

        if resource_name in resources:
            del resources[resource_name]
            return True

        return False

    def get_all_resources(self, resource_type: Optional[str] = None) -> Dict[str, ResourceState]:
        """
        Get all resources of a given type, or all resources.

        Args:
            resource_type: Type to filter by, or None for all types

        Returns:
            Dictionary mapping resource IDs (type.name) to ResourceState
        """
        all_resources = {}

        resource_types = [resource_type] if resource_type else self._state.get("resources", {}).keys()

        for rtype in resource_types:
            resources = self._state.get("resources", {}).get(rtype, {})
            for name, data in resources.items():
                resource_id = f"{rtype}.{name}"
                all_resources[resource_id] = ResourceState(**self._backfill_state_data(data))

        return all_resources

    def get_resource_graph(self) -> ResourceGraph:
        """
        Get the resource dependency graph.

        Returns:
            ResourceGraph instance
        """
        graph_data = self._state.get("resource_graph", {})

        # Convert from stored format to ResourceGraph
        graph = ResourceGraph()

        # Add all nodes
        for node in graph_data.get("nodes", []):
            graph.add_node(node)

        # Add all edges (format: [dependent, dependency])
        for edge in graph_data.get("edges", []):
            if len(edge) == 2:
                graph.add_dependency(edge[0], edge[1])

        return graph

    def set_resource_graph(self, graph: ResourceGraph) -> None:
        """
        Update the resource dependency graph in state.

        Args:
            graph: ResourceGraph to save
        """
        self._state["resource_graph"] = {
            "nodes": list(graph.nodes),
            "edges": [[src, dst] for src in graph.nodes for dst in graph.edges.get(src, [])],
        }

    def get_metadata(self) -> Dict[str, Any]:
        """
        Get deployment metadata.

        Returns:
            Metadata dictionary
        """
        return self._state.get("metadata", {}).copy()

    def set_metadata(self, metadata: Dict[str, Any]) -> None:
        """
        Update deployment metadata.

        Args:
            metadata: Metadata to save
        """
        self._state["metadata"] = metadata

    def export_to_dict(self) -> Dict[str, Any]:
        """
        Export entire state as dictionary.

        Returns:
            State dictionary
        """
        return self._state.copy()

    def get_resource_count(self, resource_type: Optional[str] = None) -> int:
        """
        Get count of resources.

        Args:
            resource_type: Type to count, or None for all

        Returns:
            Count of resources
        """
        if resource_type:
            return len(self._state.get("resources", {}).get(resource_type, {}))
        else:
            return sum(len(resources) for resources in self._state.get("resources", {}).values())

    def __repr__(self) -> str:
        """String representation"""
        return f"StateManager(version={self.STATE_VERSION}, resources={self.get_resource_count()})"
