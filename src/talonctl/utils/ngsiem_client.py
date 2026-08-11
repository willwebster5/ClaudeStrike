#!/usr/bin/env python3
"""
CrowdStrike NGSIEM Client Utilities

Provides a unified interface for NGSIEM operations with improved error handling,
retry logic, and result processing.
"""

import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass

from falconpy import NGSIEM
from talonctl.utils.auth import load_credentials

logger = logging.getLogger(__name__)


@dataclass
class QueryResult:
    """Container for NGSIEM query results with metadata"""

    success: bool
    events: List[Dict] = None
    error: str = None
    query: str = None
    duration: float = None
    event_count: int = 0
    search_id: str = None
    repository: str = None

    def __post_init__(self):
        if self.events is None:
            self.events = []
        if self.success and self.events:
            self.event_count = len(self.events)


@dataclass
class QueryConfig:
    """Configuration for NGSIEM queries"""

    timeout: int = 120
    repository: str = "search-all"
    poll_interval: int = 2
    max_retries: int = 3
    retry_delay: int = 5
    add_timestamp: bool = True
    debug: bool = False


class NGSIEMClient:
    """
    Enhanced NGSIEM client with improved error handling, retry logic, and utilities
    """

    def __init__(self, config: Optional[Dict] = None, debug: bool = False):
        """
        Initialize NGSIEM client

        Args:
            config: Optional credentials dict. If None, loads from utils.auth
            debug: Enable debug logging
        """
        self.config = config or load_credentials()
        self.debug = debug
        self._client = None
        self._setup_logging()

        if not self.config:
            raise ValueError("Failed to load CrowdStrike credentials")

    def _setup_logging(self):
        """Setup logging based on debug flag"""
        if self.debug:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

    @property
    def client(self) -> NGSIEM:
        """Lazy-loaded NGSIEM client with connection validation"""
        if self._client is None:
            self._client = NGSIEM(
                client_id=self.config.get("falcon_client_id"),
                client_secret=self.config.get("falcon_client_secret"),
                base_url=self.config.get("base_url", "US2"),
            )

            # Test connection
            if not self._test_connection():
                raise ConnectionError("Failed to establish NGSIEM connection")

        return self._client

    def _test_connection(self) -> bool:
        """Test NGSIEM connection with a simple query"""
        try:
            response = self._client.start_search(
                repository="search-all", query_string="| limit 1", start="1m", is_live=False
            )

            if response.get("status_code") == 200:
                # Stop the test search
                search_id = self._extract_search_id(response)
                if search_id:
                    self._client.stop_search(repository="search-all", id=search_id)
                return True
            return False

        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False

    def _extract_search_id(self, response: Dict) -> Optional[str]:
        """Extract search ID from start_search response"""
        resources = response.get("resources", {})
        if isinstance(resources, dict) and "id" in resources:
            return resources["id"]
        elif response.get("body", {}).get("id"):
            return response["body"]["id"]
        return None

    def _add_query_metadata(self, query: str, config: QueryConfig) -> str:
        """Add metadata to query for audit/debugging purposes"""
        if not config.add_timestamp:
            return query

        timestamp = datetime.now().isoformat()
        metadata = f"// NGSIEM Query - {timestamp}"
        if config.debug:
            metadata += f" | Timeout: {config.timeout}s | Repo: {config.repository}"

        return f"{metadata}\n{query}"

    def execute_query(self, query: str, start_time: str = "1d", config: Optional[QueryConfig] = None) -> QueryResult:
        """
        Execute NGSIEM query with comprehensive error handling and retry logic

        Args:
            query: NGSIEM query string
            start_time: Time range (e.g., "1d", "7d", "1h")
            config: Query configuration options

        Returns:
            QueryResult object with events and metadata
        """
        config = config or QueryConfig()
        start_exec_time = time.time()

        # Add query metadata
        timestamped_query = self._add_query_metadata(query, config)

        for attempt in range(config.max_retries + 1):
            try:
                logger.debug(f"Executing query (attempt {attempt + 1}/{config.max_retries + 1})")

                # Start search
                response = self.client.start_search(
                    repository=config.repository, query_string=timestamped_query, start=start_time, is_live=False
                )

                if response.get("status_code") != 200:
                    body = response.get("body") or {}
                    errors = body.get("errors")
                    status = response.get("status_code")
                    detail = (
                        (errors if isinstance(errors, str) else repr(errors)) if errors else "no detail returned by API"
                    )
                    error_msg = f"Start search failed (status={status}): {detail}"
                    logger.error(error_msg)

                    if attempt < config.max_retries:
                        time.sleep(config.retry_delay)
                        continue

                    return QueryResult(
                        success=False, error=error_msg, query=query, duration=time.time() - start_exec_time
                    )

                # Extract search ID
                search_id = self._extract_search_id(response)
                if not search_id:
                    error_msg = "Failed to extract search ID from response"
                    logger.error(error_msg)

                    if attempt < config.max_retries:
                        time.sleep(config.retry_delay)
                        continue

                    return QueryResult(
                        success=False, error=error_msg, query=query, duration=time.time() - start_exec_time
                    )

                # Poll for completion
                result = self._poll_for_completion(search_id, config, start_exec_time, query)

                if result.success or attempt == config.max_retries:
                    return result

                # Retry on failure
                logger.warning(f"Query attempt {attempt + 1} failed: {result.error}")
                time.sleep(config.retry_delay)

            except Exception as e:
                error_msg = f"Query execution failed: {str(e)}"
                logger.error(error_msg, exc_info=config.debug)

                if attempt == config.max_retries:
                    return QueryResult(
                        success=False, error=error_msg, query=query, duration=time.time() - start_exec_time
                    )

                time.sleep(config.retry_delay)

        # Should not reach here, but just in case
        return QueryResult(
            success=False, error="Max retries exceeded", query=query, duration=time.time() - start_exec_time
        )

    def _poll_for_completion(
        self, search_id: str, config: QueryConfig, start_time: float, original_query: str
    ) -> QueryResult:
        """Poll search status until completion"""
        try:
            while time.time() - start_time < config.timeout:
                status_response = self.client.get_search_status(repository=config.repository, search_id=search_id)

                if status_response.get("status_code") != 200:
                    self._cleanup_search(search_id, config.repository)
                    return QueryResult(
                        success=False,
                        error=f"Status check failed: {status_response.get('status_code')}",
                        query=original_query,
                        duration=time.time() - start_time,
                        search_id=search_id,
                    )

                body = status_response.get("body", {})

                if body.get("done", False):
                    events = body.get("events", [])
                    self._cleanup_search(search_id, config.repository)

                    return QueryResult(
                        success=True,
                        events=events,
                        query=original_query,
                        duration=time.time() - start_time,
                        search_id=search_id,
                        repository=config.repository,
                    )

                if body.get("cancelled", False):
                    self._cleanup_search(search_id, config.repository)
                    return QueryResult(
                        success=False,
                        error="Query was cancelled",
                        query=original_query,
                        duration=time.time() - start_time,
                        search_id=search_id,
                    )

                time.sleep(config.poll_interval)

            # Timeout
            self._cleanup_search(search_id, config.repository)
            return QueryResult(
                success=False,
                error=f"Query timeout after {config.timeout} seconds",
                query=original_query,
                duration=time.time() - start_time,
                search_id=search_id,
            )

        except Exception as e:
            self._cleanup_search(search_id, config.repository)
            return QueryResult(
                success=False,
                error=f"Polling failed: {str(e)}",
                query=original_query,
                duration=time.time() - start_time,
                search_id=search_id,
            )

    def _cleanup_search(self, search_id: str, repository: str):
        """Stop and cleanup search"""
        try:
            self.client.stop_search(repository=repository, id=search_id)
        except Exception as e:
            logger.warning(f"Failed to cleanup search {search_id}: {e}")

    def execute_batch_queries(
        self, queries: List[Union[str, Dict]], start_time: str = "1d", config: Optional[QueryConfig] = None
    ) -> List[QueryResult]:
        """
        Execute multiple queries in batch

        Args:
            queries: List of query strings or dicts with query and metadata
            start_time: Time range for all queries
            config: Query configuration

        Returns:
            List of QueryResult objects
        """
        config = config or QueryConfig()
        results = []

        for i, query_item in enumerate(queries):
            if isinstance(query_item, str):
                query = query_item
                query_name = f"Query_{i + 1}"
            else:
                query = query_item.get("query", "")
                query_name = query_item.get("name", f"Query_{i + 1}")

            logger.info(f"Executing {query_name} ({i + 1}/{len(queries)})")

            result = self.execute_query(query, start_time, config)
            result.query_name = query_name  # Add name for identification
            results.append(result)

            if not result.success:
                logger.warning(f"{query_name} failed: {result.error}")

        return results

    def _raw_syntax_error(self, query: str) -> Optional[str]:
        """
        Re-issue a rejected query outside the SDK to recover LogScale's diagnostic.

        LogScale returns genuinely useful syntax errors — named error codes, the
        offending line, and a caret under the exact column — but serves them as
        ``text/plain``. falconpy only parses ``application/json``; on a JSONDecodeError
        it assumes the body was empty (``_util/_functions.py``, "No response content,
        but a successful request was made") and raises NoContentWarning WITHOUT ever
        reading ``response.text``. The caller then receives a fabricated
        ``{"errors": [{"message": "No content was received for this request."}]}``,
        which is the opposite of what happened and sends authors looking at
        connectivity instead of at their query.

        There is no SDK path to the raw body, so we repeat the request with the
        session falconpy already authenticated — its token and resolved base URL —
        and read the text ourselves. No second OAuth round trip, no duplicated
        credential handling.

        Returns the diagnostic text, or None if it could not be recovered (in which
        case the caller falls back to the status-only message).
        """
        try:
            import requests

            auth = getattr(self.client, "auth_object", None)
            token = getattr(auth, "token_value", None)
            base_url = getattr(auth, "base_url", None)
            if not token or not base_url:
                return None

            resp = requests.post(
                f"{base_url}/humio/api/v1/repositories/search-all/queryjobs",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json={"queryString": query, "start": "1m", "isLive": False},
                timeout=30,
            )
            if resp.status_code == 200:
                # Raced with a transient failure — the query parses after all.
                return None

            detail = (resp.text or "").strip()
            # LogScale wraps the diagnostic in a ``` fence; unwrap so the caret
            # alignment survives without a stray code fence in terminal output.
            if detail.startswith("```") and detail.endswith("```"):
                detail = detail[3:-3].strip("\n")
            return detail or None

        except Exception as exc:  # noqa: BLE001 - diagnostics are best-effort
            logger.debug(f"Could not recover raw LogScale diagnostic: {exc}")
            return None

    def test_query_syntax(self, query: str) -> Dict[str, Any]:
        """
        Test query syntax without executing full search.

        On rejection we surface LogScale's own diagnostic verbatim when we can
        recover it (see _raw_syntax_error), degrading to the SDK's payload and
        then to a status-only message.
        """
        try:
            test_query = query.strip()

            response = self.client.start_search(
                repository="search-all", query_string=test_query, start="1m", is_live=False
            )

            search_id = self._extract_search_id(response)
            if search_id:
                self._cleanup_search(search_id, "search-all")

            status = response.get("status_code")
            if status == 200:
                return {"valid": True, "message": "Query syntax is valid"}

            # Best case: LogScale's own linter output, with caret positions.
            detail = self._raw_syntax_error(test_query)
            if detail:
                return {"valid": False, "message": f"LogScale rejected query (status={status}):\n{detail}"}

            # NGSIEM.start_search() renames the payload key: it pops "body" and
            # re-exposes it as "resources" (falconpy/ngsiem.py). Other service
            # classes keep "body", and the Uber class does not rename at all, so
            # check both rather than assuming either.
            payload = response.get("resources") or response.get("body") or {}
            errors = payload.get("errors") if isinstance(payload, dict) else None

            if errors:
                detail = errors if isinstance(errors, str) else repr(errors)
                message = f"LogScale rejected query (status={status}): {detail}"
            else:
                message = f"LogScale rejected query (status={status}, no detail returned by API)"

            return {"valid": False, "message": message}

        except Exception as e:
            return {"valid": False, "message": f"Syntax test failed: {str(e)}"}

    def get_repositories(self) -> List[str]:
        """
        Get list of available repositories

        Returns:
            List of repository names
        """
        # This would require additional API endpoints that may not be available
        # For now, return common repository names
        return [
            "search-all",
            "falcon",
            "falcon-spotlight",
            "falcon-detections",
            "falcon-cloudtrail",
            "falcon-dns",
            "falcon-proxy",
        ]


# Convenience functions for backward compatibility and simple use cases
def query_ngsiem(
    query: str, start_time: str = "1d", timeout: int = 120, repository: str = "search-all"
) -> Optional[List[Dict]]:
    """
    Simple NGSIEM query function for backward compatibility

    Returns:
        List of events or None if failed
    """
    try:
        client = NGSIEMClient()
        config = QueryConfig(timeout=timeout, repository=repository, debug=False)

        result = client.execute_query(query, start_time, config)
        return result.events if result.success else None

    except Exception as e:
        logger.error(f"Query failed: {e}")
        return None


def query_ngsiem_with_client(
    ngsiem_client, query: str, start_time: str = "1d", timeout: int = 120, repository: str = "search-all"
) -> Optional[List[Dict]]:
    """
    Execute query with existing FalconPy NGSIEM client for backward compatibility

    Returns:
        List of events or None if failed
    """
    # Create wrapper to use existing client
    try:
        # Use the enhanced client but with the provided raw client
        enhanced_client = NGSIEMClient.__new__(NGSIEMClient)
        enhanced_client._client = ngsiem_client
        enhanced_client.config = {}
        enhanced_client.debug = False
        enhanced_client._setup_logging()

        config = QueryConfig(timeout=timeout, repository=repository, debug=False)

        result = enhanced_client.execute_query(query, start_time, config)
        return result.events if result.success else None

    except Exception as e:
        logger.error(f"Query with client failed: {e}")
        return None


def make_health_query_fn(time_range_default: str = "7d"):
    """Build a query callable compatible with ``DetectionHealthChecker``.

    ``DetectionHealthChecker`` expects an ``ngsiem_query_fn`` that is called as
    ``fn(query=<cql>, time_range=<"Nd">)`` and returns a dict it can read with
    ``result.get("events", [])``. ``NGSIEMClient.execute_query`` neither takes a
    ``time_range`` kwarg (it's ``start_time``) nor returns a dict (it returns a
    ``QueryResult`` dataclass), so this adapter bridges both gaps.

    The client is constructed lazily on first use and reused across calls. Any
    auth/query failure degrades to ``{"events": []}`` with a logged warning so
    callers (e.g. ``talonctl health`` in CI without credentials) still produce a
    report rather than crashing.

    Returns:
        A callable ``fn(query, time_range=time_range_default) -> {"events": [...]}``.
    """
    state: Dict[str, Optional["NGSIEMClient"]] = {"client": None}

    def query_fn(query: str, time_range: str = time_range_default) -> Dict[str, List[Dict]]:
        try:
            if state["client"] is None:
                state["client"] = NGSIEMClient()
            result = state["client"].execute_query(query, start_time=time_range)
            return {"events": result.events if result.success else []}
        except Exception as e:
            logger.warning(f"Alert volume query failed, returning empty volumes: {e}")
            return {"events": []}

    return query_fn


# Enhanced query builders for common patterns
class QueryBuilder:
    """Helper class to build common NGSIEM queries"""

    @staticmethod
    def time_range_filter(start: str, end: Optional[str] = None) -> str:
        """Build time range filter"""
        if end:
            return f'@timestamp >= "{start}" AND @timestamp <= "{end}"'
        return f'@timestamp >= "{start}"'

    @staticmethod
    def vendor_filter(vendor: str) -> str:
        """Build vendor filter"""
        return f'#Vendor="{vendor.lower()}"'

    @staticmethod
    def event_outcome_filter(outcome: str = "success") -> str:
        """Build event outcome filter"""
        return f'#event.outcome="{outcome}"'

    @staticmethod
    def build_detection_query(
        vendor: str, event_actions: List[str], time_range: str = "1h", additional_filters: List[str] = None
    ) -> str:
        """Build a standard detection query"""
        filters = [
            QueryBuilder.vendor_filter(vendor),
            QueryBuilder.event_outcome_filter(),
        ]

        if event_actions:
            action_filter = " OR ".join([f'event.action="{action}"' for action in event_actions])
            filters.append(f"({action_filter})")

        if additional_filters:
            filters.extend(additional_filters)

        return " | ".join(filters) + " | sort @timestamp desc"


if __name__ == "__main__":
    # Example usage and testing
    client = NGSIEMClient(debug=True)

    # Test simple query
    result = client.execute_query("| limit 5", "1h")

    if result.success:
        print(f"Query executed successfully in {result.duration:.2f}s")
        print(f"Found {result.event_count} events")
    else:
        print(f"Query failed: {result.error}")

    # Test query builder
    query = QueryBuilder.build_detection_query(
        vendor="aws",
        event_actions=["CreateUser", "AttachUserPolicy"],
        additional_filters=['event.provider="iam.amazonaws.com"'],
    )
    print(f"Built query: {query}")
