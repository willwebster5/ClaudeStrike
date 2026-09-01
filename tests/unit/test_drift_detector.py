"""Unit tests for DriftDetector.

Focus: drift detection rides ``DiscoveredTemplate.template_data`` (the envelope
-> flat-dict compatibility property) and the dict-taking provider methods
(``compute_content_hash``, ``_fetch_all_remote_*``, ``get_raw_remote_rules``).
DriftDetector never touches the Envelope-consuming provider methods
(validate_template / plan_* / apply_*), so it needs no signature change for v2.

These tests exercise the real provider ``compute_content_hash`` (only the Falcon
client is mocked) for BOTH a v1-sourced template (built via the legacy flat dict
through ``make_envelope``) and a v2-sourced template (authored as a ``talon/v2``
document and loaded through ``load_envelopes``), asserting:

  * NO drift when the remote resource's canonical content matches the template.
  * Drift detected when the remote diverges.
"""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from talonctl.core.drift_detector import DriftDetector
from talonctl.core.envelope_loader import load_envelopes
from talonctl.core.state_manager import ResourceState
from talonctl.core.template_discovery import DiscoveredTemplate
from talonctl.providers.detection_provider import DetectionProvider
from talonctl.providers.saved_search_provider import SavedSearchProvider

from tests.unit._helpers import make_envelope


# --------------------------------------------------------------------------- #
# Lightweight stubs that mimic the collaborators DriftDetector reaches into.   #
# --------------------------------------------------------------------------- #
class _StubStateManager:
    """Returns a fixed {type.name: ResourceState} mapping per resource type."""

    def __init__(self, resources_by_type):
        self._resources_by_type = resources_by_type

    def get_all_resources(self, resource_type=None):
        return dict(self._resources_by_type.get(resource_type, {}))


class _StubTemplateDiscovery:
    """Returns fixed discovered templates; ignores filters (none used here)."""

    def __init__(self, discovered):
        self._discovered = discovered

    def discover_all(self, resource_types=None, tags=None, names=None):
        return {rt: list(ts) for rt, ts in self._discovered.items()}


def _make_state_entry(resource_type, name, rule_id):
    return ResourceState(
        type=resource_type,
        id=rule_id,
        content_hash="ignored-by-drift",
        template_path=f"{name}.yaml",
        deployed_at="2024-01-01T00:00:00Z",
        last_modified="2024-01-01T00:00:00Z",
        provider_metadata={"rule_id": rule_id},
        dependencies=[],
        display_name=name,
    )


def _build_detector(*, provider, resource_type, templates, state_entries):
    """Wire a DriftDetector around one real provider and stub collaborators."""
    provider_adapter = SimpleNamespace(providers={resource_type: provider})
    state_manager = _StubStateManager({resource_type: state_entries})
    template_discovery = _StubTemplateDiscovery({resource_type: templates})
    return DriftDetector(
        falcon_client=MagicMock(),
        state_manager=state_manager,
        provider_adapter=provider_adapter,
        template_discovery=template_discovery,
    )


# --------------------------------------------------------------------------- #
# Detection (v1-sourced template via make_envelope)                           #
# --------------------------------------------------------------------------- #
def _detection_flat():
    return {
        "resource_id": "aws_root_login",
        "name": "AWS Root Login",
        "description": "Root account used to sign in",
        "severity": 70,
        "status": "active",
        "search": {"filter": "#repo=base"},
    }


def _detection_remote_raw(flat, *, drift=False):
    """A raw API rule whose canonical content matches `flat` (unless drift)."""
    raw = {
        "name": flat["name"],
        "description": flat["description"],
        "severity": flat["severity"],
        "status": flat["status"],
        "rule_id": "rid-detection-1",
        "search": {"filter": flat["search"]["filter"]},
    }
    if drift:
        raw["description"] = "MANUALLY EDITED IN CONSOLE"
    return raw


@pytest.mark.parametrize("drift", [False, True])
def test_detection_drift_v1_sourced(drift):
    flat = _detection_flat()
    env = make_envelope(flat, "detection", origin_path="/proj/detections/aws_root_login.yaml")
    template = DiscoveredTemplate(
        resource_type="detection",
        name="aws_root_login",
        file_path=Path("/proj/detections/aws_root_login.yaml"),
        tags=[],
        envelope=env,
        display_name="AWS Root Login",
    )

    provider = DetectionProvider(MagicMock())
    remote_raw = _detection_remote_raw(flat, drift=drift)
    # Drift fetches normalized via _fetch_all_remote_rules, raw via get_raw_remote_rules.
    provider._fetch_all_remote_rules = MagicMock(return_value={remote_raw["name"]: remote_raw})
    provider.get_raw_remote_rules = MagicMock(return_value={remote_raw["name"]: remote_raw})

    detector = _build_detector(
        provider=provider,
        resource_type="detection",
        templates=[template],
        state_entries={"detection.aws_root_login": _make_state_entry("detection", "aws_root_login", "rid-detection-1")},
    )

    report = detector.detect(resource_types=["detection"])

    # Sanity: the real provider hash over template_data is what drift compares.
    template_hash = provider.compute_content_hash(template.template_data)
    remote_hash = provider.compute_content_hash(remote_raw)
    assert (template_hash == remote_hash) is (not drift)

    if drift:
        assert report.has_drift
        assert len(report.config_drift) == 1
        assert report.config_drift[0].resource_id == "aws_root_login"
        assert "description" in report.config_drift[0].field_diffs
        assert report.in_sync_count == 0
    else:
        assert not report.has_drift
        assert report.in_sync_count == 1
        assert report.config_drift == []


# --------------------------------------------------------------------------- #
# Saved search (v2-sourced template via load_envelopes on a talon/v2 doc)      #
# --------------------------------------------------------------------------- #
_V2_SAVED_SEARCH = """\
apiVersion: talon/v2
kind: SavedSearch
metadata:
  resource_id: failed_logins
  name: Failed Logins
spec:
  queryString: "#repo=base | groupBy(user)"
  description: All failed logins
"""


def _saved_search_remote(*, drift=False):
    return {
        "name": "Failed Logins",
        "queryString": "#repo=base | groupBy(user)",
        "description": "MANUALLY EDITED" if drift else "All failed logins",
        "rule_id": "rid-search-1",
    }


@pytest.mark.parametrize("drift", [False, True])
def test_saved_search_drift_v2_sourced(tmp_path, drift):
    yaml_path = tmp_path / "failed_logins.yaml"
    yaml_path.write_text(_V2_SAVED_SEARCH)
    env = load_envelopes(yaml_path)[0]
    assert env.api_version == "talon/v2"  # genuinely the v2 path
    env.origin_path = str(yaml_path)

    template = DiscoveredTemplate(
        resource_type="saved_search",
        name="failed_logins",
        file_path=yaml_path,
        tags=[],
        envelope=env,
        display_name="Failed Logins",
    )

    provider = SavedSearchProvider(MagicMock())
    remote = _saved_search_remote(drift=drift)
    # Saved search has no get_raw_remote_rules; drift uses the normalized fetch result
    # directly for hashing, so compute_content_hash runs on this dict for real.
    provider._fetch_all_remote_searches = MagicMock(return_value={remote["name"]: remote})

    detector = _build_detector(
        provider=provider,
        resource_type="saved_search",
        templates=[template],
        state_entries={
            "saved_search.failed_logins": _make_state_entry("saved_search", "failed_logins", "rid-search-1")
        },
    )

    report = detector.detect(resource_types=["saved_search"])

    if drift:
        assert report.has_drift
        assert len(report.config_drift) == 1
        assert report.config_drift[0].resource_id == "failed_logins"
        assert report.in_sync_count == 0
    else:
        assert not report.has_drift
        assert report.in_sync_count == 1
        assert report.config_drift == []


# --------------------------------------------------------------------------- #
# Duplicate rule names (Defects 2 and 4)                                       #
# --------------------------------------------------------------------------- #
def test_drift_matches_tracked_rule_when_another_rule_shares_its_name():
    """Drift must compare against the rule the state tracks, not a same-named stray.

    CrowdStrike allows duplicate rule names, and the remote cache is keyed by name,
    so the stray overwrote the tracked rule. Drift then diffed the template against
    the wrong object and reported permanent, unfixable drift.
    """
    flat = _detection_flat()
    env = make_envelope(flat, "detection", origin_path="/proj/detections/aws_root_login.yaml")
    template = DiscoveredTemplate(
        resource_type="detection",
        name="aws_root_login",
        file_path=Path("/proj/detections/aws_root_login.yaml"),
        tags=[],
        envelope=env,
        display_name="AWS Root Login",
    )

    tracked = _detection_remote_raw(flat)
    tracked["rule_id"] = "rid-tracked"
    stray = _detection_remote_raw(flat, drift=True)
    stray["rule_id"] = "rid-stray"

    provider = DetectionProvider(MagicMock())
    # The real fetch runs, so the name index keeps only the stray (last one wins)
    # while the rule_id index keeps both.
    provider.falcon.command = MagicMock(
        return_value={
            "status_code": 200,
            "body": {"resources": [tracked, stray], "meta": {"pagination": {"total": 2}}},
        }
    )

    detector = _build_detector(
        provider=provider,
        resource_type="detection",
        templates=[template],
        state_entries={"detection.aws_root_login": _make_state_entry("detection", "aws_root_login", "rid-tracked")},
    )

    report = detector.detect(resource_types=["detection"])

    assert report.config_drift == [], "compared the template against a same-named stray rule"
    assert report.in_sync_count == 1


def test_drift_does_not_hide_rules_that_share_a_name():
    """Every remote rule must be considered, not just the last of each name.

    The name-keyed cache made collapsed duplicates invisible: they could never be
    matched to a template, and never surfaced as orphans either.
    """
    flat = _detection_flat()
    env = make_envelope(flat, "detection", origin_path="/proj/detections/aws_root_login.yaml")
    template = DiscoveredTemplate(
        resource_type="detection",
        name="aws_root_login",
        file_path=Path("/proj/detections/aws_root_login.yaml"),
        tags=[],
        envelope=env,
        display_name="AWS Root Login",
    )

    tracked = _detection_remote_raw(flat)
    tracked["rule_id"] = "rid-tracked"
    stray = _detection_remote_raw(flat, drift=True)
    stray["rule_id"] = "rid-stray"

    provider = DetectionProvider(MagicMock())
    provider.falcon.command = MagicMock(
        return_value={
            "status_code": 200,
            "body": {"resources": [tracked, stray], "meta": {"pagination": {"total": 2}}},
        }
    )

    detector = _build_detector(
        provider=provider,
        resource_type="detection",
        templates=[template],
        state_entries={"detection.aws_root_login": _make_state_entry("detection", "aws_root_login", "rid-tracked")},
    )

    report = detector.detect(resource_types=["detection"])

    orphaned_ids = {item.resource_id for item in report.orphaned}
    assert orphaned_ids == {"rid-stray"}, f"untracked duplicate not reported as an orphan: {orphaned_ids}"


def test_stale_state_entries_are_still_reported_for_detections():
    """Step 6 (stale state) must run for providers that expose a rule_id index.

    A state entry whose rule exists in neither the templates nor the tenant is
    stale and must be surfaced, whichever remote index drift matched against.
    """
    flat = _detection_flat()
    env = make_envelope(flat, "detection", origin_path="/proj/detections/aws_root_login.yaml")
    template = DiscoveredTemplate(
        resource_type="detection",
        name="aws_root_login",
        file_path=Path("/proj/detections/aws_root_login.yaml"),
        tags=[],
        envelope=env,
        display_name="AWS Root Login",
    )

    tracked = _detection_remote_raw(flat)
    tracked["rule_id"] = "rid-detection-1"

    provider = DetectionProvider(MagicMock())
    provider.falcon.command = MagicMock(
        return_value={
            "status_code": 200,
            "body": {"resources": [tracked], "meta": {"pagination": {"total": 1}}},
        }
    )

    detector = _build_detector(
        provider=provider,
        resource_type="detection",
        templates=[template],
        state_entries={
            "detection.aws_root_login": _make_state_entry("detection", "aws_root_login", "rid-detection-1"),
            # Deployed once, since deleted from the tenant and from the templates.
            "detection.retired_rule": _make_state_entry("detection", "retired_rule", "rid-gone"),
        },
    )

    report = detector.detect(resource_types=["detection"])

    assert [item.resource_id for item in report.stale_state] == ["retired_rule"]
