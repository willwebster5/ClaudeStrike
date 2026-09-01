"""Regression tests for the "apply reports success without applying" defect cluster.

Background: a PR that changed only `metadata.name` on a deployed detection was
planned, deployed, and reported as `✓ Deployed` — while the platform object was
never modified. These tests pin the root causes:

* Defect 3 — `name` was omitted from every PATCH payload, so renames never
  propagated even though `compute_content_hash` counted `name` as content.
* Defect 1 — `apply` never re-read the resource, so a no-op PATCH was recorded
  as a success and the intended (not actual) content hash was written to state.
* Defect 2/4 — the remote cache was keyed by rule name, so duplicate-named rules
  collapsed and ID-based lookups silently resolved to the wrong object.
* Defect 5 — `ResourceState(**data)` crashed on legacy state keys.
* Defect 6 — the shared console forced terminal mode even when redirected.
"""

import pytest
from unittest.mock import Mock

from talonctl.providers.detection_provider import DetectionProvider
from tests.unit._helpers import make_envelope


@pytest.fixture
def provider():
    return DetectionProvider(Mock())


class TestPatchPayloadIncludesName:
    """Defect 3: `name` must survive into the PATCH payload."""

    def test_patch_payload_includes_name(self, provider):
        """PATCH payload must carry the template's name so renames propagate."""
        template = {
            "name": "Microsoft - Entra ID - Multiple Failed Login Attempts",
            "description": "Detects failed sign-ins",
            "severity": 50,
            "status": "active",
            "search": {"filter": "#type=entra", "lookback": "20m"},
        }

        payload = provider._prepare_patch_payload(template)

        assert payload["name"] == "Microsoft - Entra ID - Multiple Failed Login Attempts"

    def test_patch_payload_name_matches_create_payload(self, provider):
        """A rename must be expressed identically on the create and update paths."""
        template = {
            "name": "Renamed Rule",
            "description": "d",
            "severity": 50,
            "status": "active",
            "search": {"filter": "#type=x", "lookback": "5m"},
        }

        create = provider._prepare_rule_payload(template)
        patch = provider._prepare_patch_payload(template)

        assert patch["name"] == create["name"]

    def test_every_hashed_content_field_is_patchable(self, provider):
        """Any field that counts toward the content hash must be sent on update.

        A field that changes the hash (so `plan` reports an update) but is absent
        from the PATCH payload produces exactly the silent no-op this suite exists
        to prevent.
        """
        template = {
            "name": "Rule",
            "description": "d",
            "severity": 50,
            "status": "active",
            "search": {"filter": "#type=x", "lookback": "5m"},
        }

        payload = provider._prepare_patch_payload(template)

        missing = [f for f in provider.CONTENT_FIELDS if f in template and f not in payload]
        assert missing == [], f"hashed content fields dropped from PATCH payload: {missing}"


class TestLegacyStateKeysAreTolerated:
    """Defect 5: a legacy key in a state entry crashed drift for the whole type.

    `ResourceState(**data)` raised `TypeError: unexpected keyword argument
    'last_deployed'`, which drift caught per-type and reported as
    `✗ lookup_file: ...` — so lookup_file drift was never evaluated at all.
    """

    @pytest.fixture
    def state_file(self, tmp_path):
        return tmp_path / "deployed_state.json"

    def _write_legacy_entry(self, state_file, extra):
        import json

        from talonctl.core.state_manager import StateManager

        manager = StateManager(state_file)
        manager.save()
        raw = json.loads(state_file.read_text())
        entry = {
            "type": "lookup_file",
            "id": "lf-1",
            "content_hash": "abc",
            "template_path": "resources/lookups/x.yaml",
            "deployed_at": "2026-01-01T00:00:00+00:00",
            "last_modified": "2026-01-01T00:00:00+00:00",
            "provider_metadata": {},
            "dependencies": [],
        }
        entry.update(extra)
        raw["resources"]["lookup_file"] = {"x": entry}
        state_file.write_text(json.dumps(raw))
        return StateManager(state_file)

    def test_get_resource_tolerates_legacy_key(self, state_file):
        """A state entry carrying a retired field must still load."""
        manager = self._write_legacy_entry(state_file, {"last_deployed": "2026-01-01T00:00:00+00:00"})

        resource = manager.get_resource("lookup_file", "x")

        assert resource is not None
        assert resource.id == "lf-1"

    def test_get_all_resources_tolerates_legacy_key(self, state_file):
        """get_all_resources is what drift calls — it must not raise."""
        manager = self._write_legacy_entry(state_file, {"last_deployed": "2026-01-01T00:00:00+00:00"})

        resources = manager.get_all_resources("lookup_file")

        assert list(resources) == ["lookup_file.x"]


def _raw_rule(name, rule_id="r1", status="active", description="d"):
    """A raw CrowdStrike API rule object, as combined_rules_get_v2 returns it."""
    return {
        "id": "01a0203670cf7ef4b92ec5585f8bb609",
        "rule_id": rule_id,
        "name": name,
        "description": description,
        "severity": 50,
        "status": status,
        "search": {"filter": "#type=x", "lookback": "5m"},
    }


def _template(name, description="d"):
    return {
        "name": name,
        "description": description,
        "severity": 50,
        "status": "active",
        "search": {"filter": "#type=x", "lookback": "5m"},
    }


class TestApplyVerifiesItsOwnWrites:
    """Defect 1: `apply` reported `✓ Deployed` for a PATCH that changed nothing.

    The orchestrator never re-read the resource, and provider_adapter wrote the
    hash of the *intended* template into state — so the lie became ground truth.
    """

    @pytest.fixture
    def provider(self, monkeypatch):
        from talonctl.providers import detection_provider as dp

        monkeypatch.setattr(dp, "VERIFY_BACKOFF", [0, 0], raising=False)
        return DetectionProvider(Mock())

    def _wire(self, provider, remote_before, remote_after):
        """Seed the pre-update cache and script the PATCH + verification read."""
        provider._remote_rules_cache = {remote_before["name"]: provider._normalize_rule(remote_before)}
        provider._remote_rules_raw_cache = {remote_before["name"]: remote_before}

        def command(op, **kwargs):
            if op == "entities_rules_patch_v1":
                return {"status_code": 200, "body": {"resources": [remote_after]}}
            if op == "entities_rules_get_v1":
                return {"status_code": 200, "body": {"resources": [remote_after]}}
            raise AssertionError(f"unexpected API call: {op}")

        provider.falcon.command = Mock(side_effect=command)

    def test_raises_when_platform_still_holds_the_old_name(self, provider):
        """A PATCH that leaves the platform unchanged must fail, not report success."""
        old = _raw_rule("Testing - Microsoft - Entra ID - Multiple Failed Login")
        env = make_envelope(
            {**_template("Microsoft - Entra ID - Multiple Failed Login"), "resource_id": "entra_failed_login"},
            "detection",
        )

        # The platform returns the OLD object on re-read: the write did not land.
        self._wire(provider, old, old)

        with pytest.raises(RuntimeError) as exc:
            provider.apply_update("r1", env, {})

        assert "name" in str(exc.value)

    def test_succeeds_when_platform_reflects_the_template(self, provider):
        """When the write does land, apply_update returns normally."""
        old = _raw_rule("Testing - Microsoft - Entra ID - Multiple Failed Login")
        new = _raw_rule("Microsoft - Entra ID - Multiple Failed Login")
        env = make_envelope(
            {**_template("Microsoft - Entra ID - Multiple Failed Login"), "resource_id": "entra_failed_login"},
            "detection",
        )

        self._wire(provider, old, new)

        result = provider.apply_update("r1", env, {})

        assert result["rule_id"] == "r1"

    def test_reported_name_comes_from_the_platform_not_the_template(self, provider):
        """Defect 2: state recorded the intended name even when the API disagreed."""
        old = _raw_rule("Testing - Microsoft - Entra ID - Multiple Failed Login")
        new = _raw_rule("Microsoft - Entra ID - Multiple Failed Login")
        env = make_envelope(
            {**_template("Microsoft - Entra ID - Multiple Failed Login"), "resource_id": "entra_failed_login"},
            "detection",
        )

        self._wire(provider, old, new)

        result = provider.apply_update("r1", env, {})

        assert result["name"] == new["name"]
        assert result["verified"] is True


class TestDuplicateNamedRulesStayAddressable:
    """Defects 2 and 4: the remote cache was keyed by rule *name*.

    The tenant fetches 4926 rules that collapse into 680 unique names, so all but
    the last rule of each name vanished from the cache. ID lookups then missed,
    name lookups resolved to the wrong object, and every collapsed rule was
    counted as an orphan.
    """

    @pytest.fixture
    def provider(self):
        provider = DetectionProvider(Mock())
        first = _raw_rule("Duplicated Name", rule_id="rule-one", description="the tracked rule")
        second = _raw_rule("Duplicated Name", rule_id="rule-two", description="a stray duplicate")
        provider.falcon.command = Mock(
            return_value={
                "status_code": 200,
                "body": {"resources": [first, second], "meta": {"pagination": {"total": 2}}},
            }
        )
        return provider

    def test_every_rule_is_addressable_by_id(self, provider):
        """Rules sharing a name must all survive the fetch, indexed by rule_id."""
        provider._fetch_all_remote_rules()

        by_id = provider.get_remote_rules_by_id()

        assert set(by_id) == {"rule-one", "rule-two"}

    def test_collapsed_rule_is_found_without_a_second_api_call(self, provider):
        """fetch_remote_state must resolve a rule the name-index dropped."""
        provider._fetch_all_remote_rules()
        provider.falcon.command.reset_mock()

        found = provider.fetch_remote_state("rule-one")

        assert found is not None
        assert found["rule_id"] == "rule-one"
        assert provider.falcon.command.call_count == 0, "fell back to a per-rule API fetch"

    def test_duplicate_names_are_reported(self, provider, caplog):
        """Silent collapse hid thousands of duplicates — it must be logged."""
        import logging

        with caplog.at_level(logging.WARNING):
            provider._fetch_all_remote_rules()

        assert "Duplicated Name" in caplog.text


class TestConsoleRespectsRedirection:
    """Defect 6: redirecting a report to a file produced mangled, truncated output.

    The shared console was built with `force_terminal=True` whenever colour was not
    explicitly disabled, so Rich emitted terminal control sequences into files.
    """

    @pytest.fixture(autouse=True)
    def _clear_env(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("CI", raising=False)

    def test_redirected_output_is_not_terminal(self):
        """A non-TTY destination must not be treated as a terminal."""
        import io

        from talonctl.commands._common import make_console

        assert make_console(file=io.StringIO()).is_terminal is False

    def test_redirected_output_has_no_control_sequences(self):
        """Rich must write plain text when the destination is a file."""
        import io

        from talonctl.commands._common import make_console

        buffer = io.StringIO()
        console = make_console(file=buffer)
        console.print("[bold blue]Detecting drift...[/bold blue]")

        assert "\x1b[" not in buffer.getvalue()
        assert "Detecting drift..." in buffer.getvalue()

    def test_tty_output_still_gets_styling(self):
        """An interactive terminal must keep its colour."""
        import io

        from talonctl.commands._common import make_console

        class _Tty(io.StringIO):
            def isatty(self):
                return True

        assert make_console(file=_Tty()).is_terminal is True


class TestStateRecordsThePermanentRuleId:
    """Defect 2: state held an ID that addressed nothing on the platform.

    CrowdStrike correlation rules carry three identifiers: `id` (a per-version
    ULID), `rule_id` (the permanent ULID the console uses) and `executor_rule_id`.
    The state synchronizer preferred `id` — the one that changes on every update —
    over `rule_id`, which the rest of the codebase documents as the only
    identifier safe to persist.
    """

    def test_rule_id_wins_over_version_id(self):
        """A provider result carrying both must be recorded under rule_id."""
        from talonctl.core.state_synchronizer import StateSynchronizer

        provider_result = {
            "id": "01a0203670cf7ef4b92ec5585f8bb609",  # version ULID — changes per update
            "rule_id": "019c4d499c97767c9564d83fdaaf1ad5",  # permanent
        }

        assert StateSynchronizer.select_persisted_id(provider_result) == "019c4d499c97767c9564d83fdaaf1ad5"

    def test_falls_back_to_id_for_providers_without_rule_id(self):
        """Non-detection providers only return `id`; that remains correct."""
        from talonctl.core.state_synchronizer import StateSynchronizer

        assert StateSynchronizer.select_persisted_id({"id": "saved-search-42"}) == "saved-search-42"

    def test_returns_none_when_no_identifier_present(self):
        """An identifier-free result must not silently become a state key."""
        from talonctl.core.state_synchronizer import StateSynchronizer

        assert StateSynchronizer.select_persisted_id({"name": "no ids here"}) is None
