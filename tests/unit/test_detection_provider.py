"""
Unit tests for DetectionProvider
"""

import pytest
from unittest.mock import Mock

from talonctl.providers.detection_provider import DetectionProvider
from talonctl.core import ResourceAction
from tests.unit._helpers import make_envelope


def _env(flat, origin_path=None):
    """Wrap a legacy flat detection dict as an Envelope for the provider's
    Envelope-consuming methods. Defaults a resource_id (which v1_to_v2 requires)
    from the name when the test dict omits it — these tests assert on validation
    errors / planned changes, not on resource_id, so the default is inert.
    """
    if "resource_id" not in flat:
        flat = {**flat, "resource_id": "test_resource"}
    return make_envelope(flat, "detection", origin_path=origin_path)


class TestDetectionProvider:
    """Test suite for DetectionProvider"""

    @pytest.fixture
    def mock_falcon(self):
        """Create mock Falcon client"""
        return Mock()

    @pytest.fixture
    def provider(self, mock_falcon):
        """Create DetectionProvider instance"""
        return DetectionProvider(mock_falcon)

    def test_get_resource_type(self, provider):
        """Test resource type identifier"""
        assert provider.get_resource_type() == "detection"

    def test_validate_template_valid(self, provider):
        """Test validation of valid template"""
        template = {
            "name": "Test Rule",
            "description": "A test detection rule",
            "severity": 50,
            "search": {"query": "#event_simpleName=ProcessRollup2 | select([aid, FileName])"},
        }

        errors = provider.validate_template(_env(template))
        assert errors == []

    def test_validate_template_missing_fields(self, provider):
        """Test validation catches missing required fields"""
        template = {
            "name": "Test Rule"
            # Missing: description, severity, search
        }

        errors = provider.validate_template(_env(template))
        assert len(errors) >= 3
        assert any("description" in err for err in errors)
        assert any("severity" in err for err in errors)
        assert any("search" in err for err in errors)

    def test_validate_template_invalid_severity(self, provider):
        """Test validation catches invalid severity"""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 99,  # Invalid
            "search": {"query": "test"},
        }

        errors = provider.validate_template(_env(template))
        assert any("severity" in err.lower() for err in errors)

    def test_validate_template_missing_query(self, provider):
        """Test validation catches missing query"""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {},  # No query
        }

        errors = provider.validate_template(_env(template))
        assert any("query" in err.lower() for err in errors)

    def test_validate_template_invalid_status(self, provider):
        """Test validation catches invalid status"""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "status": "paused",  # Invalid
            "search": {"query": "test"},
        }

        errors = provider.validate_template(_env(template))
        assert any("status" in err.lower() for err in errors)

    def test_fetch_remote_state(self, provider, mock_falcon):
        """Test fetching remote rule state"""
        mock_falcon.command.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "rule_id": "test123",
                        "name": "Test Rule",
                        "description": "Test",
                        "severity": 50,
                        "status": "active",
                        "query": "test query",
                    }
                ]
            },
        }

        result = provider.fetch_remote_state("test123")

        assert result is not None
        assert result["rule_id"] == "test123"
        assert result["name"] == "Test Rule"
        assert "search" in result
        assert result["search"]["query"] == "test query"

    def test_fetch_remote_state_not_found(self, provider, mock_falcon):
        """Test fetching non-existent rule"""
        mock_falcon.command.return_value = {"status_code": 200, "body": {"resources": []}}

        result = provider.fetch_remote_state("nonexistent")
        assert result is None

    def test_plan_create(self, provider):
        """Test planning rule creation"""
        template = {"name": "New Rule", "description": "Test", "severity": 50, "search": {"query": "test"}}

        env = _env(template)
        change = provider.plan_create(env, "rules/test.yaml")

        assert change.action == ResourceAction.CREATE
        assert change.resource_type == "detection"
        assert change.resource_name == "New Rule"
        assert change.resource_id is None
        assert change.new_value == env.to_working_dict()
        assert change.template_path == "rules/test.yaml"
        assert change.envelope is env

    def test_plan_update_with_changes(self, provider):
        """Test planning rule update when changes exist"""
        template = {
            "name": "Test Rule",
            "description": "Updated description",
            "severity": 70,
            "search": {"query": "new query"},
        }

        current_state = {
            "rule_id": "rule123",
            "name": "Test Rule",
            "description": "Old description",
            "severity": 50,
            "search": {"query": "old query"},
        }

        change = provider.plan_update(_env(template), current_state, "rules/test.yaml")

        assert change.action == ResourceAction.UPDATE
        assert change.resource_type == "detection"
        assert change.resource_name == "Test Rule"
        assert change.resource_id == "rule123"
        assert "description" in change.changes
        assert "severity" in change.changes
        assert "search" in change.changes

    def test_plan_update_no_changes(self, provider):
        """Test planning rule update when no changes exist"""
        template = {"name": "Test Rule", "description": "Test", "severity": 50, "search": {"query": "test query"}}

        current_state = template.copy()
        current_state["rule_id"] = "rule123"

        change = provider.plan_update(_env(template), current_state, "rules/test.yaml")

        assert change.action == ResourceAction.NO_CHANGE
        assert change.resource_id == "rule123"

    def test_plan_delete(self, provider, mock_falcon):
        """Test planning rule deletion"""
        mock_falcon.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"rule_id": "rule123", "name": "Test Rule", "description": "Test", "severity": 50}]},
        }

        change = provider.plan_delete("rule123", "Test Rule")

        assert change.action == ResourceAction.DELETE
        assert change.resource_type == "detection"
        assert change.resource_name == "Test Rule"
        assert change.resource_id == "rule123"

    def test_apply_create(self, provider, mock_falcon):
        """Test creating a rule"""
        template = {"name": "New Rule", "description": "Test", "severity": 50, "search": {"query": "test query"}}

        # apply_create reads the rule back to prove the write landed, so the stub
        # must answer both the POST and the verification GET.
        created = {
            "rule_id": "new123",
            "name": "New Rule",
            "description": "Test",
            "severity": 50,
            "status": "active",
            "search": {},
        }

        def command(op, **kwargs):
            # POST answers 201; the verification GET answers 200, as the API does.
            status = 201 if op == "entities_rules_post_v1" else 200
            return {"status_code": status, "body": {"resources": [created]}}

        mock_falcon.command.side_effect = command

        result = provider.apply_create(_env(template))

        assert result["rule_id"] == "new123"
        assert result["name"] == "New Rule"
        assert "created_at" in result
        called_cmds = [c.args[0] for c in mock_falcon.command.call_args_list if c.args]
        assert called_cmds == ["entities_rules_post_v1", "entities_rules_get_v1"]

    def test_apply_update(self, provider, mock_falcon):
        """Test updating a rule"""
        template = {
            "name": "Updated Rule",
            "description": "New description",
            "severity": 70,
            "search": {"query": "new query"},
        }

        # The stub answers the pre-fetch, the PATCH, and the verification read-back
        # with the post-update rule.
        updated = {
            "rule_id": "rule123",
            "name": "Updated Rule",
            "description": "New description",
            "severity": 70,
            "status": "active",
            "search": {},
        }
        mock_falcon.command.return_value = {"status_code": 200, "body": {"resources": [updated]}}

        result = provider.apply_update("rule123", _env(template), {})

        assert result["rule_id"] == "rule123"
        assert result["name"] == "Updated Rule"
        assert "updated_at" in result
        # fetch_remote_state, then patch, then the read-back that proves it landed.
        called_cmds = [c.args[0] for c in mock_falcon.command.call_args_list if c.args]
        assert called_cmds[-2:] == ["entities_rules_patch_v1", "entities_rules_get_v1"]

    def test_apply_delete(self, provider, mock_falcon):
        """Test deleting a rule"""
        mock_falcon.command.return_value = {"status_code": 200, "body": {}}

        result = provider.apply_delete("rule123")

        assert result["rule_id"] == "rule123"
        assert "deleted_at" in result
        mock_falcon.command.assert_called_once_with("entities_rules_delete_v1", ids=["rule123"])

    def test_compute_content_hash_identical(self, provider):
        """Test hash computation produces identical results for same content"""
        template1 = {"name": "Test", "description": "Test rule", "severity": 50, "search": {"query": "test"}}

        template2 = template1.copy()

        hash1 = provider.compute_content_hash(template1)
        hash2 = provider.compute_content_hash(template2)

        assert hash1 == hash2

    def test_compute_content_hash_different(self, provider):
        """Test hash computation produces different results for different content"""
        template1 = {"name": "Test", "description": "Test rule", "severity": 50, "search": {"query": "test"}}

        template2 = {
            "name": "Test",
            "description": "Different description",
            "severity": 50,
            "search": {"query": "test"},
        }

        hash1 = provider.compute_content_hash(template1)
        hash2 = provider.compute_content_hash(template2)

        assert hash1 != hash2

    def test_extract_dependencies_query_id(self, provider):
        """Test extracting saved search dependency from query_id"""
        template = {"name": "Test", "search": {"query_id": "aws_accounts_search"}}

        deps = provider.extract_dependencies(template)

        assert "saved_search.aws_accounts_search" in deps

    def test_extract_dependencies_readfile(self, provider):
        """Test extracting lookup file dependency from readFile()"""
        template = {"name": "Test", "search": {"query": 'readFile(fileName="aws_service_accounts") | ...'}}

        deps = provider.extract_dependencies(template)

        assert "lookup_file.aws_service_accounts" in deps

    def test_extract_dependencies_in_function(self, provider):
        """Test extracting lookup file dependency from in() function"""
        template = {"name": "Test", "search": {"query": '| srcIpAddr in(name="trusted_ips")'}}

        deps = provider.extract_dependencies(template)

        assert "lookup_file.trusted_ips" in deps

    def test_extract_dependencies_multiple(self, provider):
        """Test extracting multiple dependencies"""
        template = {
            "name": "Test",
            "search": {
                "query": 'readFile(fileName="aws_accounts") | srcIpAddr in(name="trusted_ips")',
                "query_id": "base_search",
            },
        }

        deps = provider.extract_dependencies(template)

        assert len(deps) == 3
        assert "saved_search.base_search" in deps
        assert "lookup_file.aws_accounts" in deps
        assert "lookup_file.trusted_ips" in deps

    def test_prepare_rule_payload(self, provider):
        """Test preparing API payload from template"""
        template = {
            "name": "Test Rule",
            "description": "Test description",
            "severity": 50,
            "status": "active",
            "search": {
                "query": "test query",
                "use_ingest_time": True,
                "search_window": 24,
                "search_window_unit": "hour",
            },
            "mitre_attack": [{"tactic": "TA0001", "technique": "T1078"}],
        }

        payload = provider._prepare_rule_payload(template)

        assert payload["name"] == "Test Rule"
        assert payload["description"] == "Test description"
        assert payload["severity"] == 50
        assert payload["status"] == "active"
        assert payload["search"]["query"] == "test query"
        assert payload["search"]["use_ingest_time"] is True
        assert payload["search"]["search_window"] == 24
        assert payload["search"]["search_window_unit"] == "hour"
        assert "mitre_attack" in payload

    def test_prepare_rule_payload_includes_template_id_when_present(self, provider):
        """template_id in YAML should be passed to create payload for lineage tracking."""
        template = {
            "name": "AWS Root Login",
            "description": "Detects root login",
            "severity": 70,
            "status": "active",
            "template_id": "tmpl-abc123",
            "search": {"filter": "#repo=cloudtrail", "lookback": "-70m"},
        }
        payload = provider._prepare_rule_payload(template)
        assert payload.get("template_id") == "tmpl-abc123"

    def test_prepare_rule_payload_omits_template_id_when_absent(self, provider):
        """Rules without template_id (custom rules) should not include the field."""
        template = {
            "name": "Custom Rule",
            "description": "A custom rule",
            "severity": 50,
            "status": "active",
            "search": {"filter": "#repo=cloudtrail"},
        }
        payload = provider._prepare_rule_payload(template)
        assert "template_id" not in payload

    # --- ADS metadata validation ---

    def test_validate_template_ads_absent_passes(self, provider):
        """ads: block is optional — absence should not cause errors"""
        template = {"name": "Test Rule", "description": "Test", "severity": 50, "search": {"query": "test"}}
        errors = provider.validate_template(_env(template))
        assert errors == []

    def test_validate_template_ads_valid(self, provider):
        """Valid metadata.ads: block with required goal field (v0.3.0 shape)."""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "metadata": {
                "ads": {
                    "goal": "Detect unauthorized access to EC2 security groups",
                    "mitre_attack": ["Defense Evasion / Impair Defenses"],
                    "blind_spots": ["Service-linked role changes not logged"],
                    "strategy_abstract": "Correlates EC2 SG changes with known CI/CD patterns",
                }
            },
        }
        errors = provider.validate_template(_env(template))
        assert errors == []

    def test_validate_template_ads_missing_goal(self, provider):
        """metadata.ads block present without goal should fail."""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "metadata": {
                "ads": {
                    "strategy_abstract": "Some strategy",
                }
            },
        }
        errors = provider.validate_template(_env(template))
        assert any("ads.goal" in err for err in errors)

    def test_validate_template_ads_empty_goal(self, provider):
        """metadata.ads block with empty goal should fail."""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "metadata": {
                "ads": {
                    "goal": "",
                }
            },
        }
        errors = provider.validate_template(_env(template))
        assert any("ads.goal" in err for err in errors)

    def test_validate_template_ads_unknown_field(self, provider):
        """Unknown fields in metadata.ads block should be rejected."""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "metadata": {
                "ads": {
                    "goal": "Detect something",
                    "unknown_field": "value",
                }
            },
        }
        errors = provider.validate_template(_env(template))
        assert any("unknown_field" in err for err in errors)

    def test_validate_template_ads_list_field_not_list(self, provider):
        """List fields in metadata.ads must be lists."""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "metadata": {
                "ads": {
                    "goal": "Detect something",
                    "blind_spots": "not a list",
                }
            },
        }
        errors = provider.validate_template(_env(template))
        assert any("ads.blind_spots" in err and "list" in err for err in errors)

    def test_validate_template_ads_string_field_not_string(self, provider):
        """String fields in metadata.ads must be strings."""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "metadata": {
                "ads": {
                    "goal": ["not", "a", "string"],
                }
            },
        }
        errors = provider.validate_template(_env(template))
        assert any("ads.goal" in err and "string" in err for err in errors)

    def test_validate_template_ads_not_dict(self, provider):
        """metadata.ads must be a dictionary if present."""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "metadata": {"ads": "not a dict"},
        }
        errors = provider.validate_template(_env(template))
        assert any("'metadata.ads' must be a dictionary" in err for err in errors)

    def test_validate_template_ads_false_positives_mixed_entries(self, provider):
        """false_positives can contain both dicts and string references."""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "metadata": {
                "ads": {
                    "goal": "Detect something",
                    "false_positives": [
                        {
                            "pattern": "CI/CD Terraform deployments",
                            "characteristics": "github-actions-role ARN",
                            "tuning": "Filtered via $aws_service_account_detector()",
                            "status": "tuned",
                        },
                        "-> knowledge/patterns/aws.md#autoscaling-service-role",
                    ],
                }
            },
        }
        errors = provider.validate_template(_env(template))
        assert errors == []

    def test_validate_template_ads_all_optional_fields(self, provider):
        """All optional ADS fields should be accepted."""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "metadata": {
                "ads": {
                    "goal": "Detect unauthorized access",
                    "mitre_attack": ["TA0005:T1562"],
                    "strategy_abstract": "Correlates SG changes",
                    "technical_context": "CloudTrail, EC2 SG API calls",
                    "blind_spots": ["Service-linked roles"],
                    "false_positives": ["CI/CD automation"],
                    "validation": ["Modify SG from unapproved role"],
                    "priority_rationale": "High-value asset modification",
                    "response": "See playbook cloud-security-aws.md",
                    "ads_created": "2026-04-14",
                    "ads_updated": "2026-04-14",
                    "ads_author": "Will Webster",
                }
            },
        }
        errors = provider.validate_template(_env(template))
        assert errors == []

    # --- metadata: block validation ---

    @pytest.fixture
    def minimal_detection(self):
        """Minimal valid detection template (v0.3.0 new-shape) — used for metadata/ADS test permutations."""
        return {
            "resource_id": "x",
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
        }

    def test_validate_metadata_absent_passes(self, provider, minimal_detection):
        """metadata: block is optional — absence should not cause errors."""
        errors = provider.validate_template(_env(minimal_detection))
        assert errors == []

    def test_validate_metadata_empty_maturity_passes(self, provider, minimal_detection):
        """Empty metadata.maturity: {} is valid (all fields optional when block present)."""
        minimal_detection["metadata"] = {"maturity": {}}
        errors = provider.validate_template(_env(minimal_detection))
        assert errors == []

    def test_validate_metadata_full_valid_block(self, provider, minimal_detection):
        """All four maturity fields populated with valid values passes."""
        minimal_detection["metadata"] = {
            "maturity": {
                "created": "2026-01-15",
                "last_tuned": "2026-04-10",
                "tune_count": 3,
                "confidence": "high",
            }
        }
        errors = provider.validate_template(_env(minimal_detection))
        assert errors == []

    def test_validate_metadata_not_dict(self, provider, minimal_detection):
        """metadata: must be a dictionary when present."""
        minimal_detection["metadata"] = "not a dict"
        errors = provider.validate_template(_env(minimal_detection))
        assert any("'metadata' must be a dictionary" in err for err in errors)

    def test_validate_metadata_unknown_maturity_key(self, provider, minimal_detection):
        """Unknown keys in metadata.maturity: are rejected with typo-friendly error."""
        minimal_detection["metadata"] = {"maturity": {"created": "2026-01-15", "confidance": "high"}}
        errors = provider.validate_template(_env(minimal_detection))
        assert any("confidance" in err for err in errors)
        # Error should list known keys for user guidance
        assert any("confidence" in err and "created" in err for err in errors)

    def test_validate_metadata_last_tuned_null(self, provider, minimal_detection):
        """last_tuned: null is valid (means never tuned)."""
        minimal_detection["metadata"] = {"maturity": {"last_tuned": None, "tune_count": 0}}
        errors = provider.validate_template(_env(minimal_detection))
        assert errors == []

    def test_validate_metadata_bad_date_format(self, provider, minimal_detection):
        """created/last_tuned must match YYYY-MM-DD."""
        minimal_detection["metadata"] = {"maturity": {"created": "2026-4-14"}}  # missing zero pad
        errors = provider.validate_template(_env(minimal_detection))
        assert any("metadata.maturity.created" in err and "YYYY-MM-DD" in err for err in errors)

    def test_validate_metadata_non_date_string(self, provider, minimal_detection):
        """Non-date strings rejected for date fields."""
        minimal_detection["metadata"] = {"maturity": {"last_tuned": "yesterday"}}
        errors = provider.validate_template(_env(minimal_detection))
        assert any("metadata.maturity.last_tuned" in err for err in errors)

    def test_validate_metadata_tune_count_negative(self, provider, minimal_detection):
        """tune_count must be >= 0."""
        minimal_detection["metadata"] = {"maturity": {"tune_count": -1}}
        errors = provider.validate_template(_env(minimal_detection))
        assert any("metadata.maturity.tune_count" in err and "non-negative" in err for err in errors)

    def test_validate_metadata_tune_count_string(self, provider, minimal_detection):
        """tune_count must be an int, not a string."""
        minimal_detection["metadata"] = {"maturity": {"tune_count": "3"}}
        errors = provider.validate_template(_env(minimal_detection))
        assert any("metadata.maturity.tune_count" in err for err in errors)

    def test_validate_metadata_tune_count_bool_rejected(self, provider, minimal_detection):
        """Python bool is technically int — must be explicitly rejected."""
        minimal_detection["metadata"] = {"maturity": {"tune_count": True}}
        errors = provider.validate_template(_env(minimal_detection))
        assert any("metadata.maturity.tune_count" in err for err in errors)

    def test_validate_metadata_tune_count_float(self, provider, minimal_detection):
        """tune_count must be int, not float."""
        minimal_detection["metadata"] = {"maturity": {"tune_count": 1.5}}
        errors = provider.validate_template(_env(minimal_detection))
        assert any("metadata.maturity.tune_count" in err for err in errors)

    def test_validate_metadata_tune_count_zero(self, provider, minimal_detection):
        """tune_count: 0 is valid (boundary)."""
        minimal_detection["metadata"] = {"maturity": {"tune_count": 0}}
        errors = provider.validate_template(_env(minimal_detection))
        assert errors == []

    def test_validate_metadata_confidence_valid_values(self, provider, minimal_detection):
        """Each of the four confidence values must pass."""
        for value in ("low", "medium", "high", "validated"):
            minimal_detection["metadata"] = {"maturity": {"confidence": value}}
            errors = provider.validate_template(_env(minimal_detection))
            assert errors == [], f"confidence={value} should pass, got {errors}"

    def test_validate_metadata_confidence_invalid(self, provider, minimal_detection):
        """Confidence value not in enum rejected, error names all allowed values."""
        minimal_detection["metadata"] = {"maturity": {"confidence": "mature"}}
        errors = provider.validate_template(_env(minimal_detection))
        assert any("metadata.maturity.confidence" in err and "low" in err and "validated" in err for err in errors)

    def test_validate_metadata_errors_accumulate(self, provider, minimal_detection):
        """Multiple metadata errors produce multiple distinct errors (no short-circuit)."""
        minimal_detection["metadata"] = {
            "maturity": {
                "created": "bad-date",
                "tune_count": -1,
                "confidence": "not-in-enum",
            }
        }
        errors = provider.validate_template(_env(minimal_detection))
        metadata_errors = [e for e in errors if "metadata." in e]
        assert len(metadata_errors) >= 3, f"expected 3+ metadata errors, got {metadata_errors}"

    # --- ads: path-ref extension (false_positives / response / validation).
    # v0.3.0: ads: relocated under metadata.ads (was top-level ads:). ---

    @staticmethod
    def _set_ads(template, ads):
        """Helper: set ADS block at the v0.3.0 path (metadata.ads)."""
        template.setdefault("metadata", {})["ads"] = ads
        return template

    def test_validate_ads_fp_ref_dict_valid(self, provider, minimal_detection):
        """false_positives entry can be {path, label}."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "false_positives": [
                    {"path": "knowledge/patterns/aws.md#ci-cd", "label": "CI/CD Terraform"},
                ],
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert errors == []

    def test_validate_ads_fp_ref_dict_label_optional(self, provider, minimal_detection):
        """label is optional in ref dict."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "false_positives": [{"path": "knowledge/patterns/aws.md#ci-cd"}],
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert errors == []

    def test_validate_ads_fp_mixed_forms(self, provider, minimal_detection):
        """false_positives can mix string refs, inline FP dicts, and ref dicts."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "false_positives": [
                    "-> knowledge/patterns/aws.md#legacy",
                    {"pattern": "P", "characteristics": "C", "tuning": "T", "status": "tuned"},
                    {"path": "knowledge/patterns/aws.md#new", "label": "New pattern"},
                ],
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert errors == []

    def test_validate_ads_validation_ref_dict(self, provider, minimal_detection):
        """validation entry can be a ref dict."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "validation": [{"path": "knowledge/validations/foo.md"}],
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert errors == []

    def test_validate_ads_validation_mixed_forms(self, provider, minimal_detection):
        """validation can mix strings and ref dicts."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "validation": ["Step 1: do thing", {"path": "knowledge/validations/foo.md"}],
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert errors == []

    def test_validate_ads_response_ref_dict(self, provider, minimal_detection):
        """response can be a ref dict instead of a string."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "response": {"path": "playbooks/aws.md#sg-anomaly", "label": "SG anomaly playbook"},
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert errors == []

    def test_validate_ads_response_string_still_valid(self, provider, minimal_detection):
        """response: '...' string form still valid (backward compat)."""
        self._set_ads(minimal_detection, {"goal": "Detect X", "response": "Investigate user"})
        errors = provider.validate_template(_env(minimal_detection))
        assert errors == []

    def test_validate_ads_ref_dict_missing_path(self, provider, minimal_detection):
        """Ref dict without 'path' key rejected."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "false_positives": [{"label": "orphan"}],
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert any("ads.false_positives" in err and "path" in err for err in errors)

    def test_validate_ads_ref_dict_unknown_key(self, provider, minimal_detection):
        """Ref dict with unknown keys rejected."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "false_positives": [{"path": "x", "labol": "typo"}],
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert any("labol" in err for err in errors)

    def test_validate_ads_ref_dict_empty_path(self, provider, minimal_detection):
        """Ref dict with empty path rejected."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "false_positives": [{"path": ""}],
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert any("path" in err and "non-empty" in err for err in errors)

    def test_validate_ads_ref_dict_whitespace_path(self, provider, minimal_detection):
        """Ref dict with whitespace-only path rejected."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "false_positives": [{"path": "   "}],
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert any("path" in err for err in errors)

    def test_validate_ads_ref_dict_path_with_space(self, provider, minimal_detection):
        """Ref dict path containing whitespace rejected."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "false_positives": [{"path": "has space"}],
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert any("path" in err and "whitespace" in err for err in errors)

    def test_validate_ads_ref_dict_path_non_string(self, provider, minimal_detection):
        """Ref dict path must be a string."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "false_positives": [{"path": 123}],
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert any("path" in err and "string" in err for err in errors)

    def test_validate_ads_ref_dict_label_non_string(self, provider, minimal_detection):
        """Ref dict label must be a string when present."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "false_positives": [{"path": "x", "label": 123}],
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert any("label" in err and "string" in err for err in errors)

    def test_validate_ads_ref_dict_label_empty(self, provider, minimal_detection):
        """Ref dict label must be non-empty when present."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "false_positives": [{"path": "x", "label": ""}],
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert any("label" in err and "non-empty" in err for err in errors)

    def test_validate_ads_validation_inline_dict_rejected(self, provider, minimal_detection):
        """validation has no inline-dict form — a non-ref dict is rejected."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "validation": [{"characteristics": "oops"}],
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert any("ads.validation" in err and ("strings" in err or "ref" in err) for err in errors)

    def test_validate_ads_response_dict_unknown_key_rejected(self, provider, minimal_detection):
        """response dict treated as ref dict — unknown keys rejected."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "response": {"path": "x", "note": "extra"},
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert any("note" in err for err in errors)

    def test_validate_ads_fp_inline_dict_strict_keys(self, provider, minimal_detection):
        """Inline FP dict keys must be in {pattern, characteristics, tuning, status}."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "false_positives": [
                    {"pattern": "P", "charactaristics": "typo", "tuning": "T", "status": "tuned"},
                ],
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert any("charactaristics" in err for err in errors)

    def test_validate_ads_fp_entry_wrong_type(self, provider, minimal_detection):
        """false_positives entries must be string or dict."""
        self._set_ads(
            minimal_detection,
            {
                "goal": "Detect X",
                "false_positives": [123],
            },
        )
        errors = provider.validate_template(_env(minimal_detection))
        assert any("ads.false_positives" in err for err in errors)

    def test_validate_ads_response_wrong_type(self, provider, minimal_detection):
        """response must be string or ref dict, not list."""
        self._set_ads(minimal_detection, {"goal": "Detect X", "response": ["bad"]})
        errors = provider.validate_template(_env(minimal_detection))
        assert any("ads.response" in err for err in errors)

    # --- Allowlist regression: metadata: and ads: never leak to API or hash ---

    @pytest.fixture
    def rich_template(self):
        """Template populated with metadata.maturity and metadata.ads (v0.3.0 shape)."""
        return {
            "resource_id": "test___test___rich",
            "name": "Rich Template",
            "description": "Template with metadata.maturity + metadata.ads populated",
            "severity": 50,
            "status": "active",
            "search": {
                "filter": '#Vendor="test"',
                "lookback": "5m",
                "trigger_mode": "summary",
                "outcome": "detection",
            },
            "mitre_attack": ["TA0005:T1562"],
            "metadata": {
                "maturity": {
                    "created": "2026-01-15",
                    "last_tuned": "2026-04-10",
                    "tune_count": 3,
                    "confidence": "high",
                },
                "ads": {
                    "goal": "Detect the thing",
                    "blind_spots": ["blind to X"],
                    "priority_rationale": "Medium — commodity technique",
                    "false_positives": [
                        {"path": "knowledge/patterns/aws.md#ci-cd", "label": "CI/CD"},
                    ],
                    "response": {"path": "playbooks/aws.md#sg-anomaly"},
                },
            },
        }

    def test_create_payload_excludes_metadata(self, provider, rich_template):
        """POST (create) payload must not contain the metadata: namespace."""
        payload = provider._prepare_rule_payload(rich_template)
        assert "metadata" not in payload, f"metadata: leaked into create payload: {payload}"
        assert "ads" not in payload, f"ads: leaked into create payload: {payload}"

    def test_patch_payload_excludes_metadata(self, provider, rich_template):
        """PATCH (update) payload must not contain the metadata: namespace."""
        payload = provider._prepare_patch_payload(rich_template)
        assert "metadata" not in payload, f"metadata: leaked into patch payload: {payload}"
        assert "ads" not in payload, f"ads: leaked into patch payload: {payload}"

    def test_hash_unchanged_when_metadata_mutates(self, provider, rich_template):
        """Editing any metadata: field (maturity or ads) must not change the content hash."""
        baseline = provider.compute_content_hash(rich_template)
        mutated = {
            **rich_template,
            "metadata": {
                "maturity": {
                    "created": "2026-01-15",
                    "last_tuned": "2026-04-16",  # changed
                    "tune_count": 4,  # changed
                    "confidence": "validated",  # changed
                },
                "ads": {
                    "goal": "Detect the thing (revised)",
                    "strategy_abstract": "New abstract",
                    "blind_spots": ["blind to X", "also blind to Y"],
                    "false_positives": [
                        {"path": "knowledge/patterns/aws.md#ci-cd", "label": "CI/CD"},
                        {"path": "knowledge/patterns/aws.md#new", "label": "New pattern"},
                    ],
                    "response": "Inline response now",
                },
            },
        }
        assert provider.compute_content_hash(mutated) == baseline, "metadata: mutation must not change content hash"

    def test_hash_changes_when_real_field_mutates(self, provider, rich_template):
        """Sanity: content hash MUST change when a real CONTENT_FIELDS member mutates."""
        baseline = provider.compute_content_hash(rich_template)
        mutated = {**rich_template, "severity": 70}
        assert provider.compute_content_hash(mutated) != baseline, (
            "severity change must produce a different hash (sanity check)"
        )

    # --- v0.3.0 metadata namespace redesign ---

    def test_v03_new_shape_metadata_ads_validates(self, provider, minimal_detection):
        minimal_detection["metadata"] = {
            "ads": {"goal": "Detect something", "mitre_attack": ["TA0011:T1090.003"]},
        }
        assert provider.validate_template(_env(minimal_detection)) == []

    def test_v03_new_shape_metadata_maturity_validates(self, provider, minimal_detection):
        minimal_detection["metadata"] = {
            "maturity": {"created": "2026-04-16", "tune_count": 2, "confidence": "high"},
        }
        assert provider.validate_template(_env(minimal_detection)) == []

    def test_v03_new_shape_both_blocks_together(self, provider, minimal_detection):
        minimal_detection["metadata"] = {
            "maturity": {"created": "2026-04-16"},
            "ads": {"goal": "Detect something"},
        }
        assert provider.validate_template(_env(minimal_detection)) == []

    def test_v03_old_top_level_ads_rejected(self, provider, minimal_detection):
        minimal_detection["ads"] = {"goal": "Detect something"}
        errors = provider.validate_template(_env(minimal_detection))
        # Exact-string guard against silent refactors — CHANGELOG pointer must remain.
        assert any(
            "Top-level 'ads:' is removed in v0.3.0" in e and "metadata.ads" in e and "CHANGELOG.md" in e for e in errors
        )

    def test_v03_old_flat_metadata_rejected(self, provider, minimal_detection):
        minimal_detection["metadata"] = {"created": "2026-04-16", "tune_count": 2}
        errors = provider.validate_template(_env(minimal_detection))
        assert any(
            "Top-level 'metadata:' now reserves sub-namespaces" in e and "metadata.maturity" in e for e in errors
        )

    def test_v03_metadata_ads_goal_required(self, provider, minimal_detection):
        minimal_detection["metadata"] = {"ads": {"mitre_attack": ["x"]}}  # missing goal
        errors = provider.validate_template(_env(minimal_detection))
        assert any("ads.goal is required" in e for e in errors)

    def test_v03_metadata_ads_unknown_field(self, provider, minimal_detection):
        minimal_detection["metadata"] = {"ads": {"goal": "g", "bogus": 1}}
        errors = provider.validate_template(_env(minimal_detection))
        assert any("Unknown ads fields: bogus" in e for e in errors)

    def test_v03_metadata_ads_ref_dict_false_positive(self, provider, minimal_detection):
        # Existing ref-dict form (from v0.2.x spec) continues to work under new path.
        minimal_detection["metadata"] = {
            "ads": {
                "goal": "g",
                "false_positives": [
                    {"path": "knowledge/patterns/net.md#anchor", "label": "ok"},
                ],
            }
        }
        assert provider.validate_template(_env(minimal_detection)) == []

    def test_v03_metadata_not_dict(self, provider, minimal_detection):
        minimal_detection["metadata"] = "oops"
        errors = provider.validate_template(_env(minimal_detection))
        assert any("'metadata' must be a dictionary" in e for e in errors)

    def test_v03_metadata_edits_do_not_change_content_hash(self, provider, minimal_detection):
        # The whole point of the metadata: namespace — plan must show NO_CHANGE.
        base_hash = provider.compute_content_hash(minimal_detection)
        with_metadata = dict(minimal_detection)
        with_metadata["metadata"] = {
            "maturity": {"created": "2026-04-16", "tune_count": 9},
            "ads": {"goal": "g"},
            "acme_corp": {"anything": True},
        }
        assert provider.compute_content_hash(with_metadata) == base_hash

    def test_v03_internal_prefix_fields_do_not_change_content_hash(self, provider, minimal_detection):
        base_hash = provider.compute_content_hash(minimal_detection)
        with_internal = dict(minimal_detection)
        with_internal["_template_path"] = "/tmp/x.yaml"
        with_internal["_probe_future_internal"] = "z"
        assert provider.compute_content_hash(with_internal) == base_hash


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
