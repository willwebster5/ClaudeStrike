"""
Unit tests for DeploymentOrchestrator

Tests deployment planning, wave execution, dependency resolution,
error handling, and state management.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timezone
import tempfile
import json

from talonctl.core.deployment_orchestrator import DeploymentOrchestrator, ResourceChange, DeploymentPlan
from talonctl.core.template_discovery import DiscoveredTemplate
from talonctl.core.resource_graph import ResourceGraph
from talonctl.core import ResourceAction
from tests.unit._helpers import make_envelope


class TestDeploymentOrchestrator:
    """Test suite for DeploymentOrchestrator"""

    @pytest.fixture
    def mock_falcon(self):
        """Create mock Falcon client"""
        mock = Mock()
        # Mock API response for detection rules fetching
        mock.command.return_value = {"status_code": 200, "body": {"resources": []}}
        return mock

    @pytest.fixture
    def temp_state_file(self):
        """Create temporary state file"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            state = {
                "version": "3.0",
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "metadata": {},
                "resources": {"detection": {}, "workflow": {}, "saved_search": {}, "lookup_file": {}},
                "resource_graph": {"nodes": [], "edges": {}},
            }
            json.dump(state, f)
            temp_path = Path(f.name)
        yield temp_path
        if temp_path.exists():
            temp_path.unlink()

    @pytest.fixture
    def orchestrator(self, mock_falcon, temp_state_file):
        """Create DeploymentOrchestrator instance with mocked dependencies"""
        with patch("talonctl.core.deployment_orchestrator.TemplateDiscovery"):
            with patch("talonctl.core.deployment_orchestrator.ProviderAdapter"):
                orch = DeploymentOrchestrator(
                    falcon_client=mock_falcon, state_file_path=temp_state_file, remote_state_enabled=False
                )

                # Mock provider adapter with detection provider
                orch.provider_adapter.providers = {
                    "detection": Mock(),
                    "workflow": Mock(),
                    "saved_search": Mock(),
                    "lookup_file": Mock(),
                }

                return orch

    # ==================== Plan Generation Tests ====================

    def test_plan_simple_create(self, orchestrator):
        """Test planning creation of a single resource"""
        # Mock template discovery
        template = DiscoveredTemplate(
            resource_type="detection",
            name="test_rule",
            file_path=Path("rules/test.yaml"),
            envelope=make_envelope(
                {
                    "resource_id": "test_rule",
                    "name": "Test Rule",
                    "description": "Test",
                    "severity": 50,
                    "search": {"query": "test query"},
                },
                "detection",
            ),
            tags=[],
        )

        orchestrator.template_discovery.discover_all.return_value = {"detection": [template]}

        # Mock provider
        detection_provider = orchestrator.provider_adapter.providers["detection"]
        detection_provider.validate_template.return_value = []
        detection_provider.compute_content_hash.return_value = "abc123"
        detection_provider.extract_dependencies.return_value = []

        # Generate plan
        plan = orchestrator.plan()

        assert len(plan.changes) == 1
        assert plan.changes[0].action == ResourceAction.CREATE
        assert plan.changes[0].resource_type == "detection"
        assert plan.changes[0].resource_name == "test_rule"
        assert plan.statistics["create"] == 1
        assert plan.statistics["update"] == 0
        assert plan.statistics["delete"] == 0

    def test_plan_with_dependencies(self, orchestrator):
        """Test planning with resource dependencies"""
        # Create templates with dependencies
        lookup_template = DiscoveredTemplate(
            resource_type="lookup_file",
            name="trusted_ips",
            file_path=Path("data/trusted_ips.csv"),
            envelope=make_envelope({"resource_id": "trusted_ips", "name": "trusted_ips.csv"}, "lookup_file"),
            tags=[],
        )

        detection_template = DiscoveredTemplate(
            resource_type="detection",
            name="network_check",
            file_path=Path("rules/network_check.yaml"),
            envelope=make_envelope(
                {
                    "resource_id": "network_check",
                    "name": "Network Check",
                    "search": {"query": '| in(name="trusted_ips")'},
                },
                "detection",
            ),
            tags=[],
        )

        orchestrator.template_discovery.discover_all.return_value = {
            "lookup_file": [lookup_template],
            "detection": [detection_template],
        }

        # Mock providers
        for provider in orchestrator.provider_adapter.providers.values():
            provider.validate_template.return_value = []
            provider.compute_content_hash.return_value = "abc123"

        # Detection depends on lookup file
        detection_provider = orchestrator.provider_adapter.providers["detection"]
        detection_provider.extract_dependencies.return_value = ["lookup_file.trusted_ips"]

        lookup_provider = orchestrator.provider_adapter.providers["lookup_file"]
        lookup_provider.extract_dependencies.return_value = []

        # Generate plan
        plan = orchestrator.plan()

        # Verify dependency graph
        assert len(plan.waves) == 2  # lookup in wave 1, detection in wave 2
        assert "lookup_file.trusted_ips" in plan.waves[0]
        assert "detection.network_check" in plan.waves[1]

    def test_plan_detects_circular_dependency(self, orchestrator):
        """Test that circular dependencies are detected and raise error"""
        # Create circular dependency: A -> B -> A
        template_a = DiscoveredTemplate(
            resource_type="detection",
            name="rule_a",
            file_path=Path("rules/a.yaml"),
            envelope=make_envelope(
                {"resource_id": "rule_a", "name": "Rule A", "search": {"query_id": "search_b"}},
                "detection",
            ),
            tags=[],
        )

        template_b = DiscoveredTemplate(
            resource_type="saved_search",
            name="search_b",
            file_path=Path("searches/b.yaml"),
            envelope=make_envelope(
                {"resource_id": "search_b", "name": "Search B", "query": '| in(name="lookup_a")'},
                "saved_search",
            ),
            tags=[],
        )

        template_c = DiscoveredTemplate(
            resource_type="lookup_file",
            name="lookup_a",
            file_path=Path("data/a.csv"),
            envelope=make_envelope(
                {"resource_id": "lookup_a", "name": "lookup_a.csv", "_depends_on": ["detection.rule_a"]},
                "lookup_file",
            ),
            tags=[],
        )

        orchestrator.template_discovery.discover_all.return_value = {
            "detection": [template_a],
            "saved_search": [template_b],
            "lookup_file": [template_c],
        }

        # Set up circular dependencies
        orchestrator.provider_adapter.providers["detection"].extract_dependencies.return_value = [
            "saved_search.search_b"
        ]
        orchestrator.provider_adapter.providers["saved_search"].extract_dependencies.return_value = [
            "lookup_file.lookup_a"
        ]
        orchestrator.provider_adapter.providers["lookup_file"].extract_dependencies.return_value = ["detection.rule_a"]

        for provider in orchestrator.provider_adapter.providers.values():
            provider.validate_template.return_value = []

        # Should raise ValueError for circular dependency
        with pytest.raises(ValueError, match="Circular dependency"):
            orchestrator.plan()

    def test_plan_update_existing_resource(self, orchestrator):
        """Test planning update for an existing resource with changes"""
        template = DiscoveredTemplate(
            resource_type="detection",
            name="existing_rule",
            file_path=Path("rules/existing.yaml"),
            envelope=make_envelope(
                {
                    "resource_id": "existing_rule",
                    "name": "Existing Rule",
                    "description": "Updated description",
                    "severity": 70,
                    "search": {"query": "new query"},
                },
                "detection",
            ),
            tags=[],
        )

        orchestrator.template_discovery.discover_all.return_value = {"detection": [template]}

        # Mock existing state with different hash
        orchestrator.state_manager._state["resources"]["detection"]["existing_rule"] = {
            "id": "rule123",
            "content_hash": "old_hash",
            "template_path": "rules/existing.yaml",
        }

        detection_provider = orchestrator.provider_adapter.providers["detection"]
        detection_provider.validate_template.return_value = []
        detection_provider.compute_content_hash.return_value = "new_hash"  # Different hash
        detection_provider.extract_dependencies.return_value = []
        detection_provider.requires_replacement.return_value = False

        # Generate plan
        plan = orchestrator.plan()

        assert len(plan.changes) == 1
        assert plan.changes[0].action == ResourceAction.UPDATE
        assert plan.changes[0].resource_name == "existing_rule"
        assert plan.statistics["update"] == 1

    def test_plan_no_change_for_identical_resource(self, orchestrator):
        """Test that no change is planned for identical resource"""
        template = DiscoveredTemplate(
            resource_type="detection",
            name="unchanged_rule",
            file_path=Path("rules/unchanged.yaml"),
            envelope=make_envelope(
                {
                    "resource_id": "unchanged_rule",
                    "name": "Unchanged Rule",
                    "description": "Same",
                    "severity": 50,
                    "search": {"query": "same query"},
                },
                "detection",
            ),
            tags=[],
        )

        orchestrator.template_discovery.discover_all.return_value = {"detection": [template]}

        # Mock existing state with same hash
        orchestrator.state_manager._state["resources"]["detection"]["unchanged_rule"] = {
            "id": "rule123",
            "content_hash": "same_hash",
            "template_path": "rules/unchanged.yaml",
        }

        detection_provider = orchestrator.provider_adapter.providers["detection"]
        detection_provider.validate_template.return_value = []
        detection_provider.compute_content_hash.return_value = "same_hash"  # Same hash
        detection_provider.extract_dependencies.return_value = []

        # Generate plan
        plan = orchestrator.plan()

        assert len(plan.changes) == 1
        assert plan.changes[0].action == ResourceAction.NO_CHANGE
        assert plan.statistics["no-change"] == 1

    def test_plan_validation_failure_raises_error(self, orchestrator):
        """Test that template validation errors raise ValueError"""
        template = DiscoveredTemplate(
            resource_type="detection",
            name="invalid_rule",
            file_path=Path("rules/invalid.yaml"),
            envelope=make_envelope(
                {
                    "resource_id": "invalid_rule",
                    "name": "Invalid Rule",
                    # Missing required fields
                },
                "detection",
            ),
            tags=[],
        )

        orchestrator.template_discovery.discover_all.return_value = {"detection": [template]}

        detection_provider = orchestrator.provider_adapter.providers["detection"]
        detection_provider.validate_template.return_value = [
            "Missing required field: description",
            "Missing required field: severity",
        ]
        detection_provider.extract_dependencies.return_value = []

        # Should raise ValueError
        with pytest.raises(ValueError, match="Invalid template"):
            orchestrator.plan()

    # ==================== Deployment Execution Tests ====================

    def test_apply_empty_plan(self, orchestrator):
        """Test applying a plan with no changes"""
        plan = DeploymentPlan(
            changes=[], waves=[], statistics={"create": 0, "update": 0, "delete": 0}, graph=ResourceGraph()
        )

        result = orchestrator.apply(plan)

        assert result.success is True
        assert len(result.deployed) == 0
        assert len(result.failed) == 0
        assert len(result.skipped) == 0

    def test_apply_single_resource_create(self, orchestrator):
        """Test applying a plan with single resource creation"""
        change = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="detection",
            resource_id="detection.new_rule",
            resource_name="new_rule",
            new_value={"name": "New Rule", "severity": 50},
        )

        graph = ResourceGraph()
        graph.add_node("detection.new_rule")

        plan = DeploymentPlan(
            changes=[change],
            waves=[["detection.new_rule"]],
            statistics={"create": 1, "update": 0, "delete": 0},
            graph=graph,
        )

        # Mock successful deployment
        detection_provider = orchestrator.provider_adapter.providers["detection"]
        detection_provider.apply_create.return_value = {"rule_id": "new123"}
        detection_provider.compute_content_hash.return_value = "hash123"

        result = orchestrator.apply(plan, auto_approve=True)

        assert result.success is True
        assert len(result.deployed) == 1
        assert "detection.new_rule" in result.deployed
        assert len(result.failed) == 0
        detection_provider.apply_create.assert_called_once()

    def test_apply_respects_wave_ordering(self, orchestrator):
        """Test that resources are deployed in wave order"""
        # Create 3 resources in 2 waves
        change1 = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="lookup_file",
            resource_id="lookup_file.data",
            resource_name="data",
            new_value={"name": "data.csv"},
        )

        change2 = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="detection",
            resource_id="detection.rule_a",
            resource_name="rule_a",
            new_value={"name": "Rule A"},
        )

        change3 = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="detection",
            resource_id="detection.rule_b",
            resource_name="rule_b",
            new_value={"name": "Rule B"},
        )

        graph = ResourceGraph()
        graph.add_dependency("detection.rule_a", "lookup_file.data")
        graph.add_dependency("detection.rule_b", "lookup_file.data")

        waves = graph.get_deployment_waves()

        plan = DeploymentPlan(changes=[change1, change2, change3], waves=waves, statistics={"create": 3}, graph=graph)

        # Mock successful deployments
        orchestrator.provider_adapter.providers["lookup_file"].apply_create.return_value = {"id": "lf1"}
        orchestrator.provider_adapter.providers["detection"].apply_create.return_value = {"rule_id": "r1"}

        for provider in orchestrator.provider_adapter.providers.values():
            provider.compute_content_hash.return_value = "hash"

        result = orchestrator.apply(plan, auto_approve=True, parallel=2)

        assert result.success is True
        assert len(result.deployed) == 3

        # Verify lookup file was deployed before detections
        assert result.deployed[0] == "lookup_file.data"
        assert "detection.rule_a" in result.deployed[1:]
        assert "detection.rule_b" in result.deployed[1:]

    def test_apply_failed_deployment_skips_dependents(self, orchestrator):
        """Test that failed deployments cause dependent resources to be skipped"""
        change1 = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="lookup_file",
            resource_id="lookup_file.data",
            resource_name="data",
            new_value={"name": "data.csv"},
        )

        change2 = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="detection",
            resource_id="detection.dependent",
            resource_name="dependent",
            new_value={"name": "Dependent Rule"},
        )

        graph = ResourceGraph()
        graph.add_dependency("detection.dependent", "lookup_file.data")
        waves = graph.get_deployment_waves()

        plan = DeploymentPlan(changes=[change1, change2], waves=waves, statistics={"create": 2}, graph=graph)

        # Mock failed lookup file deployment
        orchestrator.provider_adapter.providers["lookup_file"].apply_create.side_effect = Exception("Deployment failed")
        orchestrator.provider_adapter.providers["detection"].apply_create.return_value = {"rule_id": "r1"}

        for provider in orchestrator.provider_adapter.providers.values():
            provider.compute_content_hash.return_value = "hash"

        result = orchestrator.apply(plan, auto_approve=True)

        assert result.success is False
        assert len(result.failed) == 1
        assert len(result.skipped) == 1
        assert "detection.dependent" in result.skipped

        # Detection should not have been attempted
        orchestrator.provider_adapter.providers["detection"].apply_create.assert_not_called()

    def test_apply_parallel_execution_within_wave(self, orchestrator):
        """Test that resources within a wave are deployed in parallel"""
        # Create 3 independent resources in same wave
        changes = []
        for i in range(3):
            changes.append(
                ResourceChange(
                    action=ResourceAction.CREATE,
                    resource_type="detection",
                    resource_id=f"detection.rule_{i}",
                    resource_name=f"rule_{i}",
                    new_value={"name": f"Rule {i}"},
                )
            )

        graph = ResourceGraph()
        for change in changes:
            graph.add_node(change.resource_id)

        plan = DeploymentPlan(
            changes=changes,
            waves=[[c.resource_id for c in changes]],  # All in one wave
            statistics={"create": 3},
            graph=graph,
        )

        # Mock successful deployments
        detection_provider = orchestrator.provider_adapter.providers["detection"]
        detection_provider.apply_create.return_value = {"rule_id": "r1"}
        detection_provider.compute_content_hash.return_value = "hash"

        result = orchestrator.apply(plan, auto_approve=True, parallel=3)

        assert result.success is True
        assert len(result.deployed) == 3
        # All 3 resources should be deployed (order may vary due to parallelism)
        assert set(result.deployed) == {f"detection.rule_{i}" for i in range(3)}

    # ==================== Rollback Tests ====================

    def test_apply_rollback_disabled_by_default(self, orchestrator):
        """Test that rollback does not occur by default when enable_rollback=False"""
        # Create 2 resources in same wave, one will fail
        change1 = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="detection",
            resource_id="detection.success",
            resource_name="success",
            new_value={"name": "Success Rule"},
            envelope=make_envelope({"resource_id": "success", "name": "Success Rule"}, "detection"),
        )

        change2 = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="detection",
            resource_id="detection.fail",
            resource_name="fail",
            new_value={"name": "Fail Rule"},
            envelope=make_envelope({"resource_id": "fail", "name": "Fail Rule"}, "detection"),
        )

        graph = ResourceGraph()
        graph.add_node("detection.success")
        graph.add_node("detection.fail")

        plan = DeploymentPlan(
            changes=[change1, change2],
            waves=[["detection.success", "detection.fail"]],
            statistics={"create": 2},
            graph=graph,
        )

        # Mock one success and one failure. Providers now receive an Envelope.
        detection_provider = orchestrator.provider_adapter.providers["detection"]

        def mock_apply_create(env):
            if env.to_working_dict().get("name") == "Fail Rule":
                raise Exception("Deployment failed")
            return {"rule_id": "success123"}

        detection_provider.apply_create.side_effect = mock_apply_create
        detection_provider.compute_content_hash.return_value = "hash"

        result = orchestrator.apply(plan, auto_approve=True, enable_rollback=False)

        # Should have one success and one failure, but no rollback
        assert result.success is False
        assert len(result.deployed) == 1
        assert "detection.success" in result.deployed
        assert len(result.failed) == 1
        assert result.failed[0][0] == "detection.fail"

    def test_apply_rollback_on_wave_failure(self, orchestrator):
        """Test that successful deployments are rolled back when wave fails with enable_rollback=True"""
        # Create 2 resources in same wave, one will succeed then one will fail
        change1 = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="detection",
            resource_id="detection.success",
            resource_name="success",
            new_value={"name": "Success Rule"},
            envelope=make_envelope({"resource_id": "success", "name": "Success Rule"}, "detection"),
        )

        change2 = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="detection",
            resource_id="detection.fail",
            resource_name="fail",
            new_value={"name": "Fail Rule"},
            envelope=make_envelope({"resource_id": "fail", "name": "Fail Rule"}, "detection"),
        )

        graph = ResourceGraph()
        graph.add_node("detection.success")
        graph.add_node("detection.fail")

        plan = DeploymentPlan(
            changes=[change1, change2],
            waves=[["detection.success", "detection.fail"]],
            statistics={"create": 2},
            graph=graph,
        )

        # Mock one success and one failure. Providers now receive an Envelope.
        detection_provider = orchestrator.provider_adapter.providers["detection"]

        def mock_apply_create(env):
            if env.to_working_dict().get("name") == "Fail Rule":
                raise Exception("Deployment failed")
            return {"rule_id": "success123"}

        detection_provider.apply_create.side_effect = mock_apply_create
        detection_provider.compute_content_hash.return_value = "hash"

        result = orchestrator.apply(plan, auto_approve=True, enable_rollback=True)

        # Should have rolled back the successful deployment
        assert result.success is False
        assert len(result.deployed) == 0  # Rolled back, so nothing deployed
        assert len(result.failed) == 1
        assert result.failed[0][0] == "detection.fail"

    def test_apply_rollback_aborts_remaining_waves(self, orchestrator):
        """Test that rollback aborts deployment of remaining waves"""
        # Create 3 resources in 2 waves
        change1 = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="lookup_file",
            resource_id="lookup_file.data",
            resource_name="data",
            new_value={"name": "data.csv"},
        )

        change2 = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="detection",
            resource_id="detection.dependent",
            resource_name="dependent",
            new_value={"name": "Dependent Rule"},
        )

        change3 = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="workflow",
            resource_id="workflow.notify",
            resource_name="notify",
            new_value={"name": "Notify Workflow"},
        )

        graph = ResourceGraph()
        graph.add_dependency("detection.dependent", "lookup_file.data")
        graph.add_dependency("workflow.notify", "detection.dependent")
        waves = graph.get_deployment_waves()

        plan = DeploymentPlan(changes=[change1, change2, change3], waves=waves, statistics={"create": 3}, graph=graph)

        # Mock first wave success, second wave failure
        orchestrator.provider_adapter.providers["lookup_file"].apply_create.return_value = {"id": "lf1"}
        orchestrator.provider_adapter.providers["detection"].apply_create.side_effect = Exception("Deployment failed")
        orchestrator.provider_adapter.providers["workflow"].apply_create.return_value = {"id": "wf1"}

        for provider in orchestrator.provider_adapter.providers.values():
            provider.compute_content_hash.return_value = "hash"

        result = orchestrator.apply(plan, auto_approve=True, enable_rollback=True)

        # First wave should be rolled back, third wave should be skipped
        assert result.success is False
        assert len(result.deployed) == 0  # Rolled back
        assert len(result.failed) == 1  # detection failed
        assert "detection.dependent" in [f[0] for f in result.failed]
        assert "workflow.notify" in result.skipped  # Third wave skipped

        # Workflow should never have been attempted
        orchestrator.provider_adapter.providers["workflow"].apply_create.assert_not_called()

    def test_apply_rollback_update_restores_previous_state(self, orchestrator):
        """Test that rollback of update restores previous state"""
        # Create an update and a create in same wave, create will fail
        change1 = ResourceChange(
            action=ResourceAction.UPDATE,
            resource_type="detection",
            resource_id="detection.existing",
            resource_name="existing",
            new_value={"name": "Existing Rule", "severity": 70},
            old_value={"id": "rule123", "name": "Existing Rule", "severity": 50, "content_hash": "old_hash"},
            envelope=make_envelope({"resource_id": "existing", "name": "Existing Rule", "severity": 70}, "detection"),
        )

        change2 = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="detection",
            resource_id="detection.new",
            resource_name="new",
            new_value={"name": "New Rule"},
            envelope=make_envelope({"resource_id": "new", "name": "New Rule"}, "detection"),
        )

        graph = ResourceGraph()
        graph.add_node("detection.existing")
        graph.add_node("detection.new")

        plan = DeploymentPlan(
            changes=[change1, change2],
            waves=[["detection.existing", "detection.new"]],
            statistics={"update": 1, "create": 1},
            graph=graph,
        )

        # Mock update success but create failure
        detection_provider = orchestrator.provider_adapter.providers["detection"]

        call_count = {"count": 0}

        def mock_update(resource_id, template, old_value=None):
            call_count["count"] += 1
            if call_count["count"] == 1:
                # First call is the actual update
                return {"rule_id": resource_id}
            else:
                # Second call is the rollback
                return {"rule_id": resource_id}

        detection_provider.apply_update.side_effect = mock_update

        def mock_create(env):
            if env.to_working_dict().get("name") == "New Rule":
                raise Exception("Create failed")
            return {"rule_id": "new123"}

        detection_provider.apply_create.side_effect = mock_create
        detection_provider.compute_content_hash.return_value = "hash"

        result = orchestrator.apply(plan, auto_approve=True, enable_rollback=True)

        # Update should be rolled back
        assert result.success is False
        assert len(result.deployed) == 0  # All rolled back
        assert len(result.failed) == 1

        # apply_update should be called twice: once for update, once for rollback
        assert detection_provider.apply_update.call_count == 2

    # ==================== State Management Tests ====================

    def test_state_updated_after_successful_deployment(self, orchestrator):
        """Test that state is updated after successful deployment"""
        change = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="detection",
            resource_id="detection.new_rule",
            resource_name="new_rule",
            new_value={"name": "New Rule", "severity": 50},
        )

        graph = ResourceGraph()
        graph.add_node("detection.new_rule")

        plan = DeploymentPlan(changes=[change], waves=[["detection.new_rule"]], statistics={"create": 1}, graph=graph)

        detection_provider = orchestrator.provider_adapter.providers["detection"]
        detection_provider.apply_create.return_value = {"rule_id": "new123"}
        detection_provider.compute_content_hash.return_value = "hash123"

        orchestrator.apply(plan, auto_approve=True)

        # Verify state was updated
        state = orchestrator.state_manager.export_to_dict()
        assert "detection" in state["resources"]
        assert "new_rule" in state["resources"]["detection"]
        assert state["resources"]["detection"]["new_rule"]["content_hash"] == "hash123"

    def test_state_not_updated_on_failed_deployment(self, orchestrator):
        """Test that state is not updated when deployment fails"""
        change = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="detection",
            resource_id="detection.fail_rule",
            resource_name="fail_rule",
            new_value={"name": "Fail Rule"},
        )

        graph = ResourceGraph()
        graph.add_node("detection.fail_rule")

        plan = DeploymentPlan(changes=[change], waves=[["detection.fail_rule"]], statistics={"create": 1}, graph=graph)

        # Mock failed deployment
        detection_provider = orchestrator.provider_adapter.providers["detection"]
        detection_provider.apply_create.side_effect = Exception("Deployment failed")

        orchestrator.apply(plan, auto_approve=True)

        # Verify state was NOT updated
        state = orchestrator.state_manager.export_to_dict()
        assert "fail_rule" not in state["resources"].get("detection", {})

    # ==================== Validation Tests ====================

    def test_validate_all_templates(self, orchestrator):
        """Test validation of all templates without deployment"""
        templates = [
            DiscoveredTemplate(
                resource_type="detection",
                name="valid",
                file_path=Path("rules/valid.yaml"),
                envelope=make_envelope(
                    {"resource_id": "valid", "name": "Valid", "severity": 50, "search": {"query": "test"}},
                    "detection",
                ),
                tags=[],
            ),
            DiscoveredTemplate(
                resource_type="detection",
                name="invalid",
                file_path=Path("rules/invalid.yaml"),
                envelope=make_envelope({"resource_id": "invalid", "name": "Invalid"}, "detection"),
                tags=[],
            ),
        ]

        orchestrator.template_discovery.discover_all.return_value = {"detection": templates}

        detection_provider = orchestrator.provider_adapter.providers["detection"]
        detection_provider.validate_template.side_effect = [
            [],  # valid template
            ["Missing required field: severity", "Missing required field: search"],  # invalid
        ]

        results = orchestrator.validate()

        assert len(results) == 2
        assert results["detection.valid"] == []
        assert len(results["detection.invalid"]) == 2

    # ==================== Sync Tests ====================

    def test_sync_with_deployed_resources(self, orchestrator):
        """Test syncing state with deployed resources"""
        template = DiscoveredTemplate(
            resource_type="detection",
            name="deployed_rule",
            file_path=Path("rules/deployed.yaml"),
            envelope=make_envelope({"resource_id": "deployed_rule", "name": "Deployed Rule"}, "detection"),
            tags=[],
        )

        orchestrator.template_discovery.discover_all.return_value = {"detection": [template]}

        # Mock deployed resources from CrowdStrike
        orchestrator.falcon.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"rule_id": "remote123", "name": "deployed_rule", "severity": 50}]},
        }

        detection_provider = orchestrator.provider_adapter.providers["detection"]
        detection_provider.compute_content_hash.return_value = "hash123"
        detection_provider._fetch_all_remote_rules.return_value = {
            "deployed_rule": {"rule_id": "remote123", "name": "deployed_rule", "severity": 50}
        }

        stats = orchestrator.sync()

        assert stats["total_fetched"] == 1
        assert stats["matched_templates"] == 1
        assert stats["updated"] == 1

        # Verify state was updated
        resource = orchestrator.state_manager.get_resource("detection", "deployed_rule")
        assert resource is not None
        assert resource.id == "remote123"

    def test_sync_records_the_permanent_rule_id_not_the_version_id(self, orchestrator):
        """sync is the repair path for broken state, so it must persist rule_id.

        CrowdStrike returns a per-version `id` alongside the permanent `rule_id`.
        Persisting `id` produces a state entry that stops addressing the rule after
        its next update — the defect that let updates target nothing for months.
        """
        template = DiscoveredTemplate(
            resource_type="detection",
            name="deployed_rule",
            file_path=Path("rules/deployed.yaml"),
            envelope=make_envelope({"resource_id": "deployed_rule", "name": "Deployed Rule"}, "detection"),
            tags=[],
            display_name="Deployed Rule",
        )
        orchestrator.template_discovery.discover_all.return_value = {"detection": [template]}

        remote = {
            "id": "01a0203670cf7ef4b92ec5585f8bb609",  # version ULID
            "rule_id": "019c4d499c97767c9564d83fdaaf1ad5",  # permanent
            "name": "Deployed Rule",
            "severity": 50,
        }

        detection_provider = orchestrator.provider_adapter.providers["detection"]
        detection_provider.compute_content_hash.return_value = "hash123"
        detection_provider._fetch_all_remote_rules.return_value = {"Deployed Rule": remote}

        orchestrator.sync()

        resource = orchestrator.state_manager.get_resource("detection", "deployed_rule")
        assert resource is not None
        assert resource.id == "019c4d499c97767c9564d83fdaaf1ad5"

    def test_apply_stores_provider_uuid_in_state_not_iac_key(self, orchestrator):
        """End-to-end: after apply, state id is the real CrowdStrike UUID, not the IaC key."""
        from talonctl.core import ResourceAction

        change = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="saved_search",
            resource_id="saved_search.my_search",
            resource_name="my_search",
            new_value={"name": "My Search", "queryString": "...", "_search_domain": "falcon"},
            template_path="resources/saved_searches/my_search.yaml",
        )

        graph = ResourceGraph()
        graph.add_node("saved_search.my_search")

        plan = DeploymentPlan(
            changes=[change],
            waves=[["saved_search.my_search"]],
            statistics={"create": 1, "update": 0, "delete": 0},
            graph=graph,
        )

        saved_search_provider = orchestrator.provider_adapter.providers["saved_search"]
        saved_search_provider.apply_create.return_value = {
            "id": "real-crowdstrike-uuid",
            "name": "My Search",
            "search_domain": "falcon",
        }
        saved_search_provider.compute_content_hash.return_value = "hash123"

        orchestrator.apply(plan, auto_approve=True)

        state = orchestrator.state_manager.export_to_dict()
        stored_id = state["resources"]["saved_search"]["my_search"]["id"]

        assert stored_id == "real-crowdstrike-uuid", (
            f"UUID write-back failed. Expected 'real-crowdstrike-uuid', got '{stored_id}'. "
            "The IaC key must not be stored as the state id."
        )

    def test_deploy_resource_returns_result_dict_on_create(self, orchestrator):
        """_deploy_resource returns the full provider result dict, not a bool."""
        change = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="saved_search",
            resource_id="saved_search.my_search",
            resource_name="my_search",
            new_value={"name": "My Search", "_search_domain": "falcon"},
        )
        expected = {"id": "uuid-abc123", "name": "My Search", "search_domain": "falcon"}
        orchestrator.provider_adapter.providers["saved_search"].apply_create.return_value = expected

        result = orchestrator._deploy_resource(change)

        assert result == expected

    def test_deploy_resource_returns_none_on_empty_result(self, orchestrator):
        """_deploy_resource returns None when provider returns falsy value."""
        change = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="saved_search",
            resource_id="saved_search.my_search",
            resource_name="my_search",
            new_value={"name": "My Search", "_search_domain": "falcon"},
        )
        orchestrator.provider_adapter.providers["saved_search"].apply_create.return_value = None

        result = orchestrator._deploy_resource(change)

        assert result is None

    def test_deploy_wave_returns_results_keyed_by_resource_id(self, orchestrator):
        """_deploy_wave includes a 'results' key mapping resource_id to provider result."""
        change = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="saved_search",
            resource_id="saved_search.my_search",
            resource_name="my_search",
            new_value={"name": "My Search", "_search_domain": "falcon"},
        )
        provider_result = {"id": "uuid-abc123", "name": "My Search"}
        orchestrator.provider_adapter.providers["saved_search"].apply_create.return_value = provider_result

        wave_result = orchestrator._deploy_wave([change], parallel=1)

        assert "results" in wave_result
        assert "saved_search.my_search" in wave_result["results"]
        assert wave_result["results"]["saved_search.my_search"]["id"] == "uuid-abc123"


class TestOrchestratorEndToEndWithRealProviders:
    """End-to-end tests that drive REAL providers (only the Falcon API client is
    mocked). These exercise the orchestrator -> provider -> envelope.to_working_dict()
    path that mocked-provider tests mask. Before the Task 9 rewire, the orchestrator
    passed dicts into the (now Envelope-consuming) plan_*/apply_* methods, so these
    tests raise AttributeError ('dict' object has no attribute 'to_working_dict').
    """

    @pytest.fixture
    def project(self, tmp_path):
        """Build a real on-disk project: resources tree + binary put file + state file."""
        resources_dir = tmp_path / "resources"
        detections_dir = resources_dir / "detections"
        put_files_dir = resources_dir / "rtr_put_files"
        detections_dir.mkdir(parents=True)
        put_files_dir.mkdir(parents=True)

        # Detection template (unmanaged -> should plan CREATE)
        (detections_dir / "test_rule.yaml").write_text(
            "type: detection\n"
            "resource_id: test_rule\n"
            "name: Test Rule\n"
            "description: An end-to-end test detection rule.\n"
            "severity: 50\n"
            "search:\n"
            "  query: '#repo=base | head(1)'\n"
        )

        # Binary asset for the put file (file-based case -> origin_path/_template_path
        # re-injection must reach the provider so it can locate the binary on disk).
        (put_files_dir / "payload.bin").write_bytes(b"sysmon-config-bytes")
        (put_files_dir / "sysmon_config.yaml").write_text(
            "type: rtr_put_file\n"
            "resource_id: sysmon_config\n"
            "name: sysmonconfig-export.xml\n"
            "description: Sysmon config pushed to endpoints.\n"
            "file_path: payload.bin\n"
        )

        # State file. Seed nothing yet — the rtr_put_file content_hash is filled in by
        # the test once it can call the real provider (hash depends on binary content).
        crowdstrike_dir = tmp_path / ".crowdstrike"
        crowdstrike_dir.mkdir()
        state_file = crowdstrike_dir / "deployed_state.json"
        state_file.write_text(
            json.dumps(
                {
                    "version": "4.0",
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                    "metadata": {},
                    "resources": {},
                    "resource_graph": {"nodes": [], "edges": {}},
                }
            )
        )

        return {
            "root": tmp_path,
            "resources_dir": resources_dir,
            "state_file": state_file,
        }

    def _make_orchestrator(self, project):
        """Real orchestrator + real providers; only the Falcon API client is a MagicMock."""
        falcon = MagicMock()
        return DeploymentOrchestrator(
            falcon_client=falcon,
            state_file_path=project["state_file"],
            resources_dir=project["resources_dir"],
            project_root=project["root"],
            remote_state_enabled=False,
        )

    def _seed_no_change_state(self, project):
        """Write a state entry for the put file whose content_hash matches what the
        REAL provider computes for the current envelope (so plan emits NO-CHANGE).

        Must run BEFORE the orchestrator is constructed: StateManager loads (and
        caches) the state file at init, so the on-disk seed has to exist first.
        Uses throwaway real discovery + provider purely to compute the hash the
        way the orchestrator will."""
        from talonctl.core.template_discovery import TemplateDiscovery
        from talonctl.providers import RTRPutFileProvider

        discovered = TemplateDiscovery(
            resources_dir=project["resources_dir"], project_root=project["root"]
        ).discover_all(resource_types=["rtr_put_file"])
        template = discovered["rtr_put_file"][0]
        provider = RTRPutFileProvider(MagicMock())
        content_hash = provider.compute_content_hash(template.envelope.to_working_dict())

        state = json.loads(project["state_file"].read_text())
        state["resources"]["rtr_put_file"] = {
            "sysmon_config": {
                "type": "rtr_put_file",
                "id": "existing-put-file-id",
                "content_hash": content_hash,
                "template_path": str(template.file_path),
                "deployed_at": datetime.now(timezone.utc).isoformat(),
                "last_modified": datetime.now(timezone.utc).isoformat(),
                "provider_metadata": {"id": "existing-put-file-id"},
                "dependencies": [],
                "display_name": "sysmonconfig-export.xml",
            }
        }
        project["state_file"].write_text(json.dumps(state))
        return content_hash

    def test_plan_create_and_no_change_with_real_providers(self, project):
        """plan() over real providers yields CREATE for the unmanaged detection and
        NO-CHANGE for the put file whose state hash matches the real provider hash."""
        self._seed_no_change_state(project)
        orchestrator = self._make_orchestrator(project)

        plan = orchestrator.plan(skip_query_validation=True)

        by_id = {c.resource_id: c for c in plan.changes}
        assert by_id["detection.test_rule"].action == ResourceAction.CREATE
        assert by_id["rtr_put_file.sysmon_config"].action == ResourceAction.NO_CHANGE
        # The CREATE change must carry the real Envelope for apply to consume.
        assert by_id["detection.test_rule"].envelope is not None

    def test_apply_create_drives_real_detection_provider(self, project):
        """apply() of the detection CREATE reaches the real DetectionProvider, which
        calls the mocked Falcon client's command() — proving the real path runs."""
        orchestrator = self._make_orchestrator(project)

        # Stub the Falcon uber-class create response the DetectionProvider expects.
        # The provider reads the rule back after creating it, so the stub must return
        # a rule whose content matches the template — otherwise the create is (rightly)
        # reported as unverified.
        created_rule = {
            "rule_id": "rule-uuid-123",
            "id": "version-id-1",
            "name": "Test Rule",
            "description": "An end-to-end test detection rule.",
            "severity": 50,
            "status": "active",
            "search": {},
        }

        def command(op, **kwargs):
            # POST answers 201; the verification GET answers 200, as the API does.
            status = 201 if op == "entities_rules_post_v1" else 200
            return {"status_code": status, "body": {"resources": [created_rule]}}

        orchestrator.falcon.command.side_effect = command

        plan = orchestrator.plan(resource_types=["detection"], skip_query_validation=True)
        result = orchestrator.apply(plan, auto_approve=True)

        assert result.success is True
        assert "detection.test_rule" in result.deployed
        # Real provider issued the create against the mocked Falcon client.
        called_cmds = [c.args[0] for c in orchestrator.falcon.command.call_args_list if c.args]
        assert "entities_rules_post_v1" in called_cmds
        # ...and read it back to confirm the platform actually holds it.
        assert "entities_rules_get_v1" in called_cmds


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
