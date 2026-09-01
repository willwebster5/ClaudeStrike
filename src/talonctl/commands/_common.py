"""Shared CLI helpers for talonctl commands."""

import os
import sys
import logging
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from talonctl.project import find_project_root

# Rich console — shared by all commands


def _color_disabled() -> bool:
    """Whether colour output is suppressed, read at call time.

    Read live rather than frozen at import so the console reflects the environment
    it is actually built in — a module-level constant is fixed by whichever import
    happens first, which is not necessarily under the caller's environment.
    """
    return os.getenv("NO_COLOR") is not None or os.getenv("CI") is not None


def make_console(file=None) -> Console:
    """Build the shared Rich console for a given destination.

    force_terminal is only ever set for a real TTY. Forcing it unconditionally made
    Rich emit terminal control sequences into redirected output, so `talonctl drift
    > report.txt` captured a mangled fragment of the report instead of the report.
    """
    stream = file if file is not None else sys.stdout
    is_tty = bool(getattr(stream, "isatty", lambda: False)())
    disable_color = _color_disabled()

    return Console(
        file=file,
        width=200 if os.getenv("CI") else None,
        force_terminal=(not disable_color) if is_tty else False,
        no_color=disable_color,
        force_jupyter=False,
    )


console = make_console()

logger = logging.getLogger("talonctl")


def parse_filters(
    resources: Optional[str] = None,
    tags: Optional[str] = None,
    names: Optional[str] = None,
) -> dict:
    """Parse comma-separated filter strings into lists."""
    filters = {}
    if resources:
        filters["resource_types"] = [r.strip() for r in resources.split(",")]
    if tags:
        filters["tags"] = [t.strip() for t in tags.split(",")]
    if names:
        filters["names"] = [n.strip() for n in names.split(",")]
    return filters


def get_state_file_path(state_file: Optional[str] = None) -> Path:
    """Determine state file path."""
    if state_file:
        return Path(state_file)
    project_root = find_project_root()
    return project_root / ".crowdstrike" / "deployed_state.json"


def resolve_resources_dir() -> Optional[Path]:
    """The resources directory set by the global ``--path`` option, or None.

    Read from the active Click context so any command (and the orchestrator)
    picks it up without threading the value through every call site. Returns
    None when there is no context (e.g. direct function calls in tests) or when
    ``--path`` was not given."""
    ctx = click.get_current_context(silent=True)
    if ctx is not None and ctx.obj:
        return ctx.obj.get("resources_dir")
    return None


def get_resources_dir() -> Path:
    """The effective resources directory: the ``--path`` override if set,
    otherwise the default ``<project-root>/resources``."""
    return resolve_resources_dir() or (find_project_root() / "resources")


def init_orchestrator(
    state_file: Optional[str] = None,
    require_credentials: bool = True,
    remote_state: bool = False,
    remote_state_search_domain: str = "falcon",
    remote_state_filename: str = "unified_deployment_state.json",
):
    """Initialize deployment orchestrator."""
    from falconpy import APIHarnessV2
    from talonctl.utils.auth import load_credentials
    from talonctl.core import DeploymentOrchestrator

    state_file_path = get_state_file_path(state_file)

    creds = None
    falcon = None
    if require_credentials:
        creds = load_credentials()
        falcon = APIHarnessV2(
            client_id=creds["falcon_client_id"],
            client_secret=creds["falcon_client_secret"],
            base_url=creds.get("base_url", "US1"),
        )

    return DeploymentOrchestrator(
        falcon_client=falcon,
        state_file_path=state_file_path,
        resources_dir=resolve_resources_dir(),
        remote_state_enabled=remote_state,
        remote_state_search_domain=remote_state_search_domain,
        remote_state_filename=remote_state_filename,
        credentials=creds,
    )


# Common Click options used by multiple commands
def filter_options(f):
    """Decorator adding --resources, --tags, --names options."""
    f = click.option("--resources", type=str, help="Filter by resource types (comma-separated)")(f)
    f = click.option("--tags", type=str, help="Filter by tags (comma-separated)")(f)
    f = click.option("--names", type=str, help="Filter by resource names (glob patterns, comma-separated)")(f)
    return f


def state_options(f):
    """Decorator adding --state-file option."""
    f = click.option("--state-file", type=str, help="Custom state file location")(f)
    return f


def remote_state_options(f):
    """Decorator adding remote state options."""
    f = click.option("--remote-state", is_flag=True, help="Enable remote state sync")(f)
    f = click.option(
        "--remote-state-search-domain",
        type=click.Choice(["falcon", "all", "third-party", "dashboards", "parsers-repository"]),
        default="falcon",
    )(f)
    f = click.option("--remote-state-filename", type=str, default="unified_deployment_state.json")(f)
    return f
