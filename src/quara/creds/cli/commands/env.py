import typing as t

import typer
from rich.console import Console
from rich.table import Table

from quara.creds.cli.utils import get_manager

console = Console()


def env_cmd(
    root: t.Optional[str] = typer.Option(
        None, "--root", "-r", help="pync root directory", envvar="PYNC_NEBULA_ROOT"
    ),
    config: t.Optional[str] = typer.Option(
        None,
        "--config",
        help="pync configuration file",
        envvar="PYNC_NEBULA_CONFIG",
    ),
) -> None:
    """Display environment used by pync"""
    # Initialize manager
    manager = get_manager(config, root)
    # Create a new rich table
    table = Table(title="pync nebula environment")
    table.add_column("Setting")
    table.add_column("Value")
    # Add rows to the table
    for key, value in manager.describe_settings().items():
        table.add_row(key, value)
    # Print the table
    console.print(table)
    raise typer.Exit(0)
