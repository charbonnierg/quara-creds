"""pync authorities list command"""
import typing as t

import typer
from rich.console import Console
from rich.table import Table

from quara.creds.manager import NebulaCertManager

console = Console()


def list_cmd(
    root: t.Optional[str] = typer.Option(
        None, "--root", "-r", help="Nebula root directory", envvar="PYNC_NEBULA_ROOT"
    ),
    config: t.Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="pync configuration file",
        envvar="PYNC_NEBULA_CONFIG",
    ),
) -> None:
    """List authorities present in pync config"""
    if config is not None:
        manager = NebulaCertManager.from_config_file(config)
    else:
        manager = NebulaCertManager.from_root(root)
    table = Table(title="pync authorities")
    table.add_column("Authority")
    table.add_column("Name")
    table.add_column("Certificate URI")
    table.add_column("Keystore")
    table.add_column("Lighthouses")

    for alias, authority in manager.authorities.items():

        table.add_row(
            alias,
            authority.name,
            authority.certificate,
            authority.keystore,
            ", ".join(authority.lighthouses),
        )

    console.print(table)
    raise typer.Exit(0)
