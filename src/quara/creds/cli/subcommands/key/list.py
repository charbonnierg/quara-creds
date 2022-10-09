"""pync nebula key list CLI command"""
import typing as t
from json import dumps

import typer
from rich.console import Console
from rich.table import Table

from quara.creds.cli.utils import get_manager

console = Console()


def list_cmd(
    root: t.Optional[str] = typer.Option(
        None, "--root", "-r", help="Nebula root directory", envvar="PYNC_NEBULA_ROOT"
    ),
    config: t.Optional[str] = typer.Option(
        None,
        "--config",
        help="pync configuration file",
        envvar="PYNC_NEBULA_CONFIG",
    ),
    json: bool = typer.Option(False, "--json", help="Return results in JSON format"),
) -> None:
    """List keys"""
    manager = get_manager(config, root)

    table = Table(title="Nebula X25519 keypairs")
    table.add_column("Name", justify="left")
    table.add_column("Public key", justify="left")
    if json:
        results: t.List[t.Dict[str, str]] = []
        for name, keypair in manager.storage.iterate_keypairs():
            results.append(
                {
                    "name": name,
                    "public_key": keypair.get_public_bytes().hex(),
                }
            )
        typer.echo(dumps(results, indent=2))
        raise typer.Exit(0)

    for name, keypair in manager.storage.iterate_keypairs():
        table.add_row(name, keypair.get_public_bytes().hex())

    console.print(table)

    raise typer.Exit(0)
