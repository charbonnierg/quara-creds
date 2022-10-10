"""pync csr show command"""
import typing as t
from collections import defaultdict
from dataclasses import asdict
from json import dumps

import typer
from rich.console import Console
from rich.table import Table

from quara.creds.cli.utils import get_manager

console = Console()


def show_cmd(
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
    authority: t.Optional[str] = typer.Option(
        None, "--ca", help="Name of CA used to sign the certificate"
    ),
    name: t.Optional[str] = typer.Option(None, "--name", "-n", help="Certificate name"),
    json: bool = typer.Option(False, "--json", help="Display JSON certificate"),
) -> None:
    """Describe a signing certificate.

    When --json option is provided, JSON output is printed.
    """
    manager = get_manager(config, root)

    if authority is None:
        authorities = list(manager.authorities)
    else:
        authorities = [authority]
    name = name or manager.default_user
    found = False
    json_result: t.Dict[str, t.List[t.Dict[str, t.Any]]] = defaultdict(list)
    for authority in authorities:
        try:
            options = manager.storage.get_signing_request(
                authority=authority, name=name
            )
        except FileNotFoundError:
            continue
        else:
            found = True
        if json:
            json_result[authority].append(asdict(options))
            continue
        else:
            table = Table(title=f"Signing options (authority={authority})")
            table.add_column("Field")
            table.add_column("Value")
            for key, value in asdict(options).items():
                table.add_row(key, str(value))
            console.print(table)
    if json_result:
        console.print(dumps(json_result, indent=2))
    if not found:
        typer.echo(f"Certificate request not found: {name}", err=True)
        raise typer.Exit(1)

    raise typer.Exit(0)
