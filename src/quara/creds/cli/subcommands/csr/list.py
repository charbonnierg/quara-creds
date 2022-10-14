"""pync csr list command"""
import typing as t
from collections import defaultdict

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
        "-c",
        help="pync configuration file",
        envvar="PYNC_NEBULA_CONFIG",
    ),
    authorities: t.Optional[str] = typer.Option(
        None, "--ca", help="Name of CA used to sign the certificate"
    ),
    names: t.Optional[str] = typer.Option(
        None, "--name", "-n", help="Name of certificate"
    ),
    json: bool = typer.Option(False, "--json", help="Display output in JSON format"),
) -> None:
    """List certificate signing requests"""
    manager = get_manager(config, root)

    if json:
        typer.echo(manager.csr.export(authorities=authorities, names=names))
        raise typer.Exit(0)

    table = Table(title="Nebula signing options")
    table.add_column("Authority")
    table.add_column("Name")
    table.add_column("IP")
    table.add_column("Groups")
    table.add_column("Subnets")
    table.add_column("Duration")

    user_rows: t.Dict[str, t.List[t.Tuple[str, ...]]] = defaultdict(list)

    for csr in manager.csr.list(authorities=authorities, names=names):
        user_rows[csr.options.Name].append(
            (
                csr.authority,
                csr.options.Name,
                csr.options.Ip,
                ", ".join(csr.options.Groups),
                ", ".join(csr.options.Subnets) or "*",
                csr.options.NotAfter,
            )
        )

    for rows in user_rows.values():
        for row in rows:
            table.add_row(*row)

    console.print(table)
    raise typer.Exit(0)
