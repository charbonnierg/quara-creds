"""pync csr list command"""
import typing as t
from collections import defaultdict

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
    authority: str = typer.Option(
        None, "--ca", help="Name of CA used to sign the certificate"
    ),
) -> None:
    """List certificate signing requests"""
    if config is not None:
        manager = NebulaCertManager.from_config_file(config)
    else:
        manager = NebulaCertManager.from_root(root)
    table = Table(title="Nebula certificates")
    table.add_column("Authority")
    table.add_column("Name")
    table.add_column("IP")
    table.add_column("Groups")
    table.add_column("Subnets")
    table.add_column("Duration")

    if authority is None:
        authorities = list(manager.authorities)
    else:
        authorities = [authority]

    user_rows: t.Dict[str, t.List[t.Tuple[str, ...]]] = defaultdict(list)

    for authority in authorities:
        for options in manager.storage.iterate_certificate_requests(
            authority=authority
        ):
            user_rows[options.Name].append(
                (
                    authority,
                    options.Name,
                    options.Ip,
                    ", ".join(options.Groups),
                    ", ".join(options.Subnets) or "*",
                    options.NotAfter,
                )
            )

    for rows in user_rows.values():
        for row in rows:
            table.add_row(*row)
    console.print(table)
    raise typer.Exit(0)
