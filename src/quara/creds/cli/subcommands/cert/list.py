"""pync cert list command"""
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
        None,
        "--ca",
        help="Name of authority used to sign the certificate. By default all authorities are used.",
    ),
) -> None:
    """List nebula node certificates"""
    if config is not None:
        manager = NebulaCertManager.from_config_file(config)
    else:
        manager = NebulaCertManager.from_root(root)
    table = Table(title="Nebula node certificates")
    table.add_column("Authority")
    table.add_column("Name")
    table.add_column("IP")
    table.add_column("Groups")
    table.add_column("Subnets")
    table.add_column("Not Before")
    table.add_column("Not After")
    table.add_column("Public Key")

    if authority is None:
        authorities = list(manager.authorities)
    else:
        authorities = [authority]

    user_rows: t.Dict[str, t.List[t.Tuple[str, ...]]] = defaultdict(list)

    for authority in authorities:
        for cert in manager.storage.iterate_certificates(authority=authority):
            user_rows[cert.Name].append(
                (
                    authority,
                    cert.Name,
                    cert.get_ip_address(),
                    ", ".join(cert.Groups),
                    ", ".join(cert.Subnets) or "*",
                    cert.get_activation_timestamp().isoformat(),
                    cert.get_expiration_timestamp().isoformat(),
                    cert.PublicKey.hex(),
                )
            )

    for rows in user_rows.values():
        for row in rows:
            table.add_row(*row)
    console.print(table)
    raise typer.Exit(0)
