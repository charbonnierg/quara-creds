"""pync nebula cert list CLI command"""
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
    authority: str = typer.Option(
        None, "--ca", help="Name of CA used to sign the certificate"
    ),
) -> None:
    """List certificates"""
    if config is not None:
        manager = NebulaCertManager.from_config_file(config)
    else:
        manager = NebulaCertManager.from_root(root)
    table = Table(title="Nebula certificates")
    table.add_column("Authority")
    table.add_column("Name")
    table.add_column("IP")
    table.add_column("Groups")
    table.add_column("Not Before")
    table.add_column("Not After")
    table.add_column("Public Key")

    if authority is None:
        authorities = list(manager.authorities)
    else:
        authorities = [authority]
    for authority in authorities:
        for cert in manager.storage.iterate_certificates(authority=authority):
            table.add_row(
                authority,
                cert.Name,
                cert.Ips[0],
                ", ".join(cert.Groups),
                cert.get_activation_timestamp().isoformat(),
                cert.get_expiration_timestamp().isoformat(),
                cert.PublicKey.hex(),
            )
    console.print(table)
    raise typer.Exit(0)
