"""pync cert list command"""
import typing as t

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
    authorities: str = typer.Option(
        None,
        "--ca",
        help="Name of authority used to sign the certificate. By default all authorities are used.",
    ),
    names: t.Optional[str] = typer.Option(
        None,
        "--name",
        "-n",
        help="Name of certificate",
    ),
    json: bool = typer.Option(
        False,
        "--json",
        help="Display result in JSON format",
    ),
) -> None:
    """List nebula node certificates"""
    manager = get_manager(config=config, root=root)

    if json:
        typer.echo(manager.certificates.export(authorities=authorities, names=names))
        raise typer.Exit(0)

    certificates = manager.certificates.list_by_names(
        authorities=authorities, names=names
    )

    table = Table(title="Nebula node certificates")
    table.add_column("Authority")
    table.add_column("Name")
    table.add_column("IP")
    table.add_column("Groups")
    table.add_column("Subnets")
    table.add_column("Not Before")
    table.add_column("Not After")
    table.add_column("Public Key")

    # for authority, certificate in manager.

    for certs in certificates.values():
        for authority, cert in certs:
            table.add_row(
                authority,
                cert.Name,
                cert.get_ip_address(),
                ", ".join(cert.Groups),
                ", ".join(cert.Subnets) or "*",
                cert.get_activation_timestamp().isoformat(),
                cert.get_expiration_timestamp().isoformat(),
                cert.PublicKey.hex(),
            )

    console.print(table)
    raise typer.Exit(0)
