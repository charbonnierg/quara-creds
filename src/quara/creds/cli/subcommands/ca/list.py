"""pync nebula ca list CLI command"""
import typing as t
from textwrap import wrap

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
) -> None:
    """List certificates"""
    manager = get_manager(config, root)
    # Create a new rich table
    table = Table(title="Nebula CA certificates")
    table.add_column("Authority")
    table.add_column("Name")
    table.add_column("IPs")
    table.add_column("Groups")
    table.add_column("Not After")
    table.add_column("Public Key")
    # Iterate over authorities
    for authority in manager.authorities:
        # Load authority certificate
        cert = manager.storage.get_signing_certificate(authority)
        # Add new row to table
        table.add_row(
            authority,
            cert.Name,
            "\n".join(wrap(" ".join(cert.Ips), width=18, break_long_words=False)),
            "\n".join(wrap(" ".join(cert.Groups), width=20, break_long_words=False)),
            cert.get_expiration_timestamp().isoformat(),
            cert.PublicKey.hex(),
        )
    # Print the table
    console.print(table)
    raise typer.Exit(0)
