"""pync key list command"""
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
        help="pync configuration file",
        envvar="PYNC_NEBULA_CONFIG",
    ),
    private: bool = typer.Option(
        False,
        "--private",
        help="List private keys. False by default, which means that a public key is expected.",
    ),
    json: bool = typer.Option(False, "--json", help="Return results in JSON format"),
) -> None:
    """List public or private keys"""
    manager = get_manager(config, root)

    if json:
        if private:
            typer.echo(manager.keys.export_keypairs())
        else:
            typer.echo(manager.keys.export_public_keys())
        raise typer.Exit(0)

    if private:
        table = Table(title="Nebula X25519 keypairs")
        table.add_column("Name")
        table.add_column("Public key")
        table.add_column("Private key")
        for name, keypair in manager.storage.find_keypairs():
            table.add_row(
                name, keypair.to_public_bytes().hex(), keypair.to_private_bytes().hex()
            )
        console.print(table)
        raise typer.Exit(0)

    table = Table(title="Nebula X25519 public keys")
    table.add_column("Name")
    table.add_column("Public key")
    table.add_column("Private key is stored")
    known_keypairs = manager.keys.list_keypairs()
    for name, pubkey in manager.storage.find_public_keys():
        is_stored = (
            "Yes" if (name, pubkey.to_public_bytes()) in known_keypairs else "No"
        )
        table.add_row(name, pubkey.to_public_bytes().hex(), is_stored)

    console.print(table)

    raise typer.Exit(0)
