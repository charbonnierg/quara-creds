"""pync key import command"""
import typing as t
from pathlib import Path

import typer

from quara.creds.cli.utils import get_manager
from quara.creds.nebula.api import parse_encryption_keypair, read_encryption_keypair


def import_cmd(
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
    name: t.Optional[str] = typer.Option(
        None,
        "--name",
        "-n",
        help="Keypair name. Current username is used when not provided.",
    ),
    private_key: str = typer.Option(
        ...,
        "--key",
        "-k",
        help="Private bytes or path to private key",
    ),
    force: bool = typer.Option(
        False, "--force", "-f", help="Overwrite files if they already exist."
    ),
) -> None:
    """Import an existing keypair using private bytes or path to private key file"""
    manager = get_manager(config, root)
    try:
        if Path(private_key).exists():
            keypair = read_encryption_keypair(private_key)
        else:
            keypair = parse_encryption_keypair(private_key)
    except Exception as exc:
        typer.echo(f"Failed to load keypair: {str(exc)}", err=True)
        raise typer.Exit(1)

    name = name or manager.default_user
    try:
        manager.storage.get_keypair(name)
    except FileNotFoundError:
        pass
    else:
        if not force:
            typer.echo(f"Error: a keypair named {name} already exists", err=True)
            typer.echo(
                "\nThe '--force' or '-f' option can be used to force overwrite.",
                err=True,
            )
            raise typer.Exit(1)
    manager.storage.save_keypair(
        name=name,
        keypair=keypair,
    )
    raise typer.Exit(0)
