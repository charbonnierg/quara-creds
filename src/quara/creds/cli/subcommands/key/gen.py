import typing as t

import typer

from quara.creds.cli.utils import get_manager
from quara.creds.nebula import EncryptionKeyPair


def gen_cmd(
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
    force: bool = typer.Option(
        False, "--force", "-f", help="Overwrite files if they already exist."
    ),
) -> None:
    """Create a new public key and associated private key"""
    manager = get_manager(config, root)

    keypair = EncryptionKeyPair()
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
