"""pync key gen command"""
import typing as t

import typer

from quara.creds.cli.utils import get_manager
from quara.creds.manager import errors


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
    update: bool = typer.Option(
        False, "--update", "-U", help="Overwrite files if they already exist."
    ),
) -> None:
    """Create a new nebula X25519 keypair and save it within store."""
    manager = get_manager(config, root)
    try:
        manager.keys.gen(name=name, update=update)
    except errors.KeyPairExistsError:
        typer.echo(f"Error: a keypair named {name} already exists", err=True)
        typer.echo(
            "\nThe '--update' or '-U' option can be used to overwrite existing keypair.",
            err=True,
        )
        raise typer.Exit(1)
    else:
        raise typer.Exit(0)
