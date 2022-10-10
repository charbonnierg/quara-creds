"""pync key rm command"""
import typing as t

import typer

from quara.creds.cli.utils import get_manager


def rm_cmd(
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
) -> None:
    """Create a new public key and associated private key"""
    manager = get_manager(config, root)
    name = name or manager.default_user
    manager.storage.delete_keypair(name=name)
    raise typer.Exit(0)
