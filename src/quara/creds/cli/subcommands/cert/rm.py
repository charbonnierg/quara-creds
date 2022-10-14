"""pync cert rm command"""
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
    authorities: str = typer.Option(
        None,
        "--ca",
        help="Name of authority which issued certificate. By default certificate is removed for all authorities.",
    ),
    name: t.Optional[str] = typer.Option(
        None,
        "--name",
        "-n",
        help="Certificate name. Current username is used when not provided.",
    ),
) -> None:
    """Remove nebula node certificates by name"""
    manager = get_manager(config, root)
    manager.certificates.remove(name=name, authorities=authorities)
