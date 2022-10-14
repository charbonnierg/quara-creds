"""pync csr rm command"""
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
        None, "--ca", help="Name of CA used to sign the certificate"
    ),
    name: t.Optional[str] = typer.Option(
        None,
        "--name",
        "-n",
        help="Certificate signing request name. Current username is used when not provided.",
    ),
) -> None:
    """Remove certificate signing request by name"""
    manager = get_manager(config, root)
    manager.csr.remove(name=name, authorities=authorities)
    raise typer.Exit(0)
