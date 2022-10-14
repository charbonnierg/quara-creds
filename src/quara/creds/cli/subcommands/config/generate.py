"""pync config gen command"""
import typing as t

import typer

from quara.creds.cli.utils import get_manager


def generate_cmd(
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
        help="Name of keypair and certificates to use in configuration",
    ),
    authorities: t.Optional[str] = typer.Option(
        None, "--ca", help="Name of authority to fetch CA from"
    ),
) -> None:
    """Generate a nebula configuration file with inlined PKI.

    CA certificate, node certificates and node keypaire are embedded into configuration file.
    """
    manager = get_manager(config, root)
    config = manager.nebula_config.gen(
        authorities=authorities,
        name=name,
    )
    typer.echo(config)
