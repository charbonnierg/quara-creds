"""pync csr update command"""
import typing as t

import typer
from rich.console import Console

from quara.creds.cli.utils import get_manager
from quara.creds.manager.errors import CertificateNotFoundError
from quara.creds.nebula.errors import InvalidSigningOptionError

console = Console()


def update_cmd(
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
        None, "--name", "-n", help="name of the certificate"
    ),
    duration: str = typer.Option(
        None,
        "--duration",
        "-d",
        help=(
            "amount of time the certificate should be valid for. "
            'Valid time units are seconds: "s", minutes: "m", hours: "h"'
        ),
    ),
    groups: t.Optional[str] = typer.Option(
        None,
        "--groups",
        "-g",
        help="comma separated list of groups. This will limit which groups subordinate certs can use",
    ),
    ip: t.Optional[str] = typer.Option(
        None,
        "--ip",
        "-i",
        help=("IP address and network in CIDR notation. "),
    ),
    subnets: t.Optional[str] = typer.Option(
        None,
        "--subnets",
        "-s",
        help=(
            "comma separated list of ip and network in CIDR notation this certificate can serve for"
        ),
    ),
) -> None:
    """Update certificate request"""
    manager = get_manager(config, root)
    try:
        manager.csr.update(
            name=name,
            authorities=authorities,
            duration=duration,
            groups=groups,
            ip=ip,
            subnets=subnets,
        )
    except CertificateNotFoundError as exc:
        typer.echo(f"Invalid authority: {str(exc)}")
        raise typer.Exit(1)
    except InvalidSigningOptionError as exc:
        typer.echo(f"Invalid signing options: {str(exc)}")
        raise typer.Exit(1)
