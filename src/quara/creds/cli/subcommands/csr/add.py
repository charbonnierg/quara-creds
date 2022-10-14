"""pync csr import command"""
import typing as t

import typer

from quara.creds.cli.utils import get_manager
from quara.creds.nebula.errors import InvalidSigningOptionError


def add_cmd(
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
    activation: str = typer.Option(
        None,
        "--not-before",
        help=(
            "amount of time before the certificate should be valid. "
            'Valid time units are seconds: "s", minutes: "m", hours: "h"'
        ),
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
    ip: str = typer.Option(
        ...,
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
    """Add a new signing request"""
    manager = get_manager(config, root)
    for csr in manager.csr.list(
        authorities=authorities, names=name or manager.default_user
    ):
        typer.echo(
            f"Signing request already exist for authority {csr.authority} and name {csr.options.Name}",
            err=True,
        )
        raise typer.Exit(1)
    try:
        manager.csr.update(
            name=name,
            authorities=authorities,
            ip=ip,
            duration=duration,
            activation=activation,
            groups=groups,
            subnets=subnets,
        )
    except InvalidSigningOptionError as exc:
        typer.echo(f"Invalid signing options: {str(exc)}", err=True)
        raise typer.Exit(1)
