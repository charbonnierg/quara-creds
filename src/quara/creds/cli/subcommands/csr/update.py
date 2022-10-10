"""pync csr update command"""
import typing as t
from time import time

import typer
from rich.console import Console

from quara.creds.cli.utils import get_manager
from quara.creds.nebula.api import InvalidSigningOptionError
from quara.creds.nebula.api.functional import (
    create_signing_options,
    verify_signing_options,
)

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
    authority: str = typer.Option(
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
    update: bool = typer.Option(
        False, help="Update certificate signing request before issuing certificate"
    ),
) -> None:
    """Update certificate request"""
    manager = get_manager(config, root)

    name = name or manager.default_user
    # Gather list of authorities used to issue certificates
    if authority is None:
        authorities = list(manager.authorities)
    else:
        authorities = [authority]

    for authority in authorities:
        # Try to load CA
        try:
            ca_crt = manager.storage.get_signing_certificate(authority)
        except FileNotFoundError:
            typer.echo(f"Unknown authority: {authority}")
            raise typer.Exit(1)

        # Fetch csr if it exists
        try:
            signing_options = manager.storage.get_signing_request(authority, name)
        except FileNotFoundError:
            signing_options = None
        # Check that an IP address is provided
        if signing_options is None and ip is None:
            typer.echo("An IP address must be provided", err=True)
            raise typer.Exit(1)
        # Check if two different IPs are provided
        if signing_options and ip:
            if signing_options.Ip != ip:
                signing_options.Ip = ip
        # Create signing options when necessary
        if signing_options is None:
            if duration == "max":
                duration = f"{int(ca_crt.NotAfter - time()) - 604800}s"
            signing_options = create_signing_options(
                name=name,
                ip=ip,
                groups=groups,
                subnets=subnets,
                duration=duration,
            )
        else:
            # Check if an update is needed
            if groups:
                group_list = groups.split(",")
                if not all(group in signing_options.Groups for group in group_list):
                    for group in group_list:
                        if group not in signing_options.Groups:
                            signing_options.Groups.append(group)

            # Check if an update is needed
            if subnets and not all(
                subnet in signing_options.Subnets for subnet in subnets
            ):
                for subnet in subnets:
                    if subnet not in signing_options.Subnets:
                        signing_options.Subnets.append(subnet)

            # Check if an update is needed
            if duration:
                if duration == "max":
                    duration = f"{int(ca_crt.NotAfter - time()) - 604800}s"
                signing_options.NotAfter = duration
        # Verify signing options
        try:
            verify_signing_options(options=signing_options, ca_crt=ca_crt)
        except InvalidSigningOptionError as exc:
            typer.echo(f"Invalid signing options: {exc.msg}")
            raise typer.Exit(1)
        # Save signing options
        manager.storage.save_signing_request(
            authority=authority, options=signing_options
        )

    raise typer.Exit(0)
