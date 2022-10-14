"""pync cert sign command"""
import typing as t

import typer
from rich.console import Console
from rich.table import Table

from quara.creds.cli.utils import get_manager
from quara.creds.manager.errors import CertificateExistsError
from quara.creds.nebula.errors import InvalidSigningOptionError

console = Console()


def sign_cmd(
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
    all: bool = typer.Option(
        False, "--all", help="Sign certificates for all signing requests in store"
    ),
    authorities: str = typer.Option(
        None, "--ca", help="Name of authority used to sign the certificate"
    ),
    name: t.Optional[str] = typer.Option(
        None, "--name", "-n", help="Name for which certificate is issued"
    ),
    public_key: t.Optional[str] = typer.Option(
        None,
        "--public-key",
        "--pub",
        help="Certificate public key. Useful when emitting certificate for a non-managed keypair.",
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
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite certificate if it already exists, even if certificate is still valid",
    ),
) -> None:
    """Create a new nebula node certificate.

    Certificate will be created according to signin request.

    Use the --update option to provide new signing options and update the signing
    request before signing the certificate.

    When --public-key option is provided, option value is used as public key.

    When --public-key is omitted, public key is retrieved from store, or created when not found.
    """
    manager = get_manager(config, root)

    if all:
        new_certs = list(manager.certificates.sign_all(authorities=authorities))
    else:
        # Update signing requests when options are provided
        if ip or duration or groups or subnets:
            if not update:
                typer.echo(
                    "Error: the --update option must be used in order to update signing request",
                    err=True,
                )
                raise typer.Exit(1)
            try:
                manager.csr.update(
                    name=name,
                    authorities=authorities,
                    duration=duration,
                    groups=groups,
                    ip=ip,
                    subnets=subnets,
                )
            except InvalidSigningOptionError as exc:
                typer.echo(f"Invalid signing options: {str(exc)}", err=True)
                raise typer.Exit(1)
        # Sign certificate
        try:
            new_certs = list(
                manager.certificates.sign(
                    authorities=authorities,
                    name=name,
                    public_key=public_key,
                    renew=force or update,
                )
            )
        except CertificateExistsError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(1)

    # Display newly signed certificates
    table = Table(title="Nebula node certificates")
    table.add_column("Authority")
    table.add_column("Name")
    table.add_column("IP")
    table.add_column("Groups")
    table.add_column("Subnets")
    table.add_column("Not Before")
    table.add_column("Not After")
    table.add_column("Public Key")
    for authority, crt in new_certs:
        table.add_row(
            authority,
            crt.Name,
            crt.get_ip_address(),
            ", ".join(crt.Groups),
            ", ".join(crt.Subnets) or "*",
            crt.get_activation_timestamp().isoformat(),
            crt.get_expiration_timestamp().isoformat(),
            crt.PublicKey.hex(),
        )
    console.print(table)

    raise typer.Exit(0)
