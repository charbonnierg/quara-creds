"""pync cert verify command"""
import typing as t

import typer

from quara.creds.cli.utils import get_manager
from quara.creds.nebula.api import InvalidCertificateError


def verify_cmd(
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
    authorities: t.Optional[str] = typer.Option(
        None,
        "--ca",
        help="Name of authority for which issued certificates should be verifited. By default certificates issued by all authorities are verified.",
    ),
    name: t.Optional[str] = typer.Option(
        None, "--name", "-n", help="Name of certificate managed by pync"
    ),
) -> None:
    """Verify one or several certificates issued by authorities."""
    manager = get_manager(config, root)
    certificates = manager.certificates.list_by_authority(
        authorities=authorities, names=name
    )
    valid = True
    for authority, certs in certificates.items():
        try:
            ca_crt = manager.storage.get_signing_certificate(authority=authority)
        except FileNotFoundError:
            typer.echo(f"Missing certificate for CA {authority}", err=True)
            raise typer.Exit(1)
        for crt in certs:
            try:
                ca_crt.verify_certificate(crt)
            except InvalidCertificateError as exc:
                typer.echo(
                    f"Certificate '{crt.Name}' issued by authority {authority} is invalid: {str(exc)}",
                    err=True,
                )
                valid = False
            else:
                typer.echo(
                    f"Certificate '{crt.Name}' issued by authority {authority} expires on {crt.get_expiration_timestamp().isoformat()}"
                )
    if not valid:
        raise typer.Exit(1)
