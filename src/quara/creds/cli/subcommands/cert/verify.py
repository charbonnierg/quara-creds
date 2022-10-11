"""pync cert verify command"""
import typing as t

import typer

from quara.creds.cli.utils import get_manager
from quara.creds.nebula.api import (
    InvalidCertificateError,
    read_node_certificate,
    verify_certificate,
)


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
    authority: t.Optional[str] = typer.Option(
        None,
        "--ca",
        help="Name of authority for which issued certificates should be verifited. By default certificates issued by all authorities are verified.",
    ),
    name: t.Optional[str] = typer.Option(
        None, "--name", "-n", help="Name of certificate managed by pync"
    ),
    path: t.Optional[str] = typer.Option(
        None,
        "--path",
        "-p",
        help="Path to certificate (useful when certificate is not managed by pync)",
    ),
) -> None:
    """Verify one or several certificates issued by authorities."""
    manager = get_manager(config, root)

    name = name or manager.default_user
    if authority is None:
        authorities = list(manager.authorities)
    else:
        authorities = [authority]
    if path is not None:
        try:
            crt = read_node_certificate(path)
        except FileNotFoundError:
            typer.echo(f"Certificate not found: {path}")
            raise typer.Exit(1)
        errors: t.Dict[str, str] = {}
        for authority in authorities:
            try:
                ca_crt = manager.storage.get_signing_certificate(authority=authority)
            except FileNotFoundError:
                typer.echo(f"Missing certificate for CA {authority}", err=True)
                raise typer.Exit(1)
            try:
                verify_certificate(ca_crt=ca_crt, crt=crt)
            except InvalidCertificateError as exc:
                errors[authority] = exc.msg
        if errors:
            typer.echo("Invalid certificate")
            for ca, error in errors.items():
                typer.echo(f"Error for CA {ca}: {error}")
            raise typer.Exit(1)
        else:
            typer.echo(
                f"Certificate expires on {crt.get_expiration_timestamp().isoformat()}"
            )
            raise typer.Exit(0)
    found = False
    for authority in authorities:
        try:
            ca_crt = manager.storage.get_signing_certificate(authority=authority)
        except FileNotFoundError:
            typer.echo(f"Missing certificate for CA {authority}", err=True)
            raise typer.Exit(1)
        try:
            crt = manager.storage.get_certificate(authority=authority, name=name)
        except FileNotFoundError:
            continue
        else:
            found = True
        try:
            verify_certificate(ca_crt=ca_crt, crt=crt)
        except InvalidCertificateError as exc:
            typer.echo(
                f"Certificate {name} issued by CA {authority} is invalid: {exc.msg}"
            )
            raise typer.Exit(1)
        typer.echo(
            f"Certificate {name} issued by CA {authority} expires on {crt.get_expiration_timestamp().isoformat()}"
        )

    if not found:
        typer.echo(f"Certificate not found: {name}", err=True)
        raise typer.Exit(1)

    raise typer.Exit(0)
