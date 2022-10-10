"""pync csr import command"""
import typing as t
from json import loads
from pathlib import Path

import requests
import typer

from quara.creds.cli.utils import get_manager
from quara.creds.nebula.interfaces import SigningOptions


def import_cmd(
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
        None,
        "--name",
        "-n",
        help="Keypair name. Current username is used when not provided.",
    ),
    uri: str = typer.Option(
        ...,
        "--uri",
        "-u",
        help="URI pointing to options or path to options",
    ),
    force: bool = typer.Option(
        False, "--force", "-f", help="Overwrite files if they already exist."
    ),
) -> None:
    """Import signing options from URL or path"""
    manager = get_manager(config, root)
    name = name or manager.default_user
    # Gather list of authorities used to issue certificates
    if authority is None:
        authorities = list(manager.authorities)
    else:
        authorities = [authority]
    try:
        if uri.startswith("file://"):
            uri = uri[7:]
            uri_path = Path(uri).expanduser()
            if uri_path.exists():
                options = SigningOptions(**loads(uri_path.read_bytes()))
            else:
                typer.echo(f"File not found: {uri_path.as_posix()}", err=True)
                raise typer.Exit(1)
        elif uri.startswith("http://") or uri.startswith("https://"):
            options = SigningOptions(requests.get(uri_path))
        else:
            uri_path = Path(uri).expanduser()
            if uri_path.exists():
                options = SigningOptions(**loads(uri_path.read_bytes()))
            else:
                typer.echo(f"File not found: {uri_path.as_posix()}", err=True)
                raise typer.Exit(1)
    except Exception as exc:
        typer.echo(f"Failed to load options: {str(exc)}", err=True)
        raise typer.Exit(1)

    for authority in authorities:
        try:
            manager.storage.get_signing_request(authority, name)
        except FileNotFoundError:
            pass
        else:
            if not force:
                typer.echo(
                    f"Error: a signing request named {name} already exists for authority {authority}",
                    err=True,
                )
                typer.echo(
                    "\nThe '--force' or '-f' option can be used to force overwrite.",
                    err=True,
                )
                raise typer.Exit(1)
        manager.storage.save_signing_request(
            name=name,
            options=options,
        )

    raise typer.Exit(0)
