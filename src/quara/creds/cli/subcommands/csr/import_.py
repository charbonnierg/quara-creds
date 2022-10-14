"""pync csr import command"""
import typing as t
from json import loads
from pathlib import Path

import click
import requests
import typer

from quara.creds.cli.utils import get_manager
from quara.creds.nebula.interfaces import SigningOptions


def get_csr_data(value: str) -> str:
    if not value and not click.get_text_stream("stdin").isatty():
        return click.get_text_stream("stdin").read().strip()
    else:
        return value


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
    data: t.Optional[str] = typer.Argument(
        None,
        help="Signing requests as JSON string. Can be parsed from stdin.",
        callback=get_csr_data,
    ),
    file: t.Optional[str] = typer.Option(
        None, "--file", "-f", help="Filepath holding signing options in JSON format."
    ),
    url: t.Optional[str] = typer.Option(
        None,
        "--url",
        "-u",
        help="URL pointing to options or path to signing options",
    ),
    update: bool = typer.Option(
        False, "--update", "-U", help="Overwrite files if they already exist."
    ),
) -> None:
    """Import signing options from URL or path"""
    manager = get_manager(config, root)

    if file:
        filepath = Path(file).expanduser()
        if not filepath.exists():
            typer.echo(f"File does not exist: {filepath.as_posix()}", err=True)
            raise typer.Exit(1)
        data = filepath.read_bytes()
    elif url:
        response = requests.get(url)
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            typer.echo(
                f"Failed to fetch signing options due to HTTP error: {str(exc)}",
                err=True,
            )
            raise typer.Exit(1)
        data = response.content
    elif data is None:
        typer.echo(
            "Either JSON argument, --path or --url option must be provided", err=True
        )
        raise typer.Exit(1)

    json_data = loads(data or [])
    if isinstance(json_data, list):
        for csr_data in json_data:
            options = SigningOptions(**csr_data["options"])
            authority = csr_data["authority"]
            cert_name = csr_data["user"]
            manager.csr.add(
                options=options,
                name=cert_name,
                authorities=authority,
                update=update,
            )
    else:
        options = SigningOptions(**json_data["options"])
        authority = json_data["authority"]
        cert_name = json_data["user"]
        manager.csr.add(
            options=options,
            name=cert_name,
            authorities=authority,
            update=update,
        )

    raise typer.Exit(0)
