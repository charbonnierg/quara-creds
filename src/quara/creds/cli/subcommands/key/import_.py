"""pync key import command"""
import typing as t
from pathlib import Path

import click
import requests
import typer

from quara.creds.cli.utils import get_manager


def get_key_data(value: str) -> str:
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
    name: t.Optional[str] = typer.Option(
        None,
        "--name",
        "-n",
        help="Keypair name. Current username is used when not provided.",
    ),
    data: t.Optional[str] = typer.Argument(
        None,
        help="Private or public key data. Can also be parsed from stdin.",
        callback=get_key_data,
    ),
    file: t.Optional[str] = typer.Option(
        None,
        "--file",
        "-f",
        help="Path to private or public key file.",
    ),
    url: t.Optional[str] = typer.Option(
        None, "--url", "-u", help="URL pointing to private or public key data."
    ),
    private: bool = typer.Option(
        False,
        "--private",
        help="Import private key. False by default, which means that a public key is expected.",
    ),
    update: bool = typer.Option(
        False, "--update", "-U", help="Overwrite files if they already exist."
    ),
) -> None:
    """Import an existing public key or private key into store.

    Key data must be provided through stdin, or through one of
     --data, --file, and --url option.
    """
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
                f"Failed to fetch keypair due to HTTP error: {str(exc)}", err=True
            )
            raise typer.Exit(1)
        data = response.content
    elif data is None:
        typer.echo("Either --data, --path or --url option must be provided", err=True)
        raise typer.Exit(1)

    if private:
        try:
            manager.keys.add_keypair(data, name=name, update=update)
        except Exception as exc:
            typer.echo(f"Failed to import private key: {str(exc)}", err=True)
            raise typer.Exit(1)
        else:
            raise typer.Exit(0)

    try:
        manager.keys.add_public_key(data, name=name, update=update)
    except Exception as exc:
        typer.echo(f"Failed to import public key: {str(exc)}", err=True)
        raise typer.Exit(1)
