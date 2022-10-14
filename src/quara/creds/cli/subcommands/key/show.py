"""pync key show command"""
import typing as t

import typer

from quara.creds.cli.utils import get_manager
from quara.creds.manager import errors


def show_cmd(
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
    name: str = typer.Option(None, "--name", "-n", help="Name of key to show"),
    raw: bool = typer.Option(
        None, "--raw", help="Show raw public bytes instead of PEM encoded key"
    ),
    json: bool = typer.Option(
        None,
        "--json",
        help="Show raw public bytes in JSON object",
    ),
    private: bool = typer.Option(
        False, "--private", help="Show private key instead of public key"
    ),
) -> None:
    """Show a single key"""
    manager = get_manager(config, root)

    if private:
        try:
            typer.echo(manager.keys.show_private_key(name=name, raw=raw, json=json))
        except errors.KeyPairNotFoundError:
            typer.echo(f"Private key not found: {name or manager.default_user}")
            raise typer.Exit(1)
        else:
            raise typer.Exit(0)

    try:
        typer.echo(manager.keys.show_public_key(name=name, raw=raw, json=json))
    except errors.PublicKeyNotFoundError as exc:
        typer.echo(
            f"Public key not found: {name or manager.default_user}. Error: {str(exc)}"
        )
        raise typer.Exit(1)
    else:
        raise typer.Exit(0)
