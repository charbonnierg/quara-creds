import typer

from quara.creds.nebula import __version__


def version_callback(value: bool) -> None:
    """Display pync version"""
    if value:
        typer.echo(f"{__version__}")
        raise typer.Exit(0)
