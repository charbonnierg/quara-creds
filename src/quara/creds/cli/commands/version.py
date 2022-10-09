import typer

from quara.creds.nebula import __version__


def version_callback(value: bool) -> None:
    """Show program name and version"""
    if value:
        typer.echo(f"{__version__}")
        raise typer.Exit(0)
