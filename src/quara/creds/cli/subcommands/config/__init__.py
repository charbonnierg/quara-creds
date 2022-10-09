import typer

from .generate import generate_cmd

app = typer.Typer(
    name="config",
    no_args_is_help=True,
    add_completion=False,
    help="Manage nebula configuration files",
)


app.command("gen")(generate_cmd)
