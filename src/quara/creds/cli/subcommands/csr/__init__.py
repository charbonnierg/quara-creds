import typer

from .import_ import import_cmd
from .list import list_cmd
from .rm import rm_cmd
from .show import show_cmd
from .update import update_cmd

app = typer.Typer(
    name="csr",
    no_args_is_help=True,
    add_completion=False,
    help="Manage nebula certificate signing requests",
)


app.command("show")(show_cmd)
app.command("list")(list_cmd)
app.command("rm")(rm_cmd)
app.command("import")(import_cmd)
app.command("update")(update_cmd)
