import typer

from .add import add_cmd
from .import_ import import_cmd
from .list import list_cmd
from .rm import rm_cmd
from .update import update_cmd

app = typer.Typer(
    name="csr",
    no_args_is_help=True,
    add_completion=False,
    help="Manage nebula certificate signing requests",
)


app.command("list")(list_cmd)
app.command("rm")(rm_cmd)
app.command("import")(import_cmd)
app.command("update")(update_cmd)
app.command("add")(add_cmd)
