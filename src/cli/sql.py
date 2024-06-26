import typer
from typing import Optional
from typing_extensions import Annotated

app = typer.Typer(no_args_is_help=True)


@app.command()
def execute(
    query: Annotated[
        Optional[str], typer.Option("-q", help="The sql query to execute")
    ] = None,
    file: Annotated[
        Optional[str], typer.Option("-f", help="The sql file to execute")
    ] = None,
):
    """Execute Snowflake SQL statements"""
    print("executing sql")
    print(f"query: {query}")
    print(f"file: {file}")
    return


@app.command()
def lint(
    query: Annotated[
        Optional[str], typer.Option("-q", help="The sql query to lint")
    ] = None,
    file: Annotated[
        Optional[str], typer.Option("-f", help="The sql file to lint")
    ] = None,
):
    """Lint Snowflake SQL statements"""
    raise NotImplementedError
