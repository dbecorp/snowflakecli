import typer
from typing import Optional
from typing_extensions import Annotated
from pathlib import Path

from cli.core.snowflake.sql import Sql
from cli.core.snowflake.query import query_all, tabulate_to_stdout
from cli.core.fs import get_file_contents


app = typer.Typer(no_args_is_help=True)


@app.command()
def execute(
    ctx: typer.Context,
    query: Annotated[
        Optional[str], typer.Option("-q", help="The sql query to execute")
    ] = None,
    file: Annotated[
        Optional[str], typer.Option("-f", help="The sql file to execute")
    ] = None,
):
    """Execute Snowflake SQL statements"""
    if query:
        sql = Sql(statement=query)
    if file:
        sql = Sql(statement=get_file_contents(Path(file)))
    results = query_all(ctx.obj.cursor, sql)
    tabulate_to_stdout(results)
    return results


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
