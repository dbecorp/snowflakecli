from typing import Union

from snowflake.connector.cursor import SnowflakeCursor
from rich import print
from rich.console import Console
from rich.table import Table

from cli.core.snowflake.sql import Sql
from cli.core.logging import logger


def execute(cursor: SnowflakeCursor, sql: Sql) -> None:
    """Execute a sql statement with the provided cursor"""
    logger.debug(f"executing sql: {sql.statement}")
    return cursor.execute(sql.statement)


def query_all(cursor: SnowflakeCursor, sql: Sql) -> list[dict]:
    """Execute a sql statement with the provided cursor"""
    logger.debug(f"executing sql: {sql.statement}")
    return cursor.execute(sql.statement).fetchall()


def query_first(cursor: SnowflakeCursor, sql: Sql) -> dict:
    """Execute a sql statement with the provided cursor"""
    logger.debug(f"executing sql: {sql.statement}")
    return cursor.execute(sql.statement).fetchone()


def get_keys_from_results(results: Union[list[dict], dict]) -> list[str]:
    """Get the keys from a result"""
    if isinstance(results, list):
        columns = results[0].keys()
    if isinstance(results, dict):
        columns = results.keys()
    return list(columns)


def tabulate_to_stdout(results: Union[list[dict], dict], table_name: str = None) -> str:
    """Formate results as a table to stdout"""
    tbl = Table(title=table_name)
    if isinstance(results, list):
        if len(results) == 0:
            # Short-circuit if no results are returned
            print("[bold green]No results found[/bold green]")
            return
    columns = get_keys_from_results(results)
    if isinstance(results, list):
        rows = results
    else:
        rows = [results]

    for column in columns:
        tbl.add_column(column, style="magenta", no_wrap=True)

    for row in rows:
        tbl.add_row(*[str(row[column]) for column in columns], style="cyan")

    console = Console()
    console.print(tbl)
