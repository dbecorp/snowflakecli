#!/usr/bin/env python3

import typer
from types import SimpleNamespace
import cli.keypair as keypair
import cli.account as account
import cli.ask as ask
import cli.configure as configure
import cli.connection as connection
import cli.recommend as recommend
import cli.scrape as scrape
import cli.sql as sql
import cli.io as io
import cli.database as database
import cli.warehouse as warehouse
import cli.security as security

from cli.core.config.parser import get_config
from cli.core.constants import SFCLI_DIR
from cli.core.fs import ensure_directory
from cli.core.snowflake.connection import snowflake_cursor
from cli.core.logging import logger


app = typer.Typer(no_args_is_help=True)


app.add_typer(
    keypair.app,
    name="keypair",
    help="Manage Local Snowflake Private/Pub Key Pair",
)
app.add_typer(
    security.app,
    name="security",
    help="Audit The Security of Your Snowflake Account",
)
app.add_typer(
    configure.app,
    name="configure",
    help="Configure Snowflakecli",
)
app.add_typer(
    connection.app,
    name="connection",
    help="Test and Manage Snowflakecli Connections",
)
app.add_typer(
    sql.app,
    name="sql",
    help="Execute, lint, and debug Snowflake SQL Statements",
)
app.add_typer(account.app, name="account", help="Manage Snowflake Accounts")
app.add_typer(
    warehouse.app,
    name="warehouse",
    help="Manage and Optimize Snowflake Virtual Warehouses",
)
app.add_typer(database.app, name="database", help="Manage Snowflake Databases")
app.add_typer(io.app, name="io", help="Bulk import and bulk export data")

########################################################################
# AI stuff
########################################################################
# app.add_typer(
#     ask.app,
#     name="ask",
#     help="[!WIP!] Ask Snowflakecli LLM about your Snowflake resources",
# )
# app.add_typer(
#     recommend.app,
#     name="recommend",
#     help="[!WIP!] Recommend optimizations, resizing, and other operations for your Snowflake resources",
# )
# app.add_typer(
#     scrape.app,
#     name="scrape",
#     help="[!WIP!] Generate vector embeddings from Snowflake statistics, metadata, and schemata",
# )


# Top-level Commands


@app.callback()
def callback(ctx: typer.Context):
    config = get_config()
    # Ensure Configuration Directory
    logger.debug(f"initializing database cursor...")
    try:
        connection_params = (
            config.connections.default.params
        )  # TODO: make this configurable
        cursor = snowflake_cursor(connection_params)
        ctx.obj = SimpleNamespace(cursor=cursor)
    except Exception as e:
        logger.debug(e)
        ctx.obj = SimpleNamespace(cursor=None)


def main():
    app()


if __name__ == "__main__":
    main()
