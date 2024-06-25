#!/usr/bin/env python3

import typer
from types import SimpleNamespace
import cli.keypair as keypair
import cli.account as account
import cli.ask as ask
import cli.configure as configure
import cli.connection as connection
import cli.debug as debug
import cli.recommend as recommend
import cli.scrape as scrape
import cli.database as database
import cli.warehouse as warehouse
import cli.security as security

from core.config.parser import get_config
from core.snowflake.connection import snowflake_cursor


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
app.add_typer(account.app, name="account", help="Manage Snowflake Accounts")
app.add_typer(
    warehouse.app,
    name="warehouse",
    help="Manage and Optimize Snowflake Virtual Warehouses",
)
app.add_typer(database.app, name="database", help="Manage Snowflake Databases")

########################################################################
# Future AI stuff
########################################################################
# app.add_typer(
#     ask.app,
#     name="ask",
#     help="[!WIP!] Ask Snowflakecli LLM about your Snowflake resources",
# )
# app.add_typer(
#     debug.app,
#     name="debug",
#     help="Debug Snowflakecli",
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


@app.callback()
def initialize_cursor(ctx: typer.Context):
    connection_params = (
        get_config().connections.default.params
    )  # TODO: make this configurable
    cursor = snowflake_cursor(connection_params)
    ctx.obj = SimpleNamespace(cursor=cursor)


def main():
    app()


if __name__ == "__main__":
    main()
