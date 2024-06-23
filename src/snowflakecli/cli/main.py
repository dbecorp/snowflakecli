#!/usr/bin/env python3

import typer
import snowflakecli.cli.keypair as keypair
import snowflakecli.cli.account as account
import snowflakecli.cli.ask as ask
import snowflakecli.cli.configure as configure
import snowflakecli.cli.debug as debug
import snowflakecli.cli.recommend as recommend
import snowflakecli.cli.scrape as scrape
import snowflakecli.cli.database as database
import snowflakecli.cli.warehouse as warehouse
import snowflakecli.cli.security as security


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


def main():
    app()


if __name__ == "__main__":
    main()
