#!/usr/bin/env python3

import typer
import snowflakecli.cli.account as account
import snowflakecli.cli.ask as ask
import snowflakecli.cli.configure as configure
import snowflakecli.cli.debug as debug
import snowflakecli.cli.recommend as recommend
import snowflakecli.cli.scrape as scrape
import snowflakecli.cli.database as database
import snowflakecli.cli.warehouse as warehouse

app = typer.Typer()


app.add_typer(
    ask.app,
    name="ask",
    help="Ask Snowflakecli LLM about your Snowflake resources",
)
app.add_typer(
    configure.app,
    name="configure",
    help="Configure Snowflakecli",
)
app.add_typer(
    debug.app,
    name="debug",
    help="Debug Snowflakecli",
)
app.add_typer(
    recommend.app,
    name="recommend",
    help="Recommend optimizations, resizing, and other operations for your Snowflake resources",
)
app.add_typer(
    scrape.app,
    name="scrape",
    help="Generate vector embeddings from Snowflake statistics, metadata, and schemata",
)
app.add_typer(account.app, name="account", help="Manage Snowflake account")
app.add_typer(
    warehouse.app,
    name="warehouse",
    help="Manage and optimize Snowflake Virtual Warehouses",
)
app.add_typer(database.app, name="database", help="Manage Snowflake databases")


def main():
    app()


if __name__ == "__main__":
    main()
