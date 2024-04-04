#!/usr/bin/env python3

import typer
import ask
import scrape
import account
import database
import warehouse

app = typer.Typer()


app.add_typer(
    ask.app,
    name="ask",
    help="Ask Snowflakecli LLM about your Snowflake resources",
)
app.add_typer(
    scrape.app,
    name="scrape",
    help="Scrape statistics, metadata, and schemata from Snowflake to seed vector embeddings",
)
app.add_typer(account.app, name="account", help="Manage Snowflake account")
app.add_typer(
    warehouse.app,
    name="warehouse",
    help="Manage and optimize Snowflake Virtual Warehouses",
)
app.add_typer(database.app, name="database", help="Manage Snowflake database")

if __name__ == "__main__":
    app()
