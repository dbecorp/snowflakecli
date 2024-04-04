#!/usr/bin/env python3

import typer

app = typer.Typer()


@app.command()
def configure():
    """Configure Snowflakecli"""
    print("Configuring your Snowflake instance...")


@app.command()
def account():
    """Snowflake account management"""
    print("Managing snowflake account")


@app.command()
def optimize():
    """Analyze actual workloads on a particular warehouse and resize it according to actual needs."""
    print("Optimizing your Snowflake instance...")


if __name__ == "__main__":
    app()
