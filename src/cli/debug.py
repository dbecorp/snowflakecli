import typer

app = typer.Typer(no_args_is_help=True)


@app.command()
def connection():
    """Debug the snowflakecli connection to your Snowflake account"""
    print("snowflakecli is currently using config from ~/.snowsql/config")
    return
