from typing import Annotated, Optional

import typer

from cli.core.security.playbooks.cis_controls import CIS_BENCHMARK_PLAYBOOK
from cli.core.security.playbooks.unc5537_breach import UNC5537_BREACH_PLAYBOOK
from cli.core.security.runner import run_security_playbook

app = typer.Typer(no_args_is_help=True)


@app.command()
def audit(
    ctx: typer.Context,
    file: Annotated[
        Optional[str],
        typer.Option(
            "-f",
            help="The audit definition to use. If no file is passed snowflakecli will use the CIS controls.",
        ),
    ] = None,
    task_name: Annotated[
        Optional[str],
        typer.Option(
            "-n",
            help="The named audit query to execute. If no name is passed all audits from the supplied definition will be used.",
        ),
    ] = None,
):
    """Leverage control benchmarks to audit the security of your Snowflake account"""
    if file:
        run_security_playbook(
            ctx.obj.cursor, playbook=get_file_contents(Path(file)), task_name=task_name
        )
    else:
        run_security_playbook(
            ctx.obj.cursor, playbook=CIS_BENCHMARK_PLAYBOOK, task_name=task_name
        )
    return


@app.command()
def hunt(
    ctx: typer.Context,
    file: Annotated[
        Optional[str],
        typer.Option(
            "-f",
            help="The hunting definition to use. If no file is passed it will use the hunt definition from the UNC5537 Snowflake breaches",
        ),
    ] = None,
    task_name: Annotated[
        Optional[str],
        typer.Option(
            "-n",
            help="The named hunting query to execute. If no name is passed all hunting queries from the supplied definition will be used",
        ),
    ] = None,
):
    """Threat hunt via Snowflake activity logging"""
    if file:
        run_security_playbook(
            ctx.obj.cursor, get_file_contents(Path(file)), task_name=task_name
        )
    else:
        run_security_playbook(
            ctx.obj.cursor, playbook=UNC5537_BREACH_PLAYBOOK, task_name=task_name
        )
