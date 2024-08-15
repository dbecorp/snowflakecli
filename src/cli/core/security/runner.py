from rich import print
from typing import Union
from cli.core.security.types import SecurityTask, SecurityPlaybook
from cli.core.snowflake.connection import SnowflakeCursor
from cli.core.snowflake.query import query_all, tabulate_to_stdout
from cli.core.logging import logger


def run_security_playbook(
    cursor: SnowflakeCursor,
    playbook: SecurityPlaybook,
    task_name: str = None,
    verbose: bool = True,
):
    if task_name:
        task = playbook.get_task(task_name)
        results = run_security_task(cursor, task, verbose)
        tabulate_to_stdout(results)
        return
    for task in playbook.tasks:
        results = run_security_task(cursor, task, verbose)
        tabulate_to_stdout(results)
        print("\n\n")


def run_security_task(
    cursor: SnowflakeCursor, task: SecurityTask, verbose: bool = True
) -> list[dict]:
    msg = f"[NAME] {task.name}\n[DESCRIPTION] {task.description}\n[CONTROL] {task.control}\n[CONTROL ID] {task.control_id}"
    result = None
    if verbose:
        print(msg)
    for query in task.queries:
        result = query_all(cursor, query)
    return result  # Only return the last query result
