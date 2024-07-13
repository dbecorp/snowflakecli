from rich import print

from cli.core.security.types import HuntDefinition
from cli.core.logging import logger
from cli.core.snowflake.connection import SnowflakeCursor
from cli.core.snowflake.query import tabulate_to_stdout
from cli.core.security.runner import run_security_query
from cli.core.security.hunt_definitions.snowflake_unc5537_breach import (
    UNC5537_BREACH_DEFINITION,
)


# TODO -> Add a threat hunt definition parser, so this can be pointed at a json file


def run_threat_hunt(
    cursor: SnowflakeCursor,
    definition: HuntDefinition = UNC5537_BREACH_DEFINITION,
    query_name: str = None,
):
    """Run a threat hunt and output the results to stdout or file"""
    msg = f"Hunting with definition: {definition.name}"
    print("#" * 80)
    print(msg)
    print("#" * 80)
    logger.debug(msg)
    if query_name:
        query = definition.get_query(query_name)
        results = run_security_query(cursor, query)
        tabulate_to_stdout(results)
        print("\n\n")
        return
    for query in definition.hunting_queries:
        results = run_security_query(cursor, query)
        tabulate_to_stdout(results)
        print("\n\n")
