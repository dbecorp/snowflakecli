from typing import Union
from cli.core.security.types import SecurityQuery
from cli.core.snowflake.connection import SnowflakeCursor
from cli.core.snowflake.query import query_all
from cli.core.logging import logger


def run_security_query(
    cursor: SnowflakeCursor, query: SecurityQuery, verbose: bool = True
) -> list[dict]:
    msg = f"Running query: [NAME] {query.name} [DESCRIPTION] {query.description}"
    logger.debug(msg)
    if verbose:
        print(msg)
    return query_all(cursor, query.query)  # TODO -> SimpleNamespace this?
