from contextlib import contextmanager
from typing import Generator, Optional
from uuid import uuid4
from dataclasses import dataclass

from snowflake.connector import DictCursor, connect
from snowflake.connector.connection import SnowflakeConnection
from snowflake.connector.cursor import SnowflakeCursor


from cli.core.util.time import iso_now
from cli.core.constants import SFCLI, SFCLI_DEFAULT_PRIV_KEY_PATH
from cli.core.logging import logger
from cli.core.util.key import get_private_key_contents


@dataclass
class ConnectionParams:
    """An object to represent Snowflake connection parameters"""

    accountname: str
    username: str
    private_key_path: str = SFCLI_DEFAULT_PRIV_KEY_PATH
    warehouse: str = None
    role: str = None
    query_tag: str = SFCLI


@dataclass
class NamedConnection:
    """An object to represent a named Snowflake connection"""

    name: str
    params: ConnectionParams


def snowflake_connection(params: ConnectionParams) -> SnowflakeConnection:
    """Generate a Snowflake Connection"""
    private_key = get_private_key_contents()
    connection_id = str(uuid4())
    query_tag = params.query_tag if params.query_tag else SFCLI
    logger.debug(
        f"opening connection with id: {connection_id}, query_tag: {query_tag}, params: {params}"
    )
    connection = connect(
        account=params.accountname,
        user=params.username,
        private_key=private_key,
        warehouse=params.warehouse,
        role=params.role,
        client_telemetry_enabled=False,
        session_parameters={
            "connection_id": connection_id,
            "connection_start": iso_now(),
            "query_tag": query_tag,
        },
        client_sesion_keep_alive=True,
        login_timeout=5,
    )
    connection._telemetry_enabled = False  # pylint: disable=W0212
    connection._application = SFCLI  # pylint: disable=W0212
    connection._internal_application_name = SFCLI  # pylint: disable=W0212
    connection._internal_application_version = "beta"  # pylint: disable=W0212
    connection.service_name = SFCLI  # pylint: disable=W0212
    return connection


def snowflake_cursor(params: ConnectionParams) -> SnowflakeCursor:
    """Generate a Snowflake Cursor"""
    connection = snowflake_connection(params)
    cursor = connection.cursor(DictCursor)
    return cursor


@contextmanager
def cursor(params: ConnectionParams) -> Generator[SnowflakeCursor, None, None]:
    """A helper context manager used to generate a cursor with some niceties"""
    cursor = snowflake_cursor(params)
    try:
        yield cursor
        cursor.connection.commit()
    except Exception:
        cursor.connection.rollback()
        raise
    cursor.close()
    return
