from contextlib import contextmanager
from typing import Generator, Optional
from uuid import uuid4
from dataclasses import dataclass

from snowflake.conector import DictCursor, connect
from snowflake.connector.connection import SnowflakeConnection
from snowflake.connector.cursor import SnowflakeCursor


from src.core.util.time import iso_now
from src.core.constants import SFCLI


def get_private_key_contents(private_key_path: Path) -> str:
    pass


@dataclass
class ConnectionParams:
    """ "An object to represent snowflake connection parameters"""

    account: str
    user: str
    private_key_path: str
    warehouse: str = None
    role: str = None
    query_tag: str = None


def snowflake_connection(params: ConnectionParams) -> SnowflakeConnection:
    """Generate a Snowflake Connection"""
    connection_id = uuid4()
    connection = connect(
        account=params.account,
        user=params.user,
        private_key=params.private_key,
        warehouse=params.warehouse,
        role=params.role,
        client_telemetry_enabled=False,
        session_parameters={
            "connection_id": connection_id,
            "connection_start": iso_now(),
        },
        client_sesion_keep_alive=True,
    )
    connection._telemetry_enabled = False  # pylint: disable=W0212
    return connection


def snowflake_cursor(
    params: ConnectionParams, query_tag: str = SFCLI
) -> SnowflakeCursor:
    """Generate a Snowflake Cursor"""
    connection = connection(params)
    cursor = connection.cursor(DictCursor)
    if query_tag:
        cursor.execute(f"alter session set query_tag = '{query_tag}';")
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
    cursor.connection.close()
    return
