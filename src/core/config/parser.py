from configparser import ConfigParser
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from core.snowflake.connection import NamedConnection, ConnectionParams
from core.constants import SFCLI_CONFIG_FILE_PATH


@dataclass
class SfcliConfig:
    connections: dict[str, NamedConnection]
    variables: SimpleNamespace = None
    options: SimpleNamespace = None


def get_config(
    config_file_path: Path = SFCLI_CONFIG_FILE_PATH,
) -> SfcliConfig:
    parser = ConfigParser()
    parser.read(config_file_path)
    connections = {}
    for idx, section in enumerate(parser.sections()):
        if "connections" in section:
            name = section.replace("connections.", "")
            params = ConnectionParams(
                accountname=parser.get(section, "accountname"),
                username=parser.get(section, "username"),
                private_key_path=parser.get(section, "private_key_path"),
                # warehouse=parser.get(section, "warehousename"),
                # role=parser.get(section, "rolename"),
                # query_tag=parser.get(section, "query_tag"),
            )
            named_connection = NamedConnection(name=name, params=params)
            connections[name] = named_connection
    return SfcliConfig(connections=SimpleNamespace(**connections))
