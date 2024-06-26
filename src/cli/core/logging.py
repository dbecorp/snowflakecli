import sys
from loguru import logger

from cli.core.constants import SFCLI_LOG_FILE_PATH


logger.remove()
logger.add(SFCLI_LOG_FILE_PATH, level="DEBUG")  # TODO -> Make this configurable
