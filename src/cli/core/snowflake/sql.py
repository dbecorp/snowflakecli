from dataclasses import dataclass


@dataclass
class Sql:
    """A class to encapsulate a sql string.

    Useful when programmatically constructing sql statements
    and wanting to keep clean type annotations.
    """

    statement: str

    def __post_init__(self):
        """TODO!!

        Validate the sql statement is valid. Sqlfluff it or something.
        """
        return

    def __str__(self) -> str:
        return self.statement


@dataclass
class Fqn:
    """
    A single, bi, or tri-level fully-qualified name to a Snowflake resource.
    """

    namespace: str

    @property
    def fqn_parts(self) -> list:
        """The parts of a single, bi, or tri-level fqn"""
        return self.namespace.split(".")

    @property
    def database(self) -> str:
        """The database."""
        return self.fqn_parts[0]

    @property
    def schema(self) -> str:
        """The schema."""
        return self.fqn_parts[1]

    @property
    def resource(self) -> str:
        """The resource name."""
        return self.fqn_parts[-1]

    @property
    def parent(self) -> Union[str, None]:
        """The parent resource name."""
        if len(self.fqn_parts) == 1:
            return self.resource
        if len(self.fqn_parts) == 2:
            return self.database
        else:
            return f"{self.database}.{self.schema}"

    def __str__(self) -> str:
        return self.namespace
