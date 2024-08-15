from dataclasses import dataclass
from functools import cached_property

from cli.core.snowflake.sql import Sql


@dataclass
class SecurityReference:
    name: str
    url: str


@dataclass
class SecurityRemediation:
    description: str
    action: str


@dataclass
class SecurityTask:
    name: str
    description: str
    rationale: str = None
    control: str = None
    control_id: str = None
    severity: int = None
    queries: list[Sql] = None
    required_privileges: str = None
    results_expected: bool = False
    remediation: str = None
    references: list[SecurityReference] = None
    callback: callable = None


@dataclass
class SecurityPlaybook:
    name: str
    description: str
    tasks: list[SecurityTask]

    @cached_property
    def named_tasks(self) -> dict[str, SecurityTask]:
        return {task.name: task for task in self.tasks}

    def get_task(self, name: str) -> SecurityTask:
        return self.tasks[name]
