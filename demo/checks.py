"""What is behind the "Task done" and "Attack succeeded" verdicts, for the page's pop-up.

Both verdicts come from AgentDojo's own checkers: a Python function per task, run on the
account before and after the run and on the assistant's reply. The pop-up shows that
function's source, exactly as AgentDojo runs it, and the account changes it sees (the
same ``WorkspaceDeepDiff`` most workspace checkers compare against).
"""

from __future__ import annotations

import inspect
import textwrap
from typing import Any

from agentdojo.base_tasks import BaseInjectionTask, BaseUserTask
from pydantic import BaseModel

MAX_CHANGES = 40
MAX_VALUE_CHARS = 240


def check_details(task: BaseUserTask | BaseInjectionTask) -> dict[str, Any]:
    """The checker AgentDojo uses for this task, with its source."""
    if isinstance(task, BaseUserTask):
        kind, text, base = "utility", task.PROMPT, BaseUserTask
    else:
        kind, text, base = "security", task.GOAL, BaseInjectionTask
    # Like TaskSuite._check_task_result: a task's *_from_traces checker wins when it has one.
    name = f"{kind}_from_traces" if getattr(type(task), f"{kind}_from_traces") is not getattr(base, f"{kind}_from_traces") else kind
    method = getattr(type(task), name)
    try:
        source = textwrap.dedent(inspect.getsource(method))
    except (OSError, TypeError):
        source = ""
    return {"task_id": task.ID, "text": text, "function": f"{type(task).__name__}.{name}", "source": source}


def account_changes(pre: Any, post: Any) -> list[dict[str, Any]]:
    """Everything that differs between the account before and after the run."""
    from agentdojo.default_suites.v1.workspace.task_suite import WorkspaceDeepDiff
    from deepdiff import extract

    diff = WorkspaceDeepDiff(pre, post)
    changes: list[dict[str, Any]] = []
    for kind, entries in diff.items():
        if hasattr(entries, "items"):  # {path: {...}}: changed values, or added/removed list items
            for path, entry in entries.items():
                if isinstance(entry, dict) and "new_value" in entry:
                    changes.append({"kind": "changed", "path": _path(path),
                                    "before": _value(entry["old_value"]), "after": _value(entry["new_value"])})
                else:
                    changes.append({"kind": _kind(kind), "path": _path(path), "value": _value(entry)})
        else:  # a set of paths: dictionary items added or removed
            source = post if "added" in kind else pre
            for path in entries:
                try:
                    value = _value(extract(source, path))
                except Exception:  # noqa: BLE001 - a path deepdiff can't resolve back
                    value = ""
                changes.append({"kind": _kind(kind), "path": _path(path), "value": value})
    return changes[:MAX_CHANGES]


def _kind(deepdiff_kind: str) -> str:
    return "added" if "added" in deepdiff_kind else "removed" if "removed" in deepdiff_kind else "changed"


def _path(path: str) -> str:
    return path.removeprefix("root.")


def _value(value: Any) -> str:
    if isinstance(value, BaseModel):
        fields = {k: v for k, v in value.model_dump().items() if v not in (None, "", [], {})}
        text = f"{type(value).__name__}: " + ", ".join(f"{k}={v!r}" for k, v in fields.items())
    else:
        text = repr(value)
    return text if len(text) <= MAX_VALUE_CHARS else text[: MAX_VALUE_CHARS - 1] + "…"
