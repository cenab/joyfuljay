"""Progress bar utilities for JoyfulJay."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

# Try to import rich for fancy progress bars
try:
    from rich.console import Console
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
    )

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class SimpleProgress:
    """Simple fallback progress indicator without rich."""

    def __init__(self, description: str = "", total: int | None = None) -> None:
        self.description = description
        self.total = total
        self.current = 0
        self._last_percent = -1

    def update(self, advance: int = 1) -> None:
        """Update progress."""
        self.current += advance
        if self.total:
            percent = int(100 * self.current / self.total)
            if percent != self._last_percent and percent % 10 == 0:
                import sys

                print(f"\r{self.description}: {percent}%", end="", file=sys.stderr)
                self._last_percent = percent

    def finish(self) -> None:
        """Finish progress."""
        import sys

        if self.total:
            print(f"\r{self.description}: 100%", file=sys.stderr)
        else:
            print(f"\r{self.description}: Done ({self.current})", file=sys.stderr)


@contextmanager
def create_progress(
    description: str = "Processing",
    total: int | None = None,
    use_rich: bool = True,
) -> Iterator[Any]:
    """Create a progress bar context manager.

    Args:
        description: Text description for the progress bar.
        total: Total number of items (None for indeterminate).
        use_rich: Whether to use rich progress bars if available.

    Yields:
        Progress object with update() and optionally task_id.
    """
    if use_rich and RICH_AVAILABLE:
        console = Console(stderr=True)
        if total is not None:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=40),
                TaskProgressColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console,
                transient=False,
            )
        else:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                TextColumn("[cyan]{task.completed}"),
                TimeElapsedColumn(),
                console=console,
                transient=False,
            )

        with progress:
            task_id = progress.add_task(description, total=total)

            class RichProgressWrapper:
                def update(self, advance: int = 1) -> None:
                    progress.update(task_id, advance=advance)

                def set_description(self, text: str) -> None:
                    progress.update(task_id, description=text)

            yield RichProgressWrapper()
    else:
        simple_progress = SimpleProgress(description, total)
        try:
            yield simple_progress
        finally:
            simple_progress.finish()


@contextmanager
def create_multi_progress(use_rich: bool = True) -> Iterator[Any]:
    """Create a multi-task progress context manager.

    Args:
        use_rich: Whether to use rich progress bars if available.

    Yields:
        Progress manager with add_task() and update() methods.
    """
    if use_rich and RICH_AVAILABLE:
        console = Console(stderr=True)
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=30),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )

        class RichMultiProgress:
            def __init__(self, prog: Progress) -> None:
                self._progress = prog
                self._tasks: dict[str, Any] = {}

            def add_task(
                self, description: str, total: int | None = None
            ) -> str:
                task_id = self._progress.add_task(description, total=total)
                self._tasks[description] = task_id
                return description

            def update(
                self, task_name: str, advance: int = 1, completed: int | None = None
            ) -> None:
                if task_name in self._tasks:
                    if completed is not None:
                        self._progress.update(self._tasks[task_name], completed=completed)
                    else:
                        self._progress.update(self._tasks[task_name], advance=advance)

            def set_description(self, task_name: str, text: str) -> None:
                if task_name in self._tasks:
                    self._progress.update(self._tasks[task_name], description=text)

        with progress:
            yield RichMultiProgress(progress)
    else:

        class SimpleMultiProgress:
            def __init__(self) -> None:
                self._tasks: dict[str, SimpleProgress] = {}

            def add_task(
                self, description: str, total: int | None = None
            ) -> str:
                self._tasks[description] = SimpleProgress(description, total)
                return description

            def update(
                self, task_name: str, advance: int = 1, completed: int | None = None
            ) -> None:
                if task_name in self._tasks:
                    if completed is not None:
                        self._tasks[task_name].current = completed
                    else:
                        self._tasks[task_name].update(advance)

            def set_description(self, task_name: str, text: str) -> None:
                if task_name in self._tasks:
                    self._tasks[task_name].description = text

        mp = SimpleMultiProgress()
        try:
            yield mp
        finally:
            for task in mp._tasks.values():
                task.finish()


def is_rich_available() -> bool:
    """Check if rich is available for progress bars."""
    return RICH_AVAILABLE
