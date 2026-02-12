"""JoyfulJay Textual TUI.

Design goals:
- Cover *all* CLI subcommands via Click introspection (no drift).
- Provide a first-class schema/feature browser (search + table).
- Run commands in a subprocess so behavior matches the CLI exactly.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import signal
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import click

try:
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical, VerticalScroll
    from textual.reactive import reactive
    from textual.widgets import (
        Button,
        Checkbox,
        DataTable,
        Footer,
        Header,
        Input,
        Label,
        OptionList,
        Select,
        Static,
        TabbedContent,
        TabPane,
        TextArea,
        RichLog,
    )
    from textual.widgets.option_list import Option
except Exception as exc:  # pragma: no cover - guarded by CLI before import
    raise RuntimeError(
        "Textual is required for the JoyfulJay TUI. Install with: joyfuljay[tui]"
    ) from exc


@dataclass(frozen=True)
class CommandSpec:
    """A leaf Click command addressable by a path like ('profiles', 'show')."""

    path: tuple[str, ...]
    command: click.Command

    @property
    def title(self) -> str:
        return " ".join(self.path)


def _walk_click_commands(root: click.Command) -> list[CommandSpec]:
    """Return leaf commands (non-groups), including nested commands."""
    specs: list[CommandSpec] = []

    def walk(cmd: click.Command, path: list[str]) -> None:
        if isinstance(cmd, click.Group):
            for name, sub in cmd.commands.items():
                walk(sub, [*path, name])
            return
        specs.append(CommandSpec(tuple(path), cmd))

    walk(root, [])
    return sorted(specs, key=lambda s: s.title)


def _is_choice_type(param: click.Parameter) -> bool:
    return isinstance(getattr(param, "type", None), click.Choice)


def _choice_values(param: click.Parameter) -> list[str]:
    tp = getattr(param, "type", None)
    if isinstance(tp, click.Choice):
        return list(tp.choices)
    return []


def _is_path_type(param: click.Parameter) -> bool:
    return isinstance(getattr(param, "type", None), click.Path)


def _param_help(param: click.Parameter) -> str:
    if isinstance(param, click.Option):
        return param.help or ""
    return ""


def _format_shell(cmd: list[str]) -> str:
    return " ".join(shlex.quote(c) for c in cmd)


def _preferred_opt(opts: Iterable[str]) -> str:
    """Prefer long-form flags (e.g., --output) over short (-o) for readability."""
    best: str | None = None
    for o in opts:
        if best is None:
            best = o
        if o.startswith("--"):
            return o
    if best is None:
        raise ValueError("No option strings provided")
    return best


class JoyfulJayTUI(App):
    """Interactive TUI wrapper around the JoyfulJay CLI."""

    CSS = """
    Screen { layout: vertical; }

    #main_row { height: 1fr; }

    #sidebar {
      width: 44;
      border: solid $accent;
      padding: 1 1;
    }

    #cmd_preview {
      height: 1fr;
      border: solid $primary;
      padding: 0 1;
    }

    #log {
      height: 12;
      border: solid $secondary;
      padding: 0 1;
    }

    #commands_left {
      width: 52;
      border: solid $accent;
      padding: 1 1;
    }

    #commands_form {
      border: solid $accent;
      padding: 1 1;
      height: 1fr;
    }

    .muted { color: $text-muted; }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("ctrl+c", "stop", "Stop Command"),
        ("ctrl+r", "run", "Run Command"),
        ("ctrl+l", "clear_log", "Clear Log"),
    ]

    # Selected command index in the filtered list
    selected_index: int = reactive(0)
    # Filter string for command list
    command_filter: str = reactive("")
    # Whether a subprocess is currently running
    running: bool = reactive(False)

    def __init__(self, *, base_cmd: list[str], cwd: Path) -> None:
        super().__init__()
        self._base_cmd = base_cmd
        self._cwd = cwd
        self._all_cmds: list[CommandSpec] = []
        self._filtered_cmds: list[CommandSpec] = []
        self._param_widgets: dict[str, Any] = {}
        self._proc: asyncio.subprocess.Process | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main_row"):
            with TabbedContent(id="main_tabs"):
                with TabPane("Commands", id="tab_commands"):
                    with Horizontal():
                        with Vertical(id="commands_left"):
                            yield Label("Command Search")
                            yield Input(
                                placeholder="Type to filter (e.g., extract, profiles show)",
                                id="cmd_search",
                            )
                            yield Label("Commands", classes="muted")
                            yield OptionList(id="cmd_list")
                        with VerticalScroll(id="commands_form"):
                            yield Static("Select a command on the left.", id="form_help")
                with TabPane("Schema", id="tab_schema"):
                    yield Label("Feature Schema Browser")
                    yield Input(placeholder="Search feature name/description...", id="schema_search")
                    table = DataTable(id="schema_table")
                    table.add_columns("group", "name", "type", "unit", "description")
                    yield table
                with TabPane("About", id="tab_about"):
                    yield Static(self._about_text(), id="about_text")

            with Vertical(id="sidebar"):
                yield Label("Command Preview", classes="muted")
                yield TextArea("", id="cmd_preview", read_only=True)
                with Horizontal():
                    yield Button("Run (Ctrl+R)", id="run_btn", variant="success")
                    yield Button("Stop (Ctrl+C)", id="stop_btn", variant="error", disabled=True)
                yield Static("", id="status_line", classes="muted")

        yield RichLog(id="log", highlight=False, markup=False, max_lines=5000, wrap=True)
        yield Footer()

    def on_mount(self) -> None:
        from ..cli.main import cli as root_cli

        self._all_cmds = _walk_click_commands(root_cli)
        self._apply_command_filter()
        self._load_schema_table()
        self._select_command(0)

    def _about_text(self) -> str:
        return (
            f"JoyfulJay TUI\n\n"
            f"Base command:\n  {_format_shell(self._base_cmd)}\n"
            f"Working directory:\n  {self._cwd}\n\n"
            f"Tips:\n"
            f"- Use the Commands tab to run any CLI subcommand.\n"
            f"- Use Schema tab to search/browse the 401-feature schema.\n"
            f"- Ctrl+R runs the selected command; Ctrl+C stops it.\n"
        )

    def _set_status(self, text: str) -> None:
        self.query_one("#status_line", Static).update(text)

    def _log_append(self, line: str) -> None:
        self.query_one("#log", RichLog).write(line)

    # ----------------------------
    # Commands: list + filtering
    # ----------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "cmd_search":
            self.command_filter = event.value
            self._apply_command_filter()
            self._select_command(0)
            return
        if event.input.id == "schema_search":
            self._load_schema_table(filter_text=event.value)
            return
        # Any other input change affects command preview
        self._update_preview()

    def on_select_changed(self, event: Select.Changed) -> None:
        # Choice selects and boolean selects (if any) should update preview.
        self._update_preview()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        self._update_preview()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id != "cmd_list":
            return
        self._select_command(event.option_index)

    def _apply_command_filter(self) -> None:
        q = self.command_filter.strip().lower()
        if not q:
            self._filtered_cmds = list(self._all_cmds)
        else:
            self._filtered_cmds = [c for c in self._all_cmds if q in c.title.lower()]

        opts = [Option(c.title) for c in self._filtered_cmds]
        lst = self.query_one("#cmd_list", OptionList)
        lst.clear_options()
        lst.add_options(opts)

    def _select_command(self, index: int) -> None:
        if not self._filtered_cmds:
            self._clear_form()
            self._set_status("No commands match the current filter.")
            return

        index = max(0, min(index, len(self._filtered_cmds) - 1))
        self.selected_index = index

        lst = self.query_one("#cmd_list", OptionList)
        try:
            lst.highlighted = index
        except Exception:
            pass

        spec = self._filtered_cmds[index]
        self._build_form_for_command(spec)
        self._update_preview()

    # ----------------------------
    # Commands: dynamic forms
    # ----------------------------

    def _clear_form(self) -> None:
        form = self.query_one("#commands_form", VerticalScroll)
        form.remove_children()
        self._param_widgets.clear()

    def _build_form_for_command(self, spec: CommandSpec) -> None:
        self._clear_form()
        form = self.query_one("#commands_form", VerticalScroll)

        header = Static(f"[b]{spec.title}[/b]\n{spec.command.help or ''}".strip())
        form.mount(header)

        if not spec.command.params:
            form.mount(Static("This command has no parameters.", classes="muted"))
            return

        for param in spec.command.params:
            # Skip hidden params
            if getattr(param, "hidden", False):
                continue

            form.mount(Static(""))
            label = self._param_label(spec, param)
            help_text = _param_help(param)
            form.mount(Label(label))
            if help_text:
                form.mount(Static(help_text, classes="muted"))

            widget_id = self._widget_id_for_param(param)

            if isinstance(param, click.Option) and (param.is_flag or isinstance(param.type, click.BOOL)):
                default = bool(param.default) if param.default is not None else False
                cb = Checkbox("enabled", value=default, id=widget_id)
                form.mount(cb)
                self._param_widgets[widget_id] = cb
                continue

            if _is_choice_type(param):
                choices = _choice_values(param)
                opts: list[tuple[str, str]] = []
                if getattr(param, "default", None) is None and isinstance(param, click.Option):
                    opts.append(("", "<unset>"))
                opts.extend([(c, c) for c in choices])
                default_val = getattr(param, "default", None)
                value = str(default_val) if default_val is not None else ""
                sel = Select(opts, value=value if value in [o[0] for o in opts] else opts[0][0], id=widget_id)
                form.mount(sel)
                self._param_widgets[widget_id] = sel
                continue

            # For multiple=True, accept comma-separated values.
            placeholder = ""
            if isinstance(param, click.Argument):
                placeholder = "<required>"
            elif isinstance(param, click.Option):
                if _is_path_type(param):
                    placeholder = "path"
                else:
                    placeholder = "" if param.default in (None, "") else str(param.default)

            inp = Input(placeholder=placeholder, id=widget_id)
            form.mount(inp)
            self._param_widgets[widget_id] = inp

    def _param_label(self, spec: CommandSpec, param: click.Parameter) -> str:
        if isinstance(param, click.Argument):
            return f"ARG: {param.name}"
        if isinstance(param, click.Option):
            opts = "/".join(param.opts + list(param.secondary_opts))
            req = " (required)" if getattr(param, "required", False) else ""
            multi = " (multi)" if getattr(param, "multiple", False) else ""
            return f"OPT: {opts}{req}{multi}"
        return param.name

    def _widget_id_for_param(self, param: click.Parameter) -> str:
        # Click uses param.name unique per command.
        return f"param__{param.name}"

    def _get_selected_spec(self) -> CommandSpec | None:
        if not self._filtered_cmds:
            return None
        if not (0 <= self.selected_index < len(self._filtered_cmds)):
            return None
        return self._filtered_cmds[self.selected_index]

    def _update_preview(self) -> None:
        spec = self._get_selected_spec()
        preview = self.query_one("#cmd_preview", TextArea)
        if spec is None:
            preview.text = ""
            return
        cmd = self._build_command_argv(spec)
        preview.text = _format_shell(cmd)

    def _build_command_argv(self, spec: CommandSpec) -> list[str]:
        argv: list[str] = [*self._base_cmd, *spec.path]

        for param in spec.command.params:
            wid = self._widget_id_for_param(param)
            w = self._param_widgets.get(wid)
            if w is None:
                continue

            if isinstance(param, click.Argument):
                val = getattr(w, "value", "").strip()
                if val:
                    argv.append(val)
                continue

            if not isinstance(param, click.Option):
                continue

            # Select widget for booleans
            if isinstance(w, Select) and (param.is_flag or isinstance(param.type, click.BOOL)):
                # (Legacy) boolean represented as select.
                current = (w.value or "") == "true"
                default = bool(param.default) if param.default is not None else False
                if current == default:
                    continue
                # Prefer explicit long opt if available
                if current:
                    argv.append(_preferred_opt(param.opts))
                else:
                    # For paired flags (--foo/--no-foo), click stores secondary opts.
                    if param.secondary_opts:
                        argv.append(_preferred_opt(param.secondary_opts))
                    else:
                        # Single flag with default True is rare; fall back to explicit false via --foo=false
                        argv.append(_preferred_opt(param.opts))
                        argv.append("false")
                continue

            if isinstance(w, Checkbox) and (param.is_flag or isinstance(param.type, click.BOOL)):
                current = bool(w.value)
                default = bool(param.default) if param.default is not None else False
                if current == default:
                    continue
                if current:
                    argv.append(_preferred_opt(param.opts))
                else:
                    if param.secondary_opts:
                        argv.append(_preferred_opt(param.secondary_opts))
                    else:
                        # Best-effort: for rare single-flag defaults, fall back to explicit false.
                        argv.append(_preferred_opt(param.opts))
                        argv.append("false")
                continue

            raw = getattr(w, "value", "")
            if isinstance(w, Select):
                raw = w.value or ""
            val = str(raw).strip()

            if not val:
                continue

            # Multi-value options: comma-separated -> repeated --opt VALUE
            if param.multiple:
                parts = [p.strip() for p in val.split(",") if p.strip()]
                for p in parts:
                    argv.append(_preferred_opt(param.opts))
                    argv.append(p)
                continue

            # Regular option: --opt VALUE
            argv.append(_preferred_opt(param.opts))
            argv.append(val)

        return argv

    # ----------------------------
    # Schema browser
    # ----------------------------

    def _load_schema_table(self, filter_text: str = "") -> None:
        from ..output.schema import export_schema_json

        table = self.query_one("#schema_table", DataTable)
        table.clear()

        data = export_schema_json()
        import json as json_module

        payload = json_module.loads(data)
        rows: list[Mapping[str, Any]] = payload["features"]

        q = filter_text.strip().lower()
        if q:
            def match(r: Mapping[str, Any]) -> bool:
                return q in str(r.get("name", "")).lower() or q in str(r.get("description", "")).lower()

            rows = [r for r in rows if match(r)]

        for r in rows:
            table.add_row(
                str(r.get("group", "")),
                str(r.get("name", "")),
                str(r.get("type", "")),
                str(r.get("unit", "") or ""),
                str(r.get("description", "")),
            )

    # ----------------------------
    # Running commands
    # ----------------------------

    def action_clear_log(self) -> None:
        self.query_one("#log", RichLog).clear()

    def action_run(self) -> None:
        if self.running:
            return
        spec = self._get_selected_spec()
        if spec is None:
            return
        argv = self._build_command_argv(spec)
        asyncio.create_task(self._run_subprocess(argv))

    def action_stop(self) -> None:
        if not self.running or self._proc is None:
            return
        try:
            self._proc.send_signal(signal.SIGINT)
        except ProcessLookupError:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run_btn":
            self.action_run()
        elif event.button.id == "stop_btn":
            self.action_stop()

    async def _run_subprocess(self, argv: list[str]) -> None:
        self.running = True
        self.query_one("#run_btn", Button).disabled = True
        self.query_one("#stop_btn", Button).disabled = False
        self._set_status("Running...")

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        self._log_append(f"$ {_format_shell(argv)}")
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd=str(self._cwd),
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            self._log_append(f"ERROR: {exc}")
            self._set_status("Failed to start process.")
            self.running = False
            self.query_one("#run_btn", Button).disabled = False
            self.query_one("#stop_btn", Button).disabled = True
            return

        self._proc = proc

        async def pump(stream: asyncio.StreamReader | None, prefix: str) -> None:
            if stream is None:
                return
            while True:
                line = await stream.readline()
                if not line:
                    return
                try:
                    text = line.decode(errors="replace").rstrip("\n")
                except Exception:
                    text = repr(line)
                self._log_append(f"{prefix}{text}")

        t_out = asyncio.create_task(pump(proc.stdout, ""))
        t_err = asyncio.create_task(pump(proc.stderr, ""))

        code = await proc.wait()
        await asyncio.gather(t_out, t_err, return_exceptions=True)

        self._proc = None
        self.running = False
        self.query_one("#run_btn", Button).disabled = False
        self.query_one("#stop_btn", Button).disabled = True

        if code == 0:
            self._set_status("Done (exit 0).")
        else:
            self._set_status(f"Failed (exit {code}).")
        self._log_append(f"[exit {code}]")


def run_tui(*, verbose: bool = False, cwd: str | Path = ".") -> None:
    """Launch the JoyfulJay TUI."""
    base_cmd = [sys.executable, "-m", "joyfuljay.cli.main"]
    if verbose:
        base_cmd.append("-v")
    JoyfulJayTUI(base_cmd=base_cmd, cwd=Path(cwd).resolve()).run()
