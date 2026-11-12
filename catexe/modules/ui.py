"""Composants d'interface terminal de CAT.EXE.

Les fonctions reçoivent un contexte explicite afin de ne plus dépendre des
variables globales de ``app.py``. Les façades de compatibilité restent dans
l'application pendant la migration progressive.
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Callable

from rich.cells import cell_len
from rich.console import Group
from rich.live import Live
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text


@dataclass
class UIContext:
    con: Any
    tr: Callable[[str], str]
    escape: Callable[[str], str]
    colors: dict[str, str]
    arrows: bool = True
    sel_style: str = "bold #050816 on #00e5ff"

    @property
    def G(self) -> str:
        return self.colors["G"]

    @property
    def P(self) -> str:
        return self.colors["P"]

    @property
    def Y(self) -> str:
        return self.colors["Y"]

    @property
    def M(self) -> str:
        return self.colors["M"]


def read_key() -> str:
    """Lit une touche et la convertit en nom stable multiplateforme."""
    if os.name == "nt":
        import msvcrt

        char = msvcrt.getwch()
        if char in ("\x00", "\xe0"):
            return {"H": "up", "P": "down", "K": "left", "M": "right", "G": "home", "O": "end", "I": "pgup", "Q": "pgdn", "S": "del"}.get(msvcrt.getwch(), "")
        return {"\r": "enter", "\n": "enter", "\x1b": "esc", "\x08": "backspace", "\t": "tab", "\x03": "ctrlc"}.get(char, char)

    import select as select_module
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        first = os.read(fd, 1)
        if first == b"\x1b":
            sequence = b""
            while len(sequence) < 6 and select_module.select([fd], [], [], 0.05)[0]:
                sequence += os.read(fd, 1)
                if len(sequence) >= 2 and (sequence[-1:].isalpha() or sequence[-1:] == b"~"):
                    break
            return {
                b"[A": "up", b"[B": "down", b"[C": "right", b"[D": "left",
                b"OA": "up", b"OB": "down", b"OC": "right", b"OD": "left",
                b"[H": "home", b"[F": "end", b"OH": "home", b"OF": "end",
                b"[1~": "home", b"[4~": "end", b"[5~": "pgup", b"[6~": "pgdn", b"[3~": "del",
            }.get(sequence, "esc" if not sequence else "")
        if first and first[0] >= 0xC0:
            first += os.read(fd, 1 if first[0] < 0xE0 else 2 if first[0] < 0xF0 else 3)
        char = first.decode("utf-8", "ignore")
        return {"\r": "enter", "\n": "enter", "\x7f": "backspace", "\x08": "backspace", "\t": "tab", "\x03": "ctrlc", "\x04": "esc"}.get(char, char)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _plain(ctx: UIContext, value: Any) -> str:
    import unicodedata

    return "".join(c for c in unicodedata.normalize("NFD", ctx.tr(str(value))) if unicodedata.category(c) != "Mn").lower()


def _pad(value: str, width: int) -> str:
    return value + " " * max(0, width - cell_len(value))


def select(ctx: UIContext, title: str, items: list[Any], default=None, back=True, side=None, height=None, echo=True, hint=None, side_min=96, paged=False, keys=()):
    """Menu à flèches. Retourne la valeur choisie ou ``None``."""
    items = [{"label": item} if isinstance(item, str) else dict(item) for item in items]
    pick = [i for i, item in enumerate(items) if not item.get("header")]
    if not pick:
        return None
    value_at = lambda index: items[index].get("value", index)
    current = next((i for i in pick if default is not None and (value_at(i) == default or (isinstance(default, int) and i == default and "value" not in items[i]))), pick[0])
    if not ctx.arrows:
        return _select_plain(ctx, title, items, pick, current, back, value_at)

    filt = ""
    groups = []
    if paged:
        for index, item in enumerate(items):
            if item.get("header"):
                groups.append((item["header"].strip("─ "), []))
            elif groups:
                groups[-1][1].append(index)
            else:
                groups.append(("", [index]))
        groups = [group for group in groups if group[1]]
        paged = len(groups) > 1
    page = next((k for k, group in enumerate(groups) if current in group[1]), 0) if paged else 0
    label_width = min(46, max(cell_len(ctx.tr(items[i]["label"])) for i in pick) + 2)

    def visible():
        if not filt:
            return list(groups[page][1]) if paged else list(range(len(items)))
        normalized = _plain(ctx, filt)
        hits = [i for i in pick if normalized in _plain(ctx, " ".join(str(items[i].get(key, "")) for key in ("label", "desc", "tags", "section")))]
        return sorted(hits, key=lambda i: (normalized not in _plain(ctx, items[i]["label"]), not _plain(ctx, items[i]["label"]).lstrip(" ←").split(" ", 1)[-1].startswith(normalized)))

    def render():
        visible_items = visible()
        use_side = side is not None and ctx.con.width >= side_min
        rows = max(4, (height or ctx.con.size.height) - 4 - (1 if filt else 0))
        selectable = [i for i in visible_items if not items[i].get("header")]
        position = visible_items.index(current) if current in visible_items else 0
        start = max(0, min(position - rows // 2, len(visible_items) - rows))
        listing = Table.grid(padding=(0, 1))
        listing.add_column(width=1)
        listing.add_column(no_wrap=True)
        if not use_side:
            listing.add_column(no_wrap=True, overflow="ellipsis")
        listing.add_row("", Text("▲ …", style=ctx.M) if start > 0 else "", *( [""] if not use_side else []))
        for index in visible_items[start:start + rows]:
            item = items[index]
            if item.get("header"):
                listing.add_row("", Text(ctx.tr(item["header"]), style=f"bold {ctx.P.split()[-1]}"), *( [""] if not use_side else []))
                continue
            selected = index == current
            label = Text(" " + _pad(ctx.tr(item["label"]), label_width - 2) + " ", style=ctx.sel_style if selected else item.get("style", "#e4e9ff"))
            row = [Text("❯" if selected else " ", style=ctx.G), label]
            if not use_side:
                row.append(Text(ctx.tr(item.get("desc", "")), style="#00e5ff" if selected else ctx.M))
            listing.add_row(*row)
        listing.add_row("", Text("▼ …", style=ctx.M) if start + rows < len(visible_items) else "", *( [""] if not use_side else []))
        head = Text.assemble((" " + ctx.tr(title) + " ", "bold #050816 on #b388ff"), "  ", (f"{selectable.index(current) + 1 if current in selectable else 0}/{len(selectable)}", ctx.M))
        parts = [head]
        if paged and not filt:
            tabs = Text(" ")
            for index, (name, _) in enumerate(groups):
                tabs.append(f" {name} ", style=f"bold #050816 on {ctx.G.split()[-1]}" if index == page else "#7480a8 on #14173a")
                tabs.append(" ")
            tabs.append(f"  {page + 1}/{len(groups)}", style=ctx.M)
            parts.append(tabs)
        if filt:
            parts.append(Text.assemble(("  🔎 ", ctx.Y), (filt, "bold #ffc861"), ("▏", "blink #ffc861"), (f"   {len(selectable)} " + ctx.tr("résultat(s)") if selectable else "   " + ctx.tr("aucun résultat"), ctx.M)))
        if use_side:
            panel = Table.grid(padding=(0, 2))
            panel.add_column(no_wrap=True)
            panel.add_column(ratio=1)
            panel.add_row(listing, side(items[current]) if current in visible_items else "")
            parts.append(panel)
        else:
            parts.append(listing)
        foot = (ctx.tr("n / → page suivante · p / ← précédente · ") if paged and not filt else "") + ctx.tr(hint or "↑↓ naviguer · Entrée valider · tape pour filtrer") + ("" if not back else " · " + ctx.tr("Échap retour"))
        parts.append(Text(" " + foot, style=ctx.M))
        return Group(*parts)

    result = None
    with Live(render(), console=ctx.con, auto_refresh=False, transient=True, redirect_stdout=False, redirect_stderr=False) as live:
        while True:
            key = read_key()
            if key == "ctrlc":
                raise KeyboardInterrupt
            visible_items = [i for i in visible() if not items[i].get("header")]
            if paged and not filt and (key in ("n", "N", "right", "tab", "p", "P", "left") or (key.isdigit() and 0 < int(key) <= len(groups))):
                page = int(key) - 1 if key.isdigit() else (page + (1 if key in ("n", "N", "right", "tab") else -1)) % len(groups)
                current = groups[page][1][0]
                live.update(render(), refresh=True)
                continue
            if key in ("up", "down", "pgup", "pgdn", "home", "end") and visible_items:
                position = visible_items.index(current) if current in visible_items else 0
                if key == "home": position = 0
                elif key == "end": position = len(visible_items) - 1
                elif key in ("up", "down"): position = (position + (1 if key == "down" else -1)) % len(visible_items)
                else: position = max(0, min(len(visible_items) - 1, position + (8 if key == "pgdn" else -8)))
                current = visible_items[position]
            elif key == "enter" or (key == "right" and not paged):
                if current in visible_items:
                    result = current
                    break
            elif key == "esc" or (key == "left" and not filt):
                if filt:
                    filt = ""
                    if paged:
                        page = next((k for k, group in enumerate(groups) if current in group[1]), page)
                elif back:
                    break
            elif key == "backspace":
                filt = filt[:-1]
            elif key in keys and not filt and current in visible_items:
                result = ("__key__", key, current)
                break
            elif len(key) == 1 and key.isprintable():
                filt += key
            visible_items = [i for i in visible() if not items[i].get("header")]
            if visible_items and current not in visible_items:
                current = visible_items[0]
            live.update(render(), refresh=True)
    if result is None:
        return None
    if isinstance(result, tuple):
        return {"key": result[1], "value": value_at(result[2])}
    if echo:
        ctx.con.print(f"[{ctx.M}]{ctx.escape(ctx.tr(title))} ›[/] [{ctx.G}]{ctx.escape(ctx.tr(items[result]['label']))}")
    return value_at(result)


def _select_plain(ctx, title, items, pick, current, back, value_at):
    ctx.con.print(f"[{ctx.P}]{ctx.escape(ctx.tr(title))}")
    numbers = {}
    for index, item in enumerate(items):
        if item.get("header"):
            ctx.con.print(f"  [{ctx.P}]{ctx.escape(ctx.tr(item['header']))}")
            continue
        numbers[str(len(numbers) + 1)] = index
        ctx.con.print(f"  [{ctx.G}]{len(numbers):>2}[/] {ctx.escape(ctx.tr(item['label']))}" + (f" [{ctx.M}]{ctx.escape(ctx.tr(item.get('desc', '')))}" if item.get("desc") else ""))
    default = next((key for key, index in numbers.items() if index == current), "1")
    key = Prompt.ask(f"[{ctx.G}]›[/]", default="" if back else default, show_default=not back).strip()
    if not key:
        return None if back else value_at(current)
    return value_at(numbers[key]) if key in numbers else (None if back else value_at(current))


def ask_yes(ctx: UIContext, question: str, default=False, lang_code="fr") -> bool:
    if not ctx.arrows:
        yes_no = "o/n" if lang_code == "fr" else "y/n"
        answer = Prompt.ask(f"[{ctx.P}]{question}[/] [{ctx.M}]({yes_no})[/]", default="o" if default else "n", show_default=False).strip().lower()
        return answer[:1] in ("o", "y", "s", "j", "д", "e", "t")
    value = default
    yes, no = ctx.tr("Oui"), ctx.tr("Non")

    def label():
        return Text.assemble(("? ", "bold #b388ff"), (ctx.tr(question), "bold #e4e9ff"), "  ", (f" {yes} ", ctx.sel_style if value else "#7480a8"), " ", (f" {no} ", "bold #ffffff on #b388ff" if not value else "#7480a8"), ("   ←→ " + ctx.tr("choisir") + " · Entrée", ctx.M))

    with Live(label(), console=ctx.con, auto_refresh=False, transient=True, redirect_stdout=False, redirect_stderr=False) as live:
        while True:
            key = read_key()
            if key == "ctrlc":
                raise KeyboardInterrupt
            if key in ("left", "right", "up", "down", "tab"):
                value = not value
            elif key in ("enter", "esc"):
                if key == "esc": value = False
                break
            elif key.lower() in ("o", "y", "j", "s", "д"):
                value = True
                break
            elif key.lower() == "n":
                value = False
                break
            live.update(label(), refresh=True)
    ctx.con.print(f"[{ctx.P}]?[/] {ctx.escape(ctx.tr(question))} [{ctx.G if value else 'bold #ff5c7a'}]{yes if value else no}")
    return value


def ask_num(ctx: UIContext, question: str, default="0") -> float:
    while True:
        value = Prompt.ask(question, default=str(default)).strip().replace(",", ".").replace(" ", "")
        value = re.sub(r"[^\d.\-]+$", "", value) or str(default)
        try:
            return float(value)
        except ValueError:
            ctx.con.print(f"[{ctx.Y}]Tape un nombre (ex : {default}).")


def ask_text(ctx: UIContext, question: str, default=None, password=False):
    return Prompt.ask(f"[{ctx.G}]›[/] [bold #e4e9ff]{question}[/]", default=default if default is not None else "", show_default=bool(default), password=password)
