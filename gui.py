#!/usr/bin/env python3
"""
gui.py - GUI symbol browser for PE/PDB files.

Usage:
    python gui.py                   # opens file picker
    python gui.py ntoskrnl.exe
    python gui.py ntoskrnl.exe --no-download
    python gui.py ntoskrnl.exe -o C:\\symbols
"""

import argparse
import os
import queue
import sys
import threading
import tkinter as tk
import tkinter.filedialog as filedialog
import tkinter.font as tkfont
import tkinter.ttk as ttk
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
from pdb_tool import PEParser, PDBReader, SymbolDownloader, Symbol, default_pdb_dir
from symbols import SymbolMatcher, load_symbols

# Colour palette (VS Code Dark+ inspired)
BG        = "#1e1e1e"
BG2       = "#252526"
BG3       = "#2d2d30"
FG        = "#d4d4d4"
FG_DIM    = "#6a6a6a"
FG_GHOST  = "#555555"
ACCENT    = "#569cd6"
ACCENT2   = "#4ec9b0"
GREEN     = "#4ec9b0"
RED       = "#f44747"
YELLOW    = "#dcdcaa"
SEL_BG    = "#094771"
SEL_FG    = "#ffffff"
BORDER    = "#3c3c3c"
ROW_ODD   = "#252526"
ROW_EVEN  = "#1e1e1e"

SB_TROUGH  = "#1a1a1a"  # track background
SB_THUMB   = "#424242"  # resting thumb
SB_THUMB_H = "#686868"  # hovered thumb
SB_THUMB_A = "#569cd6"  # active/dragging thumb
SB_WIDTH   = 10


class FlatScrollbar(tk.Canvas):
    """
    Minimal canvas-based scrollbar with no arrows.
    Drop-in replacement for ttk.Scrollbar:
        sb = FlatScrollbar(parent, orient="vertical", command=widget.yview)
        widget.config(yscrollcommand=sb.set)
    """

    MIN_THUMB = 24

    def __init__(self, master, orient: str = "vertical", command=None, **kw):
        self._orient         = orient
        self._command        = command
        self._lo             = 0.0
        self._hi             = 1.0
        self._drag_start_px  = None
        self._drag_start_lo  = None
        self._hovering       = False

        w = kw.pop("width",  SB_WIDTH if orient == "vertical"   else None)
        h = kw.pop("height", SB_WIDTH if orient == "horizontal" else None)

        super().__init__(master, width=w, height=h, bg=SB_TROUGH,
                         highlightthickness=0, bd=0, **kw)

        self._thumb_id = self.create_rectangle(0, 0, 0, 0, fill=SB_THUMB,
                                               outline="", tags="thumb")

        self.bind("<Configure>",       lambda _e: self._redraw())
        self.bind("<MouseWheel>",      self._on_wheel)
        self.bind("<ButtonPress-1>",   self._on_press)
        self.bind("<B1-Motion>",       self._on_drag)
        self.bind("<ButtonRelease-1>", self._on_release)
        self.tag_bind("thumb", "<Enter>", self._on_enter)
        self.tag_bind("thumb", "<Leave>", self._on_leave)

    def set(self, lo: float, hi: float) -> None:
        self._lo = float(lo)
        self._hi = float(hi)
        self._redraw()

    def _track_len(self) -> int:
        return (self.winfo_height() if self._orient == "vertical"
                else self.winfo_width()) or 1

    def _thumb_coords(self) -> tuple[int, int, int, int]:
        tl   = self._track_len()
        pad  = 2
        span = max(self.MIN_THUMB, int((self._hi - self._lo) * tl))
        pos  = min(int(self._lo * tl), tl - span)  # clamp so thumb never overflows
        if self._orient == "vertical":
            w = self.winfo_width() or SB_WIDTH
            return (pad, pos + pad, w - pad, pos + span - pad)
        else:
            h = self.winfo_height() or SB_WIDTH
            return (pos + pad, pad, pos + span - pad, h - pad)

    def _redraw(self) -> None:
        self.coords(self._thumb_id, *self._thumb_coords())

    def _on_press(self, event: tk.Event) -> None:
        x0, y0, x1, y1 = self._thumb_coords()
        px = event.y if self._orient == "vertical" else event.x
        if (self._orient == "vertical"   and y0 <= event.y <= y1) or \
           (self._orient == "horizontal" and x0 <= event.x <= x1):
            self._drag_start_px = px
            self._drag_start_lo = self._lo
            self.itemconfig(self._thumb_id, fill=SB_THUMB_A)
        else:
            frac = px / self._track_len()
            if self._command:
                self._command("moveto", frac - (self._hi - self._lo) / 2)

    def _on_drag(self, event: tk.Event) -> None:
        if self._drag_start_px is None:
            return
        px    = event.y if self._orient == "vertical" else event.x
        delta = (px - self._drag_start_px) / self._track_len()
        if self._command:
            self._command("moveto", self._drag_start_lo + delta)

    def _on_release(self, _event: tk.Event) -> None:
        self._drag_start_px = None
        self._drag_start_lo = None
        self.itemconfig(self._thumb_id, fill=SB_THUMB_H if self._hovering else SB_THUMB)

    def _on_wheel(self, event: tk.Event) -> None:
        if self._command:
            self._command("scroll", -1 if event.delta > 0 else 1, "units")

    def _on_enter(self, _event: tk.Event) -> None:
        self._hovering = True
        if self._drag_start_px is None:
            self.itemconfig(self._thumb_id, fill=SB_THUMB_H)

    def _on_leave(self, _event: tk.Event) -> None:
        self._hovering = False
        if self._drag_start_px is None:
            self.itemconfig(self._thumb_id, fill=SB_THUMB)


class GhostEntry(tk.Frame):
    """
    Single-line entry with inline grey ghost-text completion.
    Tab or Right-arrow at end-of-input accepts the ghost.

    Public API:
        get_typed()          → str
        set_ghost(suffix)
        accept_ghost()
        focus() / clear()
        on_change(text)      callback on every keystroke
        on_submit(text)      callback on Enter
    """

    def __init__(self, master, font, on_change=None, on_submit=None, **kw):
        super().__init__(master, bg=BG2, **kw)
        self.on_change = on_change
        self.on_submit = on_submit
        self._ghost    = ""

        # Text widget lets us mix normal + grey tagged text in one line
        self._text = tk.Text(
            self, font=font, bg=BG2, fg=FG,
            insertbackground=FG, selectbackground=SEL_BG, selectforeground=SEL_FG,
            relief="flat", bd=0, height=1, wrap="none", undo=False, cursor="xterm",
        )
        self._text.pack(fill="both", expand=True, padx=(6, 6), pady=(4, 4))
        self._text.tag_configure("ghost", foreground=FG_GHOST)
        self._text.bind("<KeyRelease>",     self._on_key_release)
        self._text.bind("<KeyPress>",       self._on_key_press)
        self._text.bind("<Return>",         self._on_enter)
        self._text.bind("<Tab>",            self._on_tab)
        self._text.bind("<Right>",          self._on_right)
        self._text.bind("<Control-Return>", lambda e: "break")  # prevent newlines
        self._updating = False

    def get_typed(self) -> str:
        try:
            return self._text.get("1.0", "ghost_start")
        except tk.TclError:
            return self._text.get("1.0", "end-1c")

    def set_ghost(self, ghost_suffix: str) -> None:
        self._ghost = ghost_suffix
        self._refresh_ghost()

    def accept_ghost(self) -> None:
        if not self._ghost:
            return
        full = self.get_typed() + self._ghost
        self._ghost = ""
        self._set_typed(full)
        self._text.mark_set("insert", "end-1c")
        if self.on_change:
            self.on_change(full)

    def focus(self) -> None:
        self._text.focus_set()

    def clear(self) -> None:
        self._set_typed("")
        self._ghost = ""

    def _set_typed(self, text: str) -> None:
        self._updating = True
        self._text.delete("1.0", "end")
        self._text.insert("1.0", text)
        self._ghost = ""
        self._updating = False

    def _refresh_ghost(self) -> None:
        self._updating = True
        self._text.tag_remove("ghost", "1.0", "end")
        typed = self.get_typed()
        self._text.delete("1.0", "end")
        self._text.insert("1.0", typed)
        if self._ghost:
            self._text.insert("end", self._ghost, "ghost")
            self._text.mark_set("ghost_start", f"1.{len(typed)}")
        col = min(int(self._text.index("insert").split(".")[1]), len(typed))
        self._text.mark_set("insert", f"1.{col}")
        self._updating = False

    def _on_key_press(self, event: tk.Event) -> Optional[str]:
        if event.keysym == "Tab":
            self.accept_ghost()
            return "break"
        if event.keysym == "Right":
            typed = self.get_typed()
            col   = int(self._text.index("insert").split(".")[1])
            if col >= len(typed) and self._ghost:
                self.accept_ghost()
                return "break"
        return None

    def _on_key_release(self, event: tk.Event) -> None:
        if self._updating:
            return
        if event.keysym in (
            "Tab", "Return", "Escape", "Left", "Right", "Up", "Down",
            "Home", "End", "Shift_L", "Shift_R", "Control_L", "Control_R",
            "Alt_L", "Alt_R", "caps_lock",
        ):
            return
        if self.on_change:
            self.on_change(self.get_typed())

    def _on_enter(self, event: tk.Event) -> str:
        if self.on_submit:
            self.on_submit(self.get_typed())
        return "break"

    def _on_tab(self, event: tk.Event) -> str:
        self.accept_ghost()
        return "break"

    def _on_right(self, event: tk.Event) -> Optional[str]:
        col = int(self._text.index("insert").split(".")[1])
        if col >= len(self.get_typed()) and self._ghost:
            self.accept_ghost()
            return "break"
        return None


class SymbolTable(tk.Frame):
    """
    Treeview-based table showing RVA | Segment | Name.
    Column headers are clickable to sort. Rows alternate shading.
    Double-clicking a row copies the RVA to the clipboard.
    """

    COLUMNS = ("rva", "segment", "name")
    HEADERS = {"rva": "RVA", "segment": "Seg", "name": "Name"}
    WIDTHS  = {"rva": 110,   "segment": 50,    "name": 420}
    ANCHOR  = {"rva": "w",   "segment": "center", "name": "w"}

    def __init__(self, master, on_select=None, **kw):
        super().__init__(master, bg=BG, **kw)
        self.on_select  = on_select
        self._sort_col  = "rva"
        self._sort_asc  = True
        self._all_rows: list[tuple[str, str, str]] = []
        self._symbols:  list[Symbol] = []
        self._build()

    def _build(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Symbol.Treeview",
            background=ROW_EVEN, foreground=FG, fieldbackground=ROW_EVEN,
            rowheight=22, borderwidth=0, relief="flat")
        style.configure("Symbol.Treeview.Heading",
            background=BG3, foreground=ACCENT, relief="flat", borderwidth=0,
            font=("Consolas", 9, "bold"))
        style.map("Symbol.Treeview",
            background=[("selected", SEL_BG)], foreground=[("selected", SEL_FG)])
        style.map("Symbol.Treeview.Heading", background=[("active", BG3)])

        self._tree = ttk.Treeview(self, columns=self.COLUMNS, show="headings",
                                  style="Symbol.Treeview", selectmode="browse")

        vsb = FlatScrollbar(self, orient="vertical",   command=self._tree.yview)
        hsb = FlatScrollbar(self, orient="horizontal", command=self._tree.xview)
        self._tree.config(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        for col in self.COLUMNS:
            self._tree.heading(col, text=self.HEADERS[col],
                               command=lambda c=col: self._sort_by(c))
            self._tree.column(col, width=self.WIDTHS[col], minwidth=40,
                              anchor=self.ANCHOR[col], stretch=(col == "name"))

        self._tree.tag_configure("odd",  background=ROW_ODD)
        self._tree.tag_configure("even", background=ROW_EVEN)
        self._tree.tag_configure("highlight", background=SEL_BG, foreground=SEL_FG)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tk.Frame(self, bg=SB_TROUGH, width=SB_WIDTH, height=SB_WIDTH).grid(
            row=1, column=1, sticky="nsew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._tree.bind("<<TreeviewSelect>>", self._on_select)
        self._tree.bind("<Double-1>",         self._on_double_click)

    def load_symbols(self, symbols: list[Symbol]) -> None:
        self._symbols  = symbols
        self._all_rows = [(f"0x{s.offset:08X}", str(s.segment), s.name) for s in symbols]
        self._repopulate(self._all_rows)

    def filter(self, query: str) -> int:
        """Filter rows by name substring. Returns the number of visible rows."""
        if not query:
            self._repopulate(self._all_rows)
            return len(self._all_rows)
        lq       = query.lower()
        filtered = [r for r in self._all_rows if lq in r[2].lower()]
        self._repopulate(filtered)
        return len(filtered)

    def scroll_to_name(self, name: str) -> None:
        for iid in self._tree.get_children():
            vals = self._tree.item(iid, "values")
            if vals and vals[2] == name:
                self._tree.selection_set(iid)
                self._tree.see(iid)
                return

    def _repopulate(self, rows: list[tuple[str, str, str]]) -> None:
        self._tree.delete(*self._tree.get_children())
        for i, (rva, seg, name) in enumerate(rows):
            self._tree.insert("", "end", values=(rva, seg, name),
                              tags=("odd" if i % 2 else "even",))

    def _sort_by(self, col: str) -> None:
        if self._sort_col == col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = col
            self._sort_asc = True

        idx  = self.COLUMNS.index(col)
        rows = list(self._all_rows)
        if col == "rva":
            rows.sort(key=lambda r: int(r[0], 16), reverse=not self._sort_asc)
        elif col == "segment":
            rows.sort(key=lambda r: int(r[1]), reverse=not self._sort_asc)
        else:
            rows.sort(key=lambda r: r[idx].lower(), reverse=not self._sort_asc)
        self._all_rows = rows

        current_filter = getattr(self, "_current_filter", "")
        visible = ([r for r in rows if current_filter.lower() in r[2].lower()]
                   if current_filter else rows)
        self._repopulate(visible)

        for c in self.COLUMNS:
            arrow = ("  ▲" if self._sort_asc else "  ▼") if c == col else ""
            self._tree.heading(c, text=self.HEADERS[c] + arrow)

    def _on_select(self, event: tk.Event) -> None:
        sel = self._tree.selection()
        if sel and self.on_select:
            vals = self._tree.item(sel[0], "values")
            if vals:
                self.on_select(vals[0], vals[1], vals[2])  # rva, seg, name

    def _on_double_click(self, event: tk.Event) -> None:
        sel = self._tree.selection()
        if sel:
            vals = self._tree.item(sel[0], "values")
            if vals:
                self._tree.clipboard_clear()
                self._tree.clipboard_append(vals[0])  # copy RVA


class DetailPanel(tk.Frame):
    """Shows Name / RVA / Segment for the selected symbol. Click RVA to copy."""

    def __init__(self, master, **kw):
        super().__init__(master, bg=BG3, **kw)
        self._labels: dict[str, tk.Label] = {}
        for i, (field, colour) in enumerate([("Name", ACCENT2), ("RVA", YELLOW), ("Segment", FG_DIM)]):
            tk.Label(self, text=f"{field}:", bg=BG3, fg=FG_DIM,
                     font=("Consolas", 9)).grid(row=0, column=i*2, padx=(12, 4), pady=6, sticky="w")
            lbl = tk.Label(self, text="—", bg=BG3, fg=colour,
                           font=("Consolas", 9, "bold"), cursor="hand2")
            lbl.grid(row=0, column=i*2+1, padx=(0, 20), pady=6, sticky="w")
            self._labels[field] = lbl
        tk.Label(self, text="Double-click row or click RVA to copy",
                 bg=BG3, fg=FG_DIM, font=("Consolas", 8)
                 ).grid(row=0, column=6, padx=12, sticky="e")
        self.grid_columnconfigure(6, weight=1)
        self._labels["RVA"].bind("<Button-1>", self._copy_rva)
        self._rva = ""

    def update(self, rva: str, segment: str, name: str) -> None:
        self._rva = rva
        self._labels["Name"].config(text=name)
        self._labels["RVA"].config(text=rva)
        self._labels["Segment"].config(text=segment)

    def _copy_rva(self, _event) -> None:
        if self._rva:
            self.clipboard_clear()
            self.clipboard_append(self._rva)


class StatusBar(tk.Frame):
    def __init__(self, master, **kw):
        super().__init__(master, bg=ACCENT, height=22, **kw)
        self._label = tk.Label(self, text="", bg=ACCENT, fg=BG,
                               font=("Consolas", 9), anchor="w")
        self._label.pack(side="left", padx=8)
        self._right = tk.Label(self, text="", bg=ACCENT, fg=BG,
                               font=("Consolas", 9), anchor="e")
        self._right.pack(side="right", padx=8)

    def set(self, left: str, right: str = "") -> None:
        self._label.config(text=left)
        self._right.config(text=right)

    def set_loading(self, msg: str) -> None:
        for w in (self, self._label, self._right):
            w.config(bg=YELLOW)
        self._label.config(fg=BG, text=msg)
        self._right.config(fg=BG)

    def set_ready(self, msg: str, right: str = "") -> None:
        for w in (self, self._label, self._right):
            w.config(bg=ACCENT)
        self._label.config(fg=BG)
        self._right.config(fg=BG)
        self.set(msg, right)

    def set_error(self, msg: str) -> None:
        for w in (self, self._label, self._right):
            w.config(bg=RED)
        self._label.config(fg=FG, text=msg)
        self._right.config(fg=FG)


class LoadingOverlay(tk.Frame):
    """Full-window overlay shown while the PDB is loading."""

    def __init__(self, master, **kw):
        super().__init__(master, bg=BG, **kw)
        inner = tk.Frame(self, bg=BG2, padx=40, pady=30)
        inner.place(relx=0.5, rely=0.5, anchor="center")

        self._title = tk.Label(inner, text="Loading symbols…", bg=BG2, fg=FG,
                               font=("Consolas", 13, "bold"))
        self._title.pack(pady=(0, 12))

        self._msg = tk.Label(inner, text="", bg=BG2, fg=FG_DIM,
                             font=("Consolas", 9), wraplength=380, justify="left")
        self._msg.pack()

        self._progress = ttk.Progressbar(inner, mode="indeterminate", length=320,
                                         style="Loading.Horizontal.TProgressbar")
        self._progress.pack(pady=(16, 0))

        style = ttk.Style()
        style.configure("Loading.Horizontal.TProgressbar",
                        troughcolor=BG3, background=ACCENT, borderwidth=0)

    def start(self, title: str = "Loading symbols…") -> None:
        self._title.config(text=title)
        self._progress.start(12)
        self.lift()

    def set_message(self, msg: str) -> None:
        self._msg.config(text=msg)
        self.update_idletasks()

    def stop(self) -> None:
        self._progress.stop()
        self.lower()


class App(tk.Tk):
    """
    Main window layout:

      ┌─────────────────────────────────────────────────────┐
      │  PDB Symbol Browser                  [PE: foo.exe]  │
      ├─────────────────────────────────────────────────────┤
      │  🔍  [search box with ghost text          ]  [Open] │
      ├─────────────────────────────────────────────────────┤
      │  RVA        │ Seg │ Name                            │
      │  0x00001000 │  1  │ NtCreateFile                    │
      ├─────────────────────────────────────────────────────┤
      │  Name: NtCreateFile   RVA: 0x00001000   Seg: 1      │
      ├─────────────────────────────────────────────────────┤
      │  42,977 symbols  │  Showing 42,977                  │
      └─────────────────────────────────────────────────────┘
    """

    MIN_W, MIN_H = 720, 520

    def __init__(self, pe_path: Optional[str], output_dir: Optional[str], no_download: bool):
        super().__init__()
        self._pe_path     = pe_path
        self._output_dir  = output_dir  # None → use temp at download time
        self._no_download = no_download
        self._reader: Optional[PDBReader]      = None
        self._matcher: Optional[SymbolMatcher] = None
        self._msg_queue: queue.Queue           = queue.Queue()

        self._configure_window()
        self._build_ui()
        self._poll_queue()

        if pe_path:
            self.after(100, lambda: self._start_load(pe_path))
        else:
            self.after(100, self._open_file_dialog)

    def _configure_window(self) -> None:
        self.title("PDB Symbol Browser")
        self.configure(bg=BG)
        self.minsize(self.MIN_W, self.MIN_H)
        self.geometry("960x640")
        # Dark title bar on Windows 10/11
        try:
            self.update()
            hwnd = int(self.frame(), 16)
            import ctypes
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 20, ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int))
        except Exception:
            pass

    def _build_ui(self) -> None:
        mono9  = tkfont.Font(family="Consolas", size=9)
        mono11 = tkfont.Font(family="Consolas", size=11)

        search_bar = tk.Frame(self, bg=BG2, pady=0)
        search_bar.pack(fill="x", side="top")
        tk.Label(search_bar, text="🔍", bg=BG2, fg=FG_DIM,
                 font=("Segoe UI Emoji", 11)).pack(side="left", padx=(10, 4), pady=6)
        self._entry = GhostEntry(search_bar, font=mono11,
                                 on_change=self._on_search_change,
                                 on_submit=self._on_search_submit)
        self._entry.pack(side="left", fill="both", expand=True, pady=4)
        tk.Button(search_bar, text="Open PE…", bg=BG3, fg=ACCENT,
                  activebackground=BG, activeforeground=ACCENT,
                  relief="flat", bd=0, padx=10, pady=4, font=mono9, cursor="hand2",
                  command=self._open_file_dialog).pack(side="right", padx=(4, 10), pady=6)
        tk.Button(search_bar, text="Save to…", bg=BG3, fg=FG_DIM,
                  activebackground=BG, activeforeground=FG,
                  relief="flat", bd=0, padx=10, pady=4, font=mono9, cursor="hand2",
                  command=self._choose_output_dir).pack(side="right", padx=(0, 4), pady=6)
        self._dir_label = tk.Label(search_bar, text=self._dir_display(),
                                   bg=BG2, fg=FG_DIM, font=mono9)
        self._dir_label.pack(side="right", padx=(0, 4), pady=6)

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        self._table = SymbolTable(self, on_select=self._on_row_select)
        self._table.pack(fill="both", expand=True)

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        self._detail = DetailPanel(self)
        self._detail.pack(fill="x")

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        self._status = StatusBar(self)
        self._status.pack(fill="x", side="bottom")
        self._status.set("No file loaded")

        self._overlay = LoadingOverlay(self)
        self._overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._overlay.lower()

        self.after(200, self._entry.focus)

    def _dir_display(self) -> str:
        """Short label shown next to the Save-to button."""
        d = self._output_dir or default_pdb_dir()
        return f"→ {d}"

    def _choose_output_dir(self) -> None:
        """Let the user pick a folder (or reset to temp) for PDB downloads."""
        choice = filedialog.askdirectory(
            title="Choose PDB download folder",
            initialdir=self._output_dir or default_pdb_dir(),
        )
        if choice:
            self._output_dir = choice
            self._dir_label.config(text=self._dir_display())

    def _open_file_dialog(self) -> None:
        path = filedialog.askopenfilename(
            title="Select PE file (EXE or DLL)",
            filetypes=[("PE files", "*.exe *.dll *.sys"), ("All files", "*.*")],
        )
        if path:
            self._start_load(path)

    def _start_load(self, pe_path: str) -> None:
        self._pe_path = pe_path
        self.title(f"PDB Symbol Browser — {Path(pe_path).name}")
        self._overlay.start(f"Loading {Path(pe_path).name}…")
        self._status.set_loading("Parsing PE…")
        self._entry.clear()
        self._table.load_symbols([])
        self._detail.update("—", "—", "—")
        threading.Thread(target=self._load_worker, args=(pe_path,), daemon=True).start()

    def _load_worker(self, pe_path: str) -> None:
        try:
            self._post("status", "Parsing PE file…")
            pe_parser = PEParser(pe_path)
            pe_parser.load()
            pdb_info = pe_parser.extract_pdb_info()

            output_dir = self._output_dir or default_pdb_dir()
            pdb_path = os.path.join(output_dir, pdb_info.pdb_filename)

            if not self._no_download:
                dl  = SymbolDownloader(output_dir=output_dir)
                url = dl.build_url(pdb_info)
                if os.path.exists(pdb_path):
                    self._post("status", f"Using cached {pdb_info.pdb_filename}")
                else:
                    self._post("status", f"Downloading {pdb_info.pdb_filename}…")
                    self._post("overlay_msg",
                               f"Downloading from Microsoft Symbol Server…\n{url}")
                pdb_path = dl.download(pdb_info)
            else:
                if not os.path.isfile(pdb_path):
                    raise FileNotFoundError(f"PDB not found: {pdb_path}")

            self._post("status", f"Parsing {pdb_info.pdb_filename}…")
            self._post("overlay_msg", f"Parsing PDB streams…\n{pdb_info.pdb_filename}")
            reader = PDBReader(pdb_path, pe_parser)
            reader.load()
            self._post("done", (reader, pdb_info))
        except Exception as exc:
            self._post("error", str(exc))

    def _post(self, kind: str, data=None) -> None:
        self._msg_queue.put((kind, data))

    def _poll_queue(self) -> None:
        """Drain the worker-thread message queue on the main thread (every 50 ms)."""
        try:
            while True:
                kind, data = self._msg_queue.get_nowait()
                if kind == "status":
                    self._status.set_loading(data)
                    self._overlay.set_message(data)
                elif kind == "overlay_msg":
                    self._overlay.set_message(data)
                elif kind == "done":
                    self._on_load_done(*data)
                elif kind == "error":
                    self._on_load_error(data)
        except queue.Empty:
            pass
        self.after(50, self._poll_queue)

    def _on_load_done(self, reader: PDBReader, pdb_info) -> None:
        self._reader  = reader
        self._matcher = SymbolMatcher(reader.symbols)
        self._overlay.stop()
        self._table.load_symbols(reader.symbols)
        n = len(reader.symbols)
        self._status.set_ready(
            f"{Path(reader.pdb_path).name}  ·  {n:,} symbols",
            f"GUID {pdb_info.guid}  Age {pdb_info.age}",
        )
        self._entry.focus()

    def _on_load_error(self, msg: str) -> None:
        self._overlay.stop()
        self._status.set_error(f"Error: {msg}")

    def _on_search_change(self, text: str) -> None:
        if not self._matcher:
            return
        if text:
            pred = self._matcher.predict(text)
            self._entry.set_ghost(pred[len(text):] if pred and pred != text else "")
        else:
            self._entry.set_ghost("")

        count = self._table.filter(text)
        self._table._current_filter = text
        total = len(self._reader.symbols) if self._reader else 0
        base  = f"{Path(self._reader.pdb_path).name}  ·  {total:,} symbols"
        self._status.set_ready(
            base,
            f"Showing {count:,} match{'es' if count != 1 else ''}" if text else "",
        )

    def _on_search_submit(self, text: str) -> None:
        if not self._matcher or not text.strip():
            return
        sym = self._matcher.exact(text) or self._matcher.exact_ci(text)
        if sym:
            self._detail.update(f"0x{sym.offset:08X}", str(sym.segment), sym.name)
            self._table.filter(text)
            self._table._current_filter = text
            self._table.scroll_to_name(sym.name)
        else:
            self._detail.update("—", "—", f'"{text}" not found')

    def _on_row_select(self, rva: str, segment: str, name: str) -> None:
        self._detail.update(rva, segment, name)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GUI symbol browser for PE/PDB files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python gui.py\n"
            "  python gui.py ntoskrnl.exe\n"
            "  python gui.py ntoskrnl.exe --no-download\n"
            "  python gui.py ntoskrnl.exe -o C:\\symbols\n"
            "  python gui.py ntoskrnl.exe --save-to-cwd\n"
        ),
    )
    parser.add_argument("pe_file", nargs="?", default=None,
                        help="Path to the EXE or DLL. File picker opens if omitted.")
    parser.add_argument(
        "--output-dir", "-o", default=None,
        help=(
            "Directory for the downloaded PDB. "
            f"Defaults to the system temp folder ({default_pdb_dir()})."
        ),
    )
    parser.add_argument(
        "--save-to-cwd", action="store_true",
        help="Save the downloaded PDB to the current working directory instead of temp.",
    )
    parser.add_argument("--no-download", action="store_true",
                        help="Skip downloading; use an already-cached PDB.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.output_dir:
        output_dir = args.output_dir
    elif args.save_to_cwd:
        output_dir = os.getcwd()
    else:
        output_dir = None  # App will use default_pdb_dir() at download time
    App(pe_path=args.pe_file, output_dir=output_dir,
        no_download=args.no_download).mainloop()


if __name__ == "__main__":
    main()
