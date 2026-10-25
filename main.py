#!/usr/bin/env python3
"""
main.py - Unified entry point for the PDB Symbol Browser.

Usage:
    python main.py --cli [pe_file] [options]
    python main.py --gui [pe_file] [options]

    If neither --cli nor --gui is given, the launch mode is determined
    automatically (see _detect_mode).

Common options forwarded to the chosen frontend:
    pe_file             Path to the EXE / DLL.  Prompted / picked if omitted.
    --output-dir, -o    Directory for the downloaded PDB (default: .)
    --no-download       Skip downloading; use an already-cached PDB.

When compiled with Nuitka into a single executable the same binary serves
both frontends — just pass --cli or --gui on the command line.
"""

import argparse
import sys
import os


def _connect_console_streams(force: bool = False) -> None:
    if force or sys.stdin is None:
        sys.stdin = open("CONIN$", "r")
    if force or sys.stdout is None:
        sys.stdout = open("CONOUT$", "w")
    if force or sys.stderr is None:
        sys.stderr = open("CONOUT$", "w")


def _attach_parent_console() -> bool:
    """Attach a GUI-subsystem executable to the invoking console, if present."""
    if sys.platform != "win32":
        return os.isatty(1)

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_console_window = kernel32.GetConsoleWindow
    get_console_window.argtypes = []
    get_console_window.restype = wintypes.HWND

    if not get_console_window():
        attach_console = kernel32.AttachConsole
        attach_console.argtypes = [wintypes.DWORD]
        attach_console.restype = wintypes.BOOL
        if not attach_console(0xFFFFFFFF):  # ATTACH_PARENT_PROCESS
            if not get_console_window():
                return False

    _connect_console_streams()
    return True


def _allocate_console() -> bool:
    """Create a console when CLI mode was requested but no parent console exists."""
    if sys.platform != "win32":
        return os.isatty(1)

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    alloc_console = kernel32.AllocConsole
    alloc_console.argtypes = []
    alloc_console.restype = wintypes.BOOL
    if not alloc_console():
        get_console_window = kernel32.GetConsoleWindow
        get_console_window.argtypes = []
        get_console_window.restype = wintypes.HWND
        if not get_console_window():
            return False

    _connect_console_streams(force=True)
    return True


def _detect_mode(has_console: bool | None = None) -> str:
    """
    Determine whether to launch the GUI or CLI automatically.
    """
    if sys.platform == "win32":
        if has_console is None:
            has_console = _attach_parent_console()
        return "cli" if has_console else "gui"
    else:
        try:
            if not os.isatty(1):
                return "gui"
        except Exception:
            pass

    # If terminal checks pass (or fail to detect GUI environment), default to CLI
    return "cli"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pdb-browser",
        description="PDB Symbol Browser — interactive CLI shell or GUI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --cli ntoskrnl.exe\n"
            "  python main.py --gui ntoskrnl.exe\n"
            "  python main.py --cli ntoskrnl.exe --no-download\n"
            "  python main.py --gui ntoskrnl.exe -o /tmp/symbols\n"
        ),
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--cli", dest="mode", action="store_const", const="cli",
        help="Launch the interactive terminal shell.",
    )
    mode_group.add_argument(
        "--gui", dest="mode", action="store_const", const="gui",
        help="Launch the graphical symbol browser.",
    )
    parser.add_argument(
        "pe_file", nargs="?", default=None,
        help="Path to the EXE or DLL.  Prompted / picked interactively if omitted.",
    )
    parser.add_argument(
        "--output-dir", "-o", default=".", metavar="DIR",
        help="Directory for the downloaded PDB (default: current directory).",
    )
    parser.add_argument(
        "--no-download", action="store_true",
        help="Skip downloading; use an already-cached PDB.",
    )
    return parser


def _forward_argv(args: argparse.Namespace) -> None:
    """Rewrite sys.argv so the chosen frontend's parse_args() sees only its own flags."""
    forwarded = [sys.argv[0]]
    if args.pe_file:
        forwarded.append(args.pe_file)
    if args.output_dir != ".":
        forwarded += ["--output-dir", args.output_dir]
    if args.no_download:
        forwarded.append("--no-download")
    sys.argv = forwarded


def main() -> None:
    has_console = _attach_parent_console()
    args = _build_parser().parse_args()
    mode = args.mode or _detect_mode(has_console)

    if mode == "cli" and sys.platform == "win32" and not has_console:
        has_console = _allocate_console()

    if mode == "cli" and sys.platform == "win32" and not has_console:
        message = "CLI mode requires a console. Run PDB Browser from Command Prompt or PowerShell."
        import ctypes
        ctypes.WinDLL("user32").MessageBoxW(None, message, "PDB Browser", 0x10)
        sys.exit(2)

    if mode == "gui":
        try:
            from gui import main as gui_main
        except ImportError as exc:
            print(f"[!] Cannot import GUI frontend: {exc}", file=sys.stderr)
            print("    Make sure tkinter is available or use --cli.", file=sys.stderr)
            sys.exit(1)
        _forward_argv(args)
        gui_main()
    else:
        from cli import main as cli_main
        _forward_argv(args)
        cli_main()


if __name__ == "__main__":
    main()
