import main


def test_windows_auto_mode_uses_cli_when_console_is_available(monkeypatch):
    monkeypatch.setattr(main.sys, "platform", "win32")

    assert main._detect_mode(has_console=True) == "cli"


def test_windows_auto_mode_uses_gui_without_console(monkeypatch):
    monkeypatch.setattr(main.sys, "platform", "win32")

    assert main._detect_mode(has_console=False) == "gui"


def test_cli_flag_is_forwarded_as_explicit_mode():
    args = main._build_parser().parse_args(["--cli", "program.exe"])

    assert args.mode == "cli"
    assert args.pe_file == "program.exe"


def test_explicit_cli_allocates_console_when_parent_console_is_unavailable(
    monkeypatch,
):
    import cli

    called = []
    monkeypatch.setattr(main.sys, "platform", "win32")
    monkeypatch.setattr(main.sys, "argv", ["pdb-browser.exe", "--cli"])
    monkeypatch.setattr(main, "_attach_parent_console", lambda: False)
    monkeypatch.setattr(main, "_allocate_console", lambda: True)
    monkeypatch.setattr(main, "_forward_argv", lambda _args: None)
    monkeypatch.setattr(cli, "main", lambda: called.append(True))

    main.main()

    assert called == [True]
