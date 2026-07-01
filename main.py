import sys


def _enable_dpi_awareness() -> None:
    """Request DPI-aware rendering on Windows so the GUI isn't blurry on
    high-resolution displays."""
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass


def main() -> None:
    if sys.platform == "win32":
        _enable_dpi_awareness()

    from gui import App
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
