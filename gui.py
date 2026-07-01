import datetime
import json
import queue
import threading
import time
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from scanner import ScanEngine, ScanResult
from utils import check_privileges, parse_ports, validate_and_expand_target

# ── Colour palette (simulated glassmorphism on dark bg) ───────────────────
BG_DEEP     = "#080c14"
BG_PANEL    = "#0d1520"
BG_CARD     = "#0f1b2d"
BG_ROW_ALT  = "#0a1018"
BORDER      = "#1a3a5c"
BORDER_HI   = "#00d4ff"
ACCENT      = "#00d4ff"
ACCENT_DIM  = "#0099bb"
TEXT_PRI    = "#e2e8f0"
TEXT_SEC    = "#7a90a8"
BTN_NEUTRAL = "#141e2c"
BTN_STOP_FG = "#ff4466"
CLR_OPEN    = "#00ff88"
CLR_CLOSED  = "#ff4466"
CLR_FILTER  = "#ffaa00"
CLR_HDR_BG  = "#0a1520"
CLR_SEL     = "#162840"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# ── Reusable labelled-entry factory ───────────────────────────────────────

def _make_labeled_entry(
    parent: ctk.CTkFrame,
    label: str,
    placeholder: str,
    **entry_kw,
) -> ctk.CTkEntry:
    ctk.CTkLabel(
        parent, text=label,
        font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
        text_color=TEXT_SEC, anchor="w",
    ).pack(fill="x", padx=2, pady=(0, 4))
    entry = ctk.CTkEntry(
        parent,
        placeholder_text=placeholder,
        fg_color=BG_DEEP,
        border_color=BORDER,
        border_width=1,
        text_color=TEXT_PRI,
        placeholder_text_color=TEXT_SEC,
        corner_radius=8,
        height=38,
        font=ctk.CTkFont(family="Consolas", size=12),
        **entry_kw,
    )
    entry.pack(fill="x")
    return entry


# ── Main application window ───────────────────────────────────────────────

class App(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()

        self.title("NetScan Pro — Port Scanner")
        self.geometry("1180x820")
        self.minsize(960, 680)
        self.configure(fg_color=BG_DEEP)

        # Runtime state
        self._engine: ScanEngine | None = None
        self._result_queue: queue.Queue = queue.Queue()
        self._scan_thread: threading.Thread | None = None
        self._all_results: list[ScanResult] = []
        self._total_tasks: int = 0
        self._scan_start: float = 0.0
        self._meta: dict = {}          # populated at scan start for export

        self._build_ui()

    # ══════════════════════════════════════════════════════════════════════
    # UI Construction
    # ══════════════════════════════════════════════════════════════════════

    def _build_ui(self) -> None:
        self._build_header()

        body = ctk.CTkFrame(self, fg_color=BG_DEEP)
        body.pack(fill="both", expand=True, padx=18, pady=(10, 0))
        body.columnconfigure(0, weight=1)
        body.rowconfigure(3, weight=1)   # results row expands

        self._build_config_card(body)
        self._build_control_bar(body)
        self._build_progress_bar(body)
        self._build_results_section(body)
        self._build_status_bar()

    # ── Header ────────────────────────────────────────────────────────────

    def _build_header(self) -> None:
        hdr = ctk.CTkFrame(
            self, fg_color=BG_PANEL, corner_radius=0, height=62,
            border_width=0,
        )
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)

        # left: logo + title
        left = ctk.CTkFrame(hdr, fg_color="transparent")
        left.pack(side="left", padx=22, pady=10)

        ctk.CTkLabel(
            left, text="⬡  NetScan Pro",
            font=ctk.CTkFont(family="Consolas", size=21, weight="bold"),
            text_color=ACCENT,
        ).pack(side="left")

        ctk.CTkLabel(
            left, text="   Advanced Network Port Scanner",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SEC,
        ).pack(side="left", pady=(4, 0))

        # right: version tag
        ctk.CTkLabel(
            hdr, text="v1.0.0  ",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=TEXT_SEC,
        ).pack(side="right", padx=18)

    # ── Config card ───────────────────────────────────────────────────────

    def _build_config_card(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(
            parent, fg_color=BG_CARD,
            border_color=BORDER, border_width=1, corner_radius=12,
        )
        card.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        ctk.CTkLabel(
            card, text="SCAN CONFIGURATION",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=ACCENT, anchor="w",
        ).pack(fill="x", padx=18, pady=(14, 2))

        sep = ctk.CTkFrame(card, fg_color=BORDER, height=1)
        sep.pack(fill="x", padx=18, pady=(0, 12))

        # --- Row 1: Target  |  Ports ---
        row1 = ctk.CTkFrame(card, fg_color="transparent")
        row1.pack(fill="x", padx=18, pady=(0, 10))
        row1.columnconfigure((0, 1), weight=1)

        target_wrap = ctk.CTkFrame(row1, fg_color="transparent")
        target_wrap.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self._target_entry = _make_labeled_entry(
            target_wrap,
            "TARGET  —  IP · Hostname · CIDR",
            "e.g.  192.168.1.1  ·  scanme.nmap.org  ·  10.0.0.0/24",
        )

        ports_wrap = ctk.CTkFrame(row1, fg_color="transparent")
        ports_wrap.grid(row=0, column=1, sticky="ew", padx=(10, 0))
        self._ports_entry = _make_labeled_entry(
            ports_wrap,
            "PORTS  —  range · list · 'common'",
            "e.g.  1-1024  ·  80,443,8080  ·  common",
        )
        self._ports_entry.insert(0, "1-1024")

        # --- Row 2: Scan type  |  Timeout slider  |  Threads slider ---
        row2 = ctk.CTkFrame(card, fg_color="transparent")
        row2.pack(fill="x", padx=18, pady=(0, 16))
        row2.columnconfigure((0, 1, 2), weight=1)

        # Scan type
        st_wrap = ctk.CTkFrame(row2, fg_color="transparent")
        st_wrap.grid(row=0, column=0, sticky="ew", padx=(0, 14))
        ctk.CTkLabel(
            st_wrap, text="SCAN TYPE",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=TEXT_SEC, anchor="w",
        ).pack(fill="x", padx=2, pady=(0, 4))
        self._scan_type_var = ctk.StringVar(value="TCP Connect")
        ctk.CTkOptionMenu(
            st_wrap,
            variable=self._scan_type_var,
            values=["TCP Connect", "SYN Stealth (root required)"],
            fg_color=BG_DEEP, button_color=BORDER,
            button_hover_color=ACCENT_DIM,
            dropdown_fg_color=BG_CARD,
            dropdown_hover_color=CLR_SEL,
            text_color=TEXT_PRI,
            font=ctk.CTkFont(family="Consolas", size=12),
            corner_radius=8, height=38,
        ).pack(fill="x")

        # Timeout slider
        to_wrap = ctk.CTkFrame(row2, fg_color="transparent")
        to_wrap.grid(row=0, column=1, sticky="ew", padx=7)
        self._timeout_var = ctk.DoubleVar(value=1.0)
        to_hdr = ctk.CTkFrame(to_wrap, fg_color="transparent")
        to_hdr.pack(fill="x", padx=2, pady=(0, 4))
        ctk.CTkLabel(
            to_hdr, text="TIMEOUT",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=TEXT_SEC, anchor="w",
        ).pack(side="left")
        self._timeout_lbl = ctk.CTkLabel(
            to_hdr, text="1.0 s",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=ACCENT,
        )
        self._timeout_lbl.pack(side="right")
        ctk.CTkSlider(
            to_wrap, from_=0.5, to=5.0,
            variable=self._timeout_var,
            command=lambda v: self._timeout_lbl.configure(text=f"{v:.1f} s"),
            progress_color=ACCENT, button_color=ACCENT,
            button_hover_color=ACCENT_DIM, height=20,
        ).pack(fill="x", pady=(8, 0))

        # Threads slider
        th_wrap = ctk.CTkFrame(row2, fg_color="transparent")
        th_wrap.grid(row=0, column=2, sticky="ew", padx=(14, 0))
        self._threads_var = ctk.IntVar(value=150)
        th_hdr = ctk.CTkFrame(th_wrap, fg_color="transparent")
        th_hdr.pack(fill="x", padx=2, pady=(0, 4))
        ctk.CTkLabel(
            th_hdr, text="THREADS",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=TEXT_SEC, anchor="w",
        ).pack(side="left")
        self._threads_lbl = ctk.CTkLabel(
            th_hdr, text="150",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=ACCENT,
        )
        self._threads_lbl.pack(side="right")
        ctk.CTkSlider(
            th_wrap, from_=10, to=500,
            variable=self._threads_var,
            command=lambda v: self._threads_lbl.configure(text=str(int(v))),
            progress_color=ACCENT, button_color=ACCENT,
            button_hover_color=ACCENT_DIM, height=20,
        ).pack(fill="x", pady=(8, 0))

    # ── Control bar ───────────────────────────────────────────────────────

    def _build_control_bar(self, parent: ctk.CTkFrame) -> None:
        bar = ctk.CTkFrame(parent, fg_color="transparent")
        bar.grid(row=1, column=0, sticky="ew", pady=(0, 8))

        self._btn_start = ctk.CTkButton(
            bar, text="▶   START SCAN",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            fg_color=ACCENT, hover_color=ACCENT_DIM,
            text_color=BG_DEEP, corner_radius=8, height=42, width=170,
            command=self._on_start,
        )
        self._btn_start.pack(side="left", padx=(0, 10))

        self._btn_stop = ctk.CTkButton(
            bar, text="■   STOP",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            fg_color=BTN_NEUTRAL, hover_color="#1e2e3e",
            text_color=TEXT_SEC, corner_radius=8, height=42, width=130,
            state="disabled",
            command=self._on_stop,
        )
        self._btn_stop.pack(side="left", padx=(0, 10))

        self._btn_export = ctk.CTkButton(
            bar, text="⬇   EXPORT JSON",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            fg_color=BTN_NEUTRAL, hover_color="#162a1e",
            text_color=TEXT_SEC, corner_radius=8, height=42, width=178,
            state="disabled",
            command=self._on_export,
        )
        self._btn_export.pack(side="left")

        # Live open-port counter (right side)
        self._open_lbl = ctk.CTkLabel(
            bar, text="",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=CLR_OPEN,
        )
        self._open_lbl.pack(side="right", padx=12)

    # ── Progress bar ──────────────────────────────────────────────────────

    def _build_progress_bar(self, parent: ctk.CTkFrame) -> None:
        pf = ctk.CTkFrame(
            parent, fg_color=BG_CARD,
            border_color=BORDER, border_width=1,
            corner_radius=8, height=56,
        )
        pf.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        pf.pack_propagate(False)

        inner = ctk.CTkFrame(pf, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=16, pady=8)
        inner.columnconfigure(0, weight=1)

        self._progress_lbl = ctk.CTkLabel(
            inner,
            text="Ready — configure target and press  ▶ START SCAN",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=TEXT_SEC, anchor="w",
        )
        self._progress_lbl.grid(row=0, column=0, sticky="ew")

        self._progress_bar = ctk.CTkProgressBar(
            inner,
            progress_color=ACCENT, fg_color=BG_DEEP,
            corner_radius=4, height=6,
        )
        self._progress_bar.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self._progress_bar.set(0)

    # ── Results table ─────────────────────────────────────────────────────

    def _build_results_section(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(
            parent, fg_color=BG_CARD,
            border_color=BORDER, border_width=1, corner_radius=12,
        )
        card.grid(row=3, column=0, sticky="nsew", pady=(0, 10))

        # Header row: title + display filter
        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.pack(fill="x", padx=18, pady=(14, 6))

        ctk.CTkLabel(
            hdr, text="SCAN RESULTS",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=ACCENT, anchor="w",
        ).pack(side="left")

        # Display filter (right side of header)
        filter_frame = ctk.CTkFrame(hdr, fg_color="transparent")
        filter_frame.pack(side="right")

        ctk.CTkLabel(
            filter_frame, text="SHOW: ",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=TEXT_SEC,
        ).pack(side="left", padx=(0, 4))

        self._filter_var = ctk.StringVar(value="Open + Filtered")
        self._filter_menu = ctk.CTkOptionMenu(
            filter_frame,
            variable=self._filter_var,
            values=["Open + Filtered", "Open Only", "All Results"],
            fg_color=BG_DEEP, button_color=BORDER,
            button_hover_color=ACCENT_DIM,
            dropdown_fg_color=BG_CARD,
            text_color=TEXT_PRI,
            font=ctk.CTkFont(family="Consolas", size=11),
            corner_radius=6, height=28, width=160,
            command=self._on_filter_change,
        )
        self._filter_menu.pack(side="left")

        sep = ctk.CTkFrame(card, fg_color=BORDER, height=1)
        sep.pack(fill="x", padx=18, pady=(0, 8))

        # Treeview
        table_wrap = ctk.CTkFrame(card, fg_color="transparent")
        table_wrap.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        self._style_treeview()

        cols = ("host", "port", "status", "service", "banner", "time")
        self._tree = ttk.Treeview(
            table_wrap, columns=cols, show="headings",
            selectmode="browse", style="Custom.Treeview",
        )

        col_defs = [
            ("host",    "HOST",               130, "w"),
            ("port",    "PORT",                65, "center"),
            ("status",  "STATUS",              90, "center"),
            ("service", "SERVICE",             95, "center"),
            ("banner",  "BANNER / SERVICE INFO", 490, "w"),
            ("time",    "TIME (s)",             80, "center"),
        ]
        for cid, heading, width, anchor in col_defs:
            self._tree.heading(cid, text=heading, anchor="center")
            self._tree.column(cid, width=width, anchor=anchor, minwidth=50)

        self._tree.tag_configure("open",     foreground=CLR_OPEN)
        self._tree.tag_configure("closed",   foreground=CLR_CLOSED)
        self._tree.tag_configure("filtered", foreground=CLR_FILTER)
        self._tree.tag_configure("alt",      background=BG_ROW_ALT)

        vsb = ttk.Scrollbar(table_wrap, orient="vertical",
                             command=self._tree.yview)
        hsb = ttk.Scrollbar(table_wrap, orient="horizontal",
                             command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self._tree.pack(fill="both", expand=True)

    def _style_treeview(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Custom.Treeview",
            background=BG_CARD,
            foreground=TEXT_PRI,
            fieldbackground=BG_CARD,
            rowheight=26,
            borderwidth=0,
            font=("Consolas", 11),
        )
        style.configure(
            "Custom.Treeview.Heading",
            background=CLR_HDR_BG,
            foreground=ACCENT,
            font=("Consolas", 11, "bold"),
            relief="flat",
            borderwidth=0,
        )
        style.map(
            "Custom.Treeview",
            background=[("selected", CLR_SEL)],
            foreground=[("selected", TEXT_PRI)],
        )
        style.map("Custom.Treeview.Heading", relief=[("active", "flat")])

        # Style scrollbars
        style.configure(
            "Vertical.TScrollbar",
            background=BG_PANEL, troughcolor=BG_DEEP,
            arrowcolor=TEXT_SEC, borderwidth=0,
        )
        style.configure(
            "Horizontal.TScrollbar",
            background=BG_PANEL, troughcolor=BG_DEEP,
            arrowcolor=TEXT_SEC, borderwidth=0,
        )

    # ── Status bar ────────────────────────────────────────────────────────

    def _build_status_bar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=28)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self._status_lbl = ctk.CTkLabel(
            bar, text="  NetScan Pro  |  Ready",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=TEXT_SEC, anchor="w",
        )
        self._status_lbl.pack(side="left", padx=12, fill="y")

    # ══════════════════════════════════════════════════════════════════════
    # Event handlers
    # ══════════════════════════════════════════════════════════════════════

    def _set_status(self, msg: str) -> None:
        self._status_lbl.configure(text=f"  {msg}")

    # ── Start ─────────────────────────────────────────────────────────────

    def _on_start(self) -> None:
        target_raw = self._target_entry.get().strip()
        port_raw   = self._ports_entry.get().strip()

        if not target_raw:
            messagebox.showerror(
                "Missing Target",
                "Please enter a target IP address, hostname, or CIDR range.",
            )
            return
        if not port_raw:
            messagebox.showerror(
                "Missing Ports",
                "Please enter a port range, comma-separated list, or 'common'.",
            )
            return

        try:
            hosts = validate_and_expand_target(target_raw)
        except ValueError as exc:
            messagebox.showerror("Invalid Target", str(exc))
            return

        try:
            ports = parse_ports(port_raw)
        except ValueError as exc:
            messagebox.showerror("Invalid Port Input", str(exc))
            return

        scan_type_raw = self._scan_type_var.get()
        scan_type = "TCP Connect" if "TCP" in scan_type_raw else "SYN Stealth"

        if scan_type == "SYN Stealth" and not check_privileges():
            messagebox.showwarning(
                "Elevated Privileges Required",
                "SYN Stealth scan requires administrator / root privileges.\n\n"
                "• Windows: close the app, right-click → Run as Administrator.\n"
                "  Also ensure Npcap is installed (https://npcap.com).\n\n"
                "• Linux / macOS: run with  sudo python main.py",
            )
            return

        total = len(hosts) * len(ports)
        if total > 50_000:
            if not messagebox.askyesno(
                "Large Scan Warning",
                f"This scan covers {total:,} host×port combinations and may\n"
                f"take several minutes. Continue?",
            ):
                return

        # Reset everything
        self._all_results.clear()
        for item in self._tree.get_children():
            self._tree.delete(item)

        self._total_tasks = total
        self._scan_start  = time.monotonic()
        self._meta = {
            "target":    target_raw,
            "scan_type": scan_type,
            "port_range": port_raw,
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        }

        self._progress_bar.set(0)
        self._open_lbl.configure(text="")

        # Spin up engine
        self._result_queue = queue.Queue()
        self._engine = ScanEngine(self._result_queue)

        timeout  = round(self._timeout_var.get(), 1)
        workers  = int(self._threads_var.get())

        self._scan_thread = threading.Thread(
            target=self._engine.run_scan,
            args=(hosts, ports, scan_type, timeout, workers),
            daemon=True,
        )
        self._scan_thread.start()

        # UI state: scanning
        self._btn_start.configure(state="disabled")
        self._btn_stop.configure(
            state="normal", text_color=BTN_STOP_FG,
            hover_color="#2a1018",
        )
        self._btn_export.configure(state="disabled", text_color=TEXT_SEC)
        self._progress_lbl.configure(
            text=f"Scanning {len(hosts)} host(s) across {len(ports)} port(s) …",
        )
        self._set_status(
            f"Scanning  {target_raw}  [{scan_type}]  "
            f"{len(hosts)} host(s) × {len(ports)} ports",
        )

        self.after(100, self._poll_queue)

    # ── Stop ──────────────────────────────────────────────────────────────

    def _on_stop(self) -> None:
        if self._engine:
            self._engine.stop()
        self._btn_stop.configure(state="disabled", text_color=TEXT_SEC,
                                 hover_color="#1e2e3e")
        self._progress_lbl.configure(text="Stopping — waiting for active threads …")
        self._set_status("Stop requested.")

    # ── Queue polling ─────────────────────────────────────────────────────

    def _poll_queue(self) -> None:
        try:
            while True:
                msg = self._result_queue.get_nowait()
                kind, payload, done, total = msg

                if kind == "error":
                    self._on_scan_error(str(payload))
                    return
                elif kind == "done":
                    self._on_scan_done(done, total)
                    return
                else:
                    self._handle_result(payload, done, total)
        except queue.Empty:
            pass

        self.after(100, self._poll_queue)

    def _handle_result(self, result: ScanResult, done: int, total: int) -> None:
        self._all_results.append(result)

        # Progress
        pct = done / total if total else 0
        self._progress_bar.set(pct)
        open_ct = sum(1 for r in self._all_results if r.status == "open")
        self._progress_lbl.configure(
            text=(
                f"Scanned {done}/{total}  ({int(pct * 100)}%)"
                f"   —   Open: {open_ct}"
            ),
        )
        if open_ct:
            self._open_lbl.configure(text=f"⬡  {open_ct}  OPEN")

        # Insert into table if passes display filter
        if self._passes_filter(result):
            self._insert_row(result)
            children = self._tree.get_children()
            if children:
                self._tree.see(children[-1])

    def _on_scan_done(self, done: int, total: int) -> None:
        elapsed   = time.monotonic() - self._scan_start
        open_ct   = sum(1 for r in self._all_results if r.status == "open")
        closed_ct = sum(1 for r in self._all_results if r.status == "closed")
        filt_ct   = sum(1 for r in self._all_results if r.status == "filtered")

        self._progress_bar.set(1.0)
        self._progress_lbl.configure(
            text=(
                f"Scan complete — {done} ports in {elapsed:.1f}s"
                f"   |   Open: {open_ct}   Closed: {closed_ct}   Filtered: {filt_ct}"
            ),
        )
        self._btn_start.configure(state="normal")
        self._btn_stop.configure(state="disabled", text_color=TEXT_SEC,
                                 hover_color="#1e2e3e")
        if self._all_results:
            self._btn_export.configure(state="normal", text_color=CLR_OPEN)
        self._open_lbl.configure(
            text=f"⬡  {open_ct}  OPEN" if open_ct else "",
        )
        self._set_status(
            f"Done  {self._meta.get('target', '')}  |  {done}/{total} scanned  |  "
            f"{open_ct} open  {filt_ct} filtered  in {elapsed:.1f}s",
        )

    def _on_scan_error(self, message: str) -> None:
        self._btn_start.configure(state="normal")
        self._btn_stop.configure(state="disabled", text_color=TEXT_SEC)
        messagebox.showerror("Scan Error", message)
        self._progress_lbl.configure(text="Scan failed — see error dialog.")
        self._set_status("Error during scan.")

    # ── Display filter ────────────────────────────────────────────────────

    def _passes_filter(self, result: ScanResult) -> bool:
        f = self._filter_var.get()
        if f == "Open Only":
            return result.status == "open"
        if f == "Open + Filtered":
            return result.status in ("open", "filtered")
        return True  # "All Results"

    def _on_filter_change(self, _value: str = "") -> None:
        for item in self._tree.get_children():
            self._tree.delete(item)
        for result in self._all_results:
            if self._passes_filter(result):
                self._insert_row(result)

    def _insert_row(self, result: ScanResult) -> None:
        idx = len(self._tree.get_children())
        tags: tuple[str, ...] = (result.status,)
        if idx % 2 == 1:
            tags = tags + ("alt",)

        self._tree.insert(
            "", "end",
            values=(
                result.host,
                result.port,
                result.status.upper(),
                result.service or "—",
                result.banner  or "—",
                f"{result.scan_time:.3f}",
            ),
            tags=tags,
        )

    # ── Export ────────────────────────────────────────────────────────────

    def _on_export(self) -> None:
        target_slug = self._meta.get("target", "scan").replace("/", "-")
        timestamp   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"netscan_{target_slug}_{timestamp}.json"

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=default_name,
            title="Export Scan Results",
        )
        if not path:
            return

        open_ct   = sum(1 for r in self._all_results if r.status == "open")
        closed_ct = sum(1 for r in self._all_results if r.status == "closed")
        filt_ct   = sum(1 for r in self._all_results if r.status == "filtered")

        data = {
            "scan_info": {
                **self._meta,
                "duration_seconds": round(time.monotonic() - self._scan_start, 2),
            },
            "results": [
                {
                    "host":      r.host,
                    "port":      r.port,
                    "status":    r.status,
                    "service":   r.service,
                    "banner":    r.banner,
                    "scan_time": r.scan_time,
                }
                for r in self._all_results
            ],
            "summary": {
                "total_hosts":         len({r.host for r in self._all_results}),
                "total_ports_scanned": len(self._all_results),
                "open":     open_ct,
                "closed":   closed_ct,
                "filtered": filt_ct,
            },
        }

        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
            messagebox.showinfo(
                "Export Complete",
                f"Results exported successfully.\n\n{path}",
            )
            self._set_status(f"Exported {len(self._all_results)} results → {path}")
        except OSError as exc:
            messagebox.showerror("Export Failed", str(exc))
