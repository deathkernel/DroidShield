from __future__ import annotations

import json
import threading
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .adb import AdbClient
from .report import html_report, markdown_report
from .scanner import scan_device
from .windows import list_adb_devices, windows_environment_report


BG = "#0B0F14"
PANEL = "#121820"
PANEL_2 = "#171F29"
TEXT = "#E8EEF5"
MUTED = "#8B9AA8"
ACCENT = "#59D6A5"
WARNING = "#F4C95D"
DANGER = "#FF6B6B"
INFO = "#6EA8FE"


class DroidShieldWindowsApp:
    """Desktop security console for the existing defensive scanner."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("DroidShield Security Console")
        self.root.geometry("1220x780")
        self.root.minsize(1000, 680)
        self.root.configure(bg=BG)

        self.report: dict | None = None
        self.scan_history: list[dict] = []
        self._scan_running = False

        self._configure_style()
        self._build_header()
        self._build_body()
        self.refresh()

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED)
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 24, "bold"))
        style.configure("Subtitle.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 10))
        style.configure("Card.TFrame", background=PANEL)
        style.configure("CardTitle.TLabel", background=PANEL, foreground=MUTED, font=("Segoe UI", 9, "bold"))
        style.configure("CardValue.TLabel", background=PANEL, foreground=TEXT, font=("Segoe UI", 20, "bold"))
        style.configure("TButton", background=PANEL_2, foreground=TEXT, padding=(12, 8), borderwidth=0)
        style.map("TButton", background=[("active", "#202B37")])
        style.configure("Accent.TButton", background=ACCENT, foreground="#08110D", font=("Segoe UI", 10, "bold"))
        style.map("Accent.TButton", background=[("active", "#77E6BE"), ("disabled", "#33463F")])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL_2, foreground=MUTED, padding=(16, 9))
        style.map("TNotebook.Tab", background=[("selected", PANEL)], foreground=[("selected", TEXT)])
        style.configure(
            "Treeview",
            background=PANEL,
            fieldbackground=PANEL,
            foreground=TEXT,
            rowheight=30,
            borderwidth=0,
        )
        style.configure("Treeview.Heading", background=PANEL_2, foreground=MUTED, relief="flat")
        style.map("Treeview", background=[("selected", "#24333D")], foreground=[("selected", TEXT)])
        style.configure("Horizontal.TProgressbar", troughcolor=PANEL_2, background=ACCENT, borderwidth=0)

    def _build_header(self) -> None:
        header = ttk.Frame(self.root, padding=(24, 20, 24, 12))
        header.pack(fill="x")

        left = ttk.Frame(header)
        left.pack(side="left")
        ttk.Label(left, text="DroidShield", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            left,
            text="Android defensive triage • Windows security console",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(2, 0))

        right = ttk.Frame(header)
        right.pack(side="right")
        self.connection_label = ttk.Label(right, text="● NO DEVICE", foreground=DANGER, background=BG)
        self.connection_label.pack(anchor="e")
        self.environment_label = ttk.Label(right, text="ADB: checking…", style="Muted.TLabel")
        self.environment_label.pack(anchor="e", pady=(4, 0))

    def _build_body(self) -> None:
        body = ttk.Frame(self.root, padding=(24, 0, 24, 20))
        body.pack(fill="both", expand=True)

        toolbar = ttk.Frame(body)
        toolbar.pack(fill="x", pady=(0, 12))

        self.device_var = tk.StringVar()
        self.device_combo = ttk.Combobox(
            toolbar,
            textvariable=self.device_var,
            state="readonly",
            width=28,
        )
        self.device_combo.pack(side="left")
        self.device_combo.bind("<<ComboboxSelected>>", lambda _event: self._device_changed())

        ttk.Button(toolbar, text="Refresh", command=self.refresh).pack(side="left", padx=(8, 0))
        self.scan_button = ttk.Button(
            toolbar,
            text="START DEEP SCAN",
            style="Accent.TButton",
            command=self.scan,
        )
        self.scan_button.pack(side="left", padx=(8, 0))
        self.hash_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(toolbar, text="Hash APKs", variable=self.hash_var).pack(side="left", padx=12)
        ttk.Button(toolbar, text="Save JSON", command=self.save_json).pack(side="right")
        ttk.Button(toolbar, text="Save HTML", command=self.save_html).pack(side="right", padx=(0, 8))
        ttk.Button(toolbar, text="Copy Summary", command=self.copy_summary).pack(side="right", padx=(0, 8))

        self.progress = ttk.Progressbar(body, mode="indeterminate", style="Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(0, 12))

        cards = ttk.Frame(body)
        cards.pack(fill="x", pady=(0, 14))
        self.card_device = self._card(cards, "DEVICE", "—")
        self.card_risk = self._card(cards, "RISK", "—")
        self.card_findings = self._card(cards, "FINDINGS", "—")
        self.card_apps = self._card(cards, "ANALYZED APPS", "—")
        self.card_confidence = self._card(cards, "CONFIDENCE", "—")
        for card in (self.card_device, self.card_risk, self.card_findings, self.card_apps, self.card_confidence):
            card.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.card_confidence.pack_configure(padx=0)

        self.notebook = ttk.Notebook(body)
        self.notebook.pack(fill="both", expand=True)

        self.dashboard_tab = ttk.Frame(self.notebook)
        self.findings_tab = ttk.Frame(self.notebook)
        self.apps_tab = ttk.Frame(self.notebook)
        self.evidence_tab = ttk.Frame(self.notebook)
        self.history_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Overview")
        self.notebook.add(self.findings_tab, text="Findings")
        self.notebook.add(self.apps_tab, text="Packages")
        self.notebook.add(self.evidence_tab, text="Evidence")
        self.notebook.add(self.history_tab, text="History")

        self._build_overview()
        self._build_findings()
        self._build_packages()
        self._build_evidence()
        self._build_history()

        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(body, textvariable=self.status_var, style="Muted.TLabel").pack(fill="x", pady=(8, 0))

    def _card(self, parent: ttk.Frame, title: str, value: str) -> ttk.Frame:
        card = ttk.Frame(parent, style="Card.TFrame", padding=(16, 12))
        ttk.Label(card, text=title, style="CardTitle.TLabel").pack(anchor="w")
        value_label = ttk.Label(card, text=value, style="CardValue.TLabel")
        value_label.pack(anchor="w", pady=(4, 0))
        card.value_label = value_label  # type: ignore[attr-defined]
        return card

    def _set_card(self, card: ttk.Frame, value: str) -> None:
        card.value_label.configure(text=value)  # type: ignore[attr-defined]

    def _build_overview(self) -> None:
        tab = self.dashboard_tab
        top = ttk.Frame(tab, padding=16)
        top.pack(fill="both", expand=True)

        self.verdict = tk.Text(
            top,
            height=8,
            bg=PANEL,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            padx=14,
            pady=12,
            wrap="word",
        )
        self.verdict.pack(fill="x", pady=(0, 12))
        self.verdict.configure(state="disabled")

        lower = ttk.Frame(top)
        lower.pack(fill="both", expand=True)

        hardening_frame = ttk.Frame(lower, style="Panel.TFrame", padding=14)
        hardening_frame.pack(side="left", fill="both", expand=True, padx=(0, 6))
        ttk.Label(hardening_frame, text="HARDENING RECOMMENDATIONS", foreground=MUTED, background=PANEL,
                  font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.hardening = tk.Listbox(
            hardening_frame,
            bg=PANEL,
            fg=TEXT,
            selectbackground="#24333D",
            relief="flat",
            highlightthickness=0,
        )
        self.hardening.pack(fill="both", expand=True, pady=(8, 0))

        security_frame = ttk.Frame(lower, style="Panel.TFrame", padding=14)
        security_frame.pack(side="left", fill="both", expand=True, padx=(6, 0))
        ttk.Label(security_frame, text="SECURITY STATE", foreground=MUTED, background=PANEL,
                  font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.security_text = tk.Text(
            security_frame,
            bg=PANEL,
            fg=TEXT,
            relief="flat",
            wrap="word",
            padx=8,
            pady=8,
        )
        self.security_text.pack(fill="both", expand=True, pady=(8, 0))
        self.security_text.configure(state="disabled")

    def _build_findings(self) -> None:
        tab = self.findings_tab
        paned = ttk.Panedwindow(tab, orient="vertical")
        paned.pack(fill="both", expand=True, padx=10, pady=10)

        upper = ttk.Frame(paned)
        lower = ttk.Frame(paned)
        paned.add(upper, weight=3)
        paned.add(lower, weight=2)

        columns = ("severity", "title", "package", "evidence")
        self.findings = ttk.Treeview(upper, columns=columns, show="headings")
        headings = {"severity": "Severity", "title": "Finding", "package": "Package", "evidence": "Evidence"}
        widths = {"severity": 90, "title": 330, "package": 260, "evidence": 120}
        for column in columns:
            self.findings.heading(column, text=headings[column])
            self.findings.column(column, width=widths[column], anchor="w")
        self.findings.pack(fill="both", expand=True)
        self.findings.bind("<<TreeviewSelect>>", self._finding_selected)

        self.finding_detail = self._detail_text(lower)
        self.findings.tag_configure("HIGH", foreground=DANGER)
        self.findings.tag_configure("MEDIUM", foreground=WARNING)
        self.findings.tag_configure("LOW", foreground=ACCENT)

    def _build_packages(self) -> None:
        tab = self.apps_tab
        paned = ttk.Panedwindow(tab, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=10, pady=10)

        left = ttk.Frame(paned)
        right = ttk.Frame(paned)
        paned.add(left, weight=3)
        paned.add(right, weight=2)

        columns = ("package", "version", "installer", "assessment")
        action_bar = ttk.Frame(left)
        action_bar.pack(fill="x", pady=(0, 6))
        ttk.Label(action_bar, text="PACKAGE INVESTIGATION", foreground=MUTED, background=BG, font=("Segoe UI", 9, "bold")).pack(side="left")
        ttk.Button(action_bar, text="Investigate Selected", command=self._investigate_selected).pack(side="right")

        self.packages = ttk.Treeview(left, columns=columns, show="headings")
        for column, title, width in (
            ("package", "Package", 280),
            ("version", "Version", 130),
            ("installer", "Installer", 180),
            ("assessment", "Assessment", 110),
        ):
            self.packages.heading(column, text=title)
            self.packages.column(column, width=width, anchor="w")
        self.packages.pack(fill="both", expand=True)
        self.packages.bind("<<TreeviewSelect>>", self._package_selected)

        self.package_detail = self._detail_text(right)

    def _build_evidence(self) -> None:
        tab = self.evidence_tab
        frame = ttk.Frame(tab, padding=14)
        frame.pack(fill="both", expand=True)

        self.evidence_text = self._detail_text(frame)
        ttk.Button(frame, text="Open Evidence Folder", command=self.open_evidence_folder).pack(
            anchor="e", pady=(8, 0)
        )

    def _build_history(self) -> None:
        tab = self.history_tab
        frame = ttk.Frame(tab, padding=10)
        frame.pack(fill="both", expand=True)

        columns = ("time", "device", "risk", "findings")
        self.history = ttk.Treeview(frame, columns=columns, show="headings")
        for column, title, width in (
            ("time", "Time", 180),
            ("device", "Device", 250),
            ("risk", "Risk", 120),
            ("findings", "Findings", 100),
        ):
            self.history.heading(column, text=title)
            self.history.column(column, width=width)
        self.history.pack(fill="both", expand=True)

    def _detail_text(self, parent: ttk.Frame) -> tk.Text:
        widget = tk.Text(
            parent,
            bg=PANEL,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            wrap="word",
            padx=12,
            pady=12,
        )
        widget.pack(fill="both", expand=True)
        widget.configure(state="disabled")
        return widget

    def _write_text(self, widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def _device_changed(self) -> None:
        serial = self.device_var.get()
        if serial:
            self.status_var.set(f"Selected device: {serial}")
            self.connection_label.configure(text="● DEVICE READY", foreground=ACCENT)

    def refresh(self) -> None:
        self.status_var.set("Refreshing ADB devices and Windows capabilities…")
        try:
            report = windows_environment_report()
            devices = list_adb_devices()
        except Exception as exc:
            self.environment_label.configure(text="ADB: unavailable")
            self.connection_label.configure(text="● ADB ERROR", foreground=DANGER)
            self.device_combo["values"] = ()
            self._write_text(self.security_text, f"ADB error:\n{exc}")
            self.status_var.set("ADB refresh failed.")
            return

        serials = [serial for serial, state in devices if state == "device"]
        self.device_combo["values"] = serials
        if self.device_var.get() not in serials:
            self.device_var.set(serials[0] if serials else "")

        if serials:
            self.connection_label.configure(text=f"● {len(serials)} DEVICE{'S' if len(serials) != 1 else ''}", foreground=ACCENT)
        else:
            self.connection_label.configure(text="● NO DEVICE", foreground=DANGER)
        self.environment_label.configure(
            text=f"ADB: {report['adb'] or 'not found'}  •  Python {report['python']}"
        )
        self.status_var.set(f"Ready. {len(serials)} authorized device(s) detected.")

    def _selected_serial(self) -> str | None:
        value = self.device_var.get().strip()
        return value or None

    def scan(self) -> None:
        serial = self._selected_serial()
        if not serial:
            messagebox.showwarning("DroidShield", "Select an authorized ADB device first.")
            return
        if self._scan_running:
            return

        self._scan_running = True
        self.scan_button.configure(state="disabled")
        self.progress.start(12)
        self.status_var.set(f"Running deep read-only scan on {serial}…")
        self._write_text(self.verdict, "SCAN IN PROGRESS\n\nDroidShield is collecting device, package, permission, component, runtime and security evidence.")
        threading.Thread(
            target=self._scan_worker,
            args=(serial, self.hash_var.get()),
            daemon=True,
        ).start()

    def _scan_worker(self, serial: str, hash_apks: bool) -> None:
        try:
            report = scan_device(AdbClient(), serial, hash_apks=hash_apks)
            self.root.after(0, lambda: self._scan_complete(report))
        except Exception as exc:
            self.root.after(0, lambda: self._scan_failed(str(exc)))

    def _scan_complete(self, report: dict) -> None:
        self._scan_running = False
        self.progress.stop()
        self.scan_button.configure(state="normal")
        self.report = report
        self._render_report(report)

        risk = report.get("risk", {})
        device = report.get("device", {})
        findings = report.get("findings", [])
        coverage = report.get("metadata_coverage", {})
        self.scan_history.append({
            "time": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S"),
            "device": device.get("serial", "unknown"),
            "risk": f"{risk.get('level', 'UNKNOWN')} ({risk.get('score', '?')}/100)",
            "findings": len(findings),
            "report": report,
        })
        self._render_history()
        self.status_var.set(
            f"Scan complete • {len(findings)} finding(s) • "
            f"{coverage.get('packages_analyzed', 0)} package(s) analyzed"
        )

    def _render_report(self, report: dict) -> None:
        risk = report.get("risk", {})
        device = report.get("device", {})
        findings = report.get("findings", [])
        coverage = report.get("metadata_coverage", {})

        level = str(risk.get("level", "UNKNOWN"))
        score = risk.get("score", "—")
        confidence = risk.get("confidence", "—")
        self._set_card(self.card_device, str(device.get("model") or device.get("serial") or "—"))
        self._set_card(self.card_risk, f"{level} {score}/100")
        self._set_card(self.card_findings, str(len(findings)))
        self._set_card(self.card_apps, str(coverage.get("packages_analyzed", 0)))
        self._set_card(self.card_confidence, str(confidence).upper())

        verdict = (
            f"SCAN COMPLETE  •  {level} ({score}/100)\n"
            f"Device: {device.get('manufacturer', '')} {device.get('model', '')}\n"
            f"Android: {device.get('android', 'unknown')}  •  Patch: {device.get('security_patch', 'unknown')}\n"
            f"Findings: {len(findings)}  •  Analysis confidence: {confidence}\n\n"
            "Risk is heuristic evidence, not a malware verdict. Review the finding evidence and provenance before remediation."
        )
        self._write_text(self.verdict, verdict)

        self.hardening.delete(0, "end")
        for item in report.get("hardening", []):
            self.hardening.insert("end", f"• {item}")

        security = report.get("security", {})
        self._write_text(self.security_text, json.dumps(security, indent=2, ensure_ascii=False))
        self._render_findings(findings)
        self._render_packages(report)
        self._render_evidence(report)

    def _render_findings(self, findings: list[dict]) -> None:
        for item in self.findings.get_children():
            self.findings.delete(item)
        for index, finding in enumerate(findings):
            severity = str(finding.get("severity", "UNKNOWN"))
            evidence = finding.get("evidence") or {}
            self.findings.insert(
                "",
                "end",
                iid=f"finding-{index}",
                values=(
                    severity,
                    finding.get("title", "Untitled finding"),
                    finding.get("package", "—") or "—",
                    evidence.get("evidence_quality", "—"),
                ),
                tags=(severity,),
            )
        self._write_text(
            self.finding_detail,
            "Select a finding to inspect its evidence, signals, and recommended review path.",
        )

    def _render_packages(self, report: dict) -> None:
        for item in self.packages.get_children():
            self.packages.delete(item)
        packages = report.get("package_metadata", [])
        assessments = {
            item.get("package"): item
            for item in report.get("package_assessments", [])
            if isinstance(item, dict)
        }
        if isinstance(packages, dict):
            packages = list(packages.values())
        for index, package in enumerate(packages):
            name = package.get("package", "unknown")
            assessment = assessments.get(name, {})
            self.packages.insert(
                "",
                "end",
                iid=f"package-{index}",
                values=(
                    name,
                    package.get("version_name") or package.get("version_code") or "—",
                    package.get("installer_package") or "—",
                    assessment.get("level", "—"),
                ),
            )
            self.packages.item(f"package-{index}", tags=(assessment.get("level", "—"),))
        self.packages.tag_configure("HIGH", foreground=DANGER)
        self.packages.tag_configure("MEDIUM", foreground=WARNING)
        self.packages.tag_configure("LOW", foreground=ACCENT)

    def _render_evidence(self, report: dict) -> None:
        payload = {
            "schema_version": report.get("schema_version"),
            "timestamp": report.get("timestamp"),
            "metadata_coverage": report.get("metadata_coverage"),
            "permission_summary": report.get("permission_summary"),
            "collection_errors": report.get("metadata_coverage", {}).get("collection_errors", []),
            "risk_signals": report.get("risk", {}).get("signals", []),
        }
        self._write_text(self.evidence_text, json.dumps(payload, indent=2, ensure_ascii=False))

    def _finding_selected(self, _event=None) -> None:
        selected = self.findings.selection()
        if not selected or not self.report:
            return
        index = int(selected[0].split("-")[-1])
        findings = self.report.get("findings", [])
        if index >= len(findings):
            return
        finding = findings[index]
        self._write_text(self.finding_detail, json.dumps(finding, indent=2, ensure_ascii=False))
        self.notebook.select(self.findings_tab)

    def _package_selected(self, _event=None) -> None:
        selected = self.packages.selection()
        if not selected or not self.report:
            return
        index = int(selected[0].split("-")[-1])
        packages = self.report.get("package_metadata", [])
        if isinstance(packages, dict):
            packages = list(packages.values())
        if index >= len(packages):
            return
        self._write_text(self.package_detail, self._package_investigation(packages[index]))

    def _package_investigation(self, package: dict) -> str:
        if not self.report:
            return "No scan report loaded."
        name = package.get("package", "unknown")
        assessments = {item.get("package"): item for item in self.report.get("package_assessments", []) if isinstance(item, dict)}
        assessment = assessments.get(name, {})
        permission = package.get("permission_intelligence", {}) or {}
        graph = self.report.get("component_graph", {}) or {}
        node = next((item for item in graph.get("nodes", []) if item.get("package") == name), {})
        runtime = self.report.get("runtime", {}).get("intelligence", {}) or {}
        processes = [item for item in runtime.get("attributed_processes", []) if item.get("package") == name]
        network = self.report.get("network", {}).get("intelligence", {}) or {}
        sockets = [item for item in network.get("socket_attribution", []) if item.get("package") == name]
        related_findings = [item for item in self.report.get("findings", []) if item.get("package") == name]
        explain = next((item for item in self.report.get("explainability", {}).get("packages", []) if item.get("package") == name), None)
        payload = {
            "package": name,
            "provenance": {
                "installer_package": package.get("installer_package"),
                "first_install_time": package.get("first_install_time"),
                "last_update_time": package.get("last_update_time"),
                "apk_paths": package.get("apk_paths", []),
                "apk_sha256": package.get("apk_sha256", {}),
                "system_path_evidence": package.get("system_path_evidence", False),
                "system_flag_evidence": package.get("system_flag_evidence", False),
            },
            "assessment": assessment,
            "permissions": permission,
            "active_roles": package.get("active_roles", []),
            "components": node.get("components", package.get("component_details", {})),
            "runtime": {"process_count": len(processes), "processes": processes},
            "network": {"socket_count": len(sockets), "sockets": sockets},
            "related_findings": related_findings,
            "explainability": explain,
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    def _investigate_selected(self) -> None:
        selected = self.packages.selection()
        if not selected or not self.report:
            messagebox.showinfo("DroidShield", "Select a package first.")
            return
        index = int(selected[0].split("-")[-1])
        packages = self.report.get("package_metadata", [])
        if isinstance(packages, dict):
            packages = list(packages.values())
        if index >= len(packages):
            return
        self._write_text(self.package_detail, self._package_investigation(packages[index]))
        self.notebook.select(self.apps_tab)
        self.status_var.set(f"Investigating package: {packages[index].get('package', 'unknown')}")

    def _render_history(self) -> None:
        for item in self.history.get_children():
            self.history.delete(item)
        for index, entry in enumerate(reversed(self.scan_history)):
            self.history.insert(
                "",
                "end",
                iid=f"history-{index}",
                values=(entry["time"], entry["device"], entry["risk"], entry["findings"]),
            )

    def save_json(self) -> None:
        if not self.report:
            messagebox.showinfo("DroidShield", "Run a scan before exporting a report.")
            return
        path = filedialog.asksaveasfilename(
            title="Save DroidShield JSON report",
            defaultextension=".json",
            filetypes=[("JSON report", "*.json")],
        )
        if not path:
            return
        Path(path).write_text(json.dumps(self.report, indent=2, ensure_ascii=False), encoding="utf-8")
        self.status_var.set(f"JSON report saved: {path}")

    def save_html(self) -> None:
        if not self.report:
            messagebox.showinfo("DroidShield", "Run a scan before exporting a report.")
            return
        path = filedialog.asksaveasfilename(
            title="Save DroidShield HTML report",
            defaultextension=".html",
            filetypes=[("HTML report", "*.html")],
        )
        if not path:
            return
        Path(path).write_text(html_report(self.report), encoding="utf-8")
        self.status_var.set(f"HTML report saved: {path}")

    def copy_summary(self) -> None:
        if not self.report:
            messagebox.showinfo("DroidShield", "Run a scan before copying a summary.")
            return
        risk = self.report.get("risk", {})
        device = self.report.get("device", {})
        summary = (
            f"DroidShield scan\\n"
            f"Device: {device.get('manufacturer', '')} {device.get('model', '')}\\n"
            f"Risk: {risk.get('level', 'UNKNOWN')} ({risk.get('score', '?')}/100)\\n"
            f"Confidence: {risk.get('confidence', 'unknown')}\\n"
            f"Findings: {len(self.report.get('findings', []))}"
        )
        self.root.clipboard_clear()
        self.root.clipboard_append(summary)
        self.status_var.set("Scan summary copied to clipboard.")

    def open_evidence_folder(self) -> None:
        evidence = Path.cwd() / "evidence"
        evidence.mkdir(parents=True, exist_ok=True)
        try:
            import os
            os.startfile(evidence)  # type: ignore[attr-defined]
        except OSError as exc:
            messagebox.showerror("DroidShield", f"Could not open evidence folder:\\n{exc}")

    def _scan_failed(self, error: str) -> None:
        self._scan_running = False
        self.progress.stop()
        self.scan_button.configure(state="normal")
        self.status_var.set("Scan failed.")
        self._write_text(self.verdict, f"SCAN FAILED\\n\\n{error}")
        messagebox.showerror("DroidShield scan", error)


def launch() -> None:
    root = tk.Tk()
    DroidShieldWindowsApp(root)
    root.mainloop()


if __name__ == "__main__":
    launch()
