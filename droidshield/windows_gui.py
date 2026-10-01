from __future__ import annotations

import json
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .scanner import scan_device
from .windows import list_adb_devices, windows_environment_report
from .adb import AdbClient


class DroidShieldWindowsApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("DroidShield - Windows")
        self.root.geometry("900x650")
        self.root.minsize(760, 520)
        self.report: dict | None = None

        frame = ttk.Frame(root, padding=16)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="DroidShield", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(frame, text="Android defensive triage • Windows edition").pack(anchor="w", pady=(0, 12))

        actions = ttk.Frame(frame)
        actions.pack(fill="x", pady=(0, 10))
        ttk.Button(actions, text="Refresh", command=self.refresh).pack(side="left")
        self.scan_button = ttk.Button(actions, text="Scan Device", command=self.scan)
        self.scan_button.pack(side="left", padx=8)
        ttk.Button(actions, text="Copy Report", command=self.copy_report).pack(side="left")

        columns = ("serial", "state")
        self.devices = ttk.Treeview(frame, columns=columns, show="headings", height=7)
        self.devices.heading("serial", text="ADB Serial")
        self.devices.heading("state", text="State")
        self.devices.column("serial", width=520)
        self.devices.column("state", width=180)
        self.devices.pack(fill="x")

        self.status = tk.Text(frame, height=22, wrap="word")
        self.status.pack(fill="both", expand=True, pady=(12, 0))
        self.status.configure(state="disabled")
        self.refresh()

    def _write_status(self, value: str) -> None:
        self.status.configure(state="normal")
        self.status.delete("1.0", "end")
        self.status.insert("1.0", value)
        self.status.configure(state="disabled")

    def refresh(self) -> None:
        for item in self.devices.get_children():
            self.devices.delete(item)
        report = windows_environment_report()
        try:
            devices = list_adb_devices()
            for serial, state in devices:
                self.devices.insert("", "end", values=(serial, state))
        except RuntimeError as exc:
            devices = []
            self._write_status(f"ADB: {exc}\n")
        summary = {
            "platform": report["platform"],
            "python": report["python"],
            "architecture": report["architecture"],
            "adb": report["adb"] or "NOT FOUND",
            "devices": devices,
            "tools": report["tools"],
        }
        self._write_status(json.dumps(summary, indent=2))

    def _selected_serial(self) -> str | None:
        selected = self.devices.selection()
        if not selected:
            return None
        return str(self.devices.item(selected[0], "values")[0])

    def scan(self) -> None:
        serial = self._selected_serial()
        if not serial:
            messagebox.showwarning("DroidShield", "Select an authorized ADB device first.")
            return
        self.scan_button.configure(state="disabled")
        self._write_status("Running read-only device scan...\nPlease wait.")
        threading.Thread(target=self._scan_worker, args=(serial,), daemon=True).start()

    def _scan_worker(self, serial: str) -> None:
        try:
            report = scan_device(AdbClient(), serial, hash_apks=False)
            self.root.after(0, lambda: self._scan_complete(report))
        except Exception as exc:
            self.root.after(0, lambda: self._scan_failed(str(exc)))

    def _scan_complete(self, report: dict) -> None:
        self.report = report
        summary = {
            "device": report.get("device"),
            "risk": report.get("risk"),
            "findings": report.get("findings", []),
            "hardening": report.get("hardening", []),
            "metadata_coverage": report.get("metadata_coverage"),
        }
        self._write_status(json.dumps(summary, indent=2))
        self.scan_button.configure(state="normal")

    def _scan_failed(self, error: str) -> None:
        self._write_status(f"Scan failed:\n{error}")
        self.scan_button.configure(state="normal")
        messagebox.showerror("DroidShield scan", error)

    def copy_report(self) -> None:
        text = self.status.get("1.0", "end-1c")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("DroidShield", "Current report copied to clipboard.")


def launch() -> None:
    root = tk.Tk()
    DroidShieldWindowsApp(root)
    root.mainloop()
