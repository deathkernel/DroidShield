from __future__ import annotations

import json
import tkinter as tk
from tkinter import messagebox, ttk

from .windows import list_adb_devices, windows_environment_report


class DroidShieldWindowsApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("DroidShield - Windows")
        self.root.geometry("760x500")
        self.root.minsize(680, 420)

        frame = ttk.Frame(root, padding=16)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="DroidShield", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(
            frame,
            text="Android defensive triage • Windows edition",
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(0, 14))

        actions = ttk.Frame(frame)
        actions.pack(fill="x", pady=(0, 12))
        ttk.Button(actions, text="Refresh", command=self.refresh).pack(side="left")
        ttk.Button(actions, text="Copy Report", command=self.copy_report).pack(side="left", padx=8)

        columns = ("serial", "state")
        self.devices = ttk.Treeview(frame, columns=columns, show="headings", height=8)
        self.devices.heading("serial", text="ADB Serial")
        self.devices.heading("state", text="State")
        self.devices.column("serial", width=430)
        self.devices.column("state", width=180)
        self.devices.pack(fill="x")

        self.status = tk.Text(frame, height=14, wrap="word")
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
            self._write_status(f"ADB: {exc}\n\n")
        summary = {
            "platform": report["platform"],
            "python": report["python"],
            "architecture": report["architecture"],
            "adb": report["adb"] or "NOT FOUND",
            "devices": devices,
            "tools": report["tools"],
        }
        self._write_status(json.dumps(summary, indent=2))

    def copy_report(self) -> None:
        text = self.status.get("1.0", "end-1c")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("DroidShield", "Environment report copied to clipboard.")


def launch() -> None:
    root = tk.Tk()
    DroidShieldWindowsApp(root)
    root.mainloop()
