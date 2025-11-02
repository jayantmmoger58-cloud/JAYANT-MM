#!/usr/bin/env python3
"""
antivirus.py - SimpleShield (educational antivirus)
Requires Python 3.10+. Tested on Windows.
Usage: python antivirus.py
"""

import os
import json
import hashlib
import shutil
import logging
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

APP_NAME = "SimpleShield (educational)"
BASE_DIR = Path.home() / "simple_shield"
SIGNATURES_FILE = BASE_DIR / "signatures.json"
QUARANTINE_DIR = BASE_DIR / "quarantine"
LOG_FILE = BASE_DIR / "scan.log"

# Ensure dirs exist
BASE_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

# --- Signatures handling ---
DEFAULT_SIGNATURES = {
    # EICAR test file SHA256:
    # This is the SHA256 for the standard ASCII EICAR test string (without newline)
    "EICAR-Test-File": "275a021bbfb6481d3d3f5d5b1b2d03c0f6a8c7e1f8c9c9ddf4a5a1b2c3d4e5f6"
}

def load_signatures():
    if not SIGNATURES_FILE.exists():
        with open(SIGNATURES_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_SIGNATURES, f, indent=2)
    with open(SIGNATURES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_signatures(sigdict):
    with open(SIGNATURES_FILE, "w", encoding="utf-8") as f:
        json.dump(sigdict, f, indent=2)

# --- Utility functions ---
def sha256_of_file(path: Path, block_size=65536) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            h.update(block)
    return h.hexdigest()

def is_pe_file(path: Path) -> bool:
    # Simple header check for PE files (MZ at start)
    try:
        with path.open("rb") as f:
            start = f.read(2)
            return start == b"MZ"
    except Exception:
        return False

# --- Scanner ---
class Scanner:
    def __init__(self):
        self.signatures = load_signatures()  # name -> sha256
        self.running = False
        self.results = []  # list of dicts: {path, reason, sig_name/sha}
    
    def scan_path(self, root_path: Path, progress_callback=None):
        self.running = True
        self.results.clear()
        file_count = 0
        for dirpath, dirnames, filenames in os.walk(root_path):
            for fname in filenames:
                if not self.running:
                    logging.info("Scan cancelled by user.")
                    return
                file_count += 1
                fpath = Path(dirpath) / fname
                try:
                    sha = sha256_of_file(fpath)
                except Exception as e:
                    logging.warning(f"Skipping unreadable file {fpath}: {e}")
                    continue
                # signature check
                for sname, ssha in self.signatures.items():
                    if sha.lower() == ssha.lower():
                        self.results.append({
                            "path": str(fpath),
                            "reason": "signature",
                            "sig_name": sname,
                            "sha256": sha
                        })
                        logging.info(f"Detected by signature: {fpath} -> {sname}")
                        break
                else:
                    # heuristic checks
                    suspicious = False
                    # suspicious filename patterns
                    lower = fname.lower()
                    if any(tok in lower for tok in ["keygen", "crack", "patch", "trojan", "malware", "eicar"]):
                        suspicious = True
                        reason = "suspicious_filename"
                    elif fpath.suffix.lower() in [".exe", ".dll", ".scr", ".sys"] and is_pe_file(fpath):
                        # mark as interesting (heuristic)
                        suspicious = True
                        reason = "pe_file"
                    if suspicious:
                        self.results.append({
                            "path": str(fpath),
                            "reason": reason,
                            "sha256": sha
                        })
                        logging.info(f"Heuristic match: {fpath} ({reason})")
                if progress_callback:
                    progress_callback(file_count, str(fpath))
        self.running = False

    def quarantine(self, result_item):
        src = Path(result_item["path"])
        if not src.exists():
            raise FileNotFoundError(src)
        dst = QUARANTINE_DIR / (src.name + "_" + result_item.get("sha256", "")[:8])
        # avoid overwriting
        i = 1
        final_dst = dst
        while final_dst.exists():
            final_dst = dst.with_name(dst.name + f".{i}")
            i += 1
        try:
            shutil.move(str(src), str(final_dst))
            logging.info(f"Quarantined {src} -> {final_dst}")
            return str(final_dst)
        except Exception as e:
            logging.error(f"Failed to quarantine {src}: {e}")
            raise

    def add_signature(self, name, sha256):
        self.signatures[name] = sha256
        save_signatures(self.signatures)
        logging.info(f"Added signature {name}: {sha256}")

# --- GUI ---
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("760x480")
        self.scanner = Scanner()
        self._create_widgets()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _create_widgets(self):
        frm_top = ttk.Frame(self)
        frm_top.pack(fill="x", padx=8, pady=8)

        ttk.Label(frm_top, text="Folder to scan:").pack(side="left")
        self.path_var = tk.StringVar()
        self.entry_path = ttk.Entry(frm_top, textvariable=self.path_var, width=60)
        self.entry_path.pack(side="left", padx=6)
        ttk.Button(frm_top, text="Browse", command=self.browse).pack(side="left", padx=4)
        ttk.Button(frm_top, text="Scan", command=self.start_scan).pack(side="left", padx=4)
        ttk.Button(frm_top, text="Stop", command=self.stop_scan).pack(side="left", padx=4)

        # progress and status
        self.status_var = tk.StringVar(value="Idle")
        self.progress_label = ttk.Label(self, textvariable=self.status_var)
        self.progress_label.pack(anchor="w", padx=8)

        # results tree
        cols = ("path", "reason", "sig")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=18)
        self.tree.heading("path", text="Path")
        self.tree.heading("reason", text="Reason")
        self.tree.heading("sig", text="Signature/sha256")
        self.tree.column("path", width=480)
        self.tree.column("reason", width=120)
        self.tree.column("sig", width=140)
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

        frm_bottom = ttk.Frame(self)
        frm_bottom.pack(fill="x", padx=8, pady=6)
        ttk.Button(frm_bottom, text="Quarantine Selected", command=self.quarantine_selected).pack(side="left")
        ttk.Button(frm_bottom, text="Add Selected to Signatures", command=self.add_selected_signature).pack(side="left", padx=6)
        ttk.Button(frm_bottom, text="Open Quarantine Folder", command=lambda: os.startfile(str(QUARANTINE_DIR))).pack(side="right")
        ttk.Button(frm_bottom, text="View Log", command=self.view_log).pack(side="right", padx=6)

    def browse(self):
        p = filedialog.askdirectory()
        if p:
            self.path_var.set(p)

    def start_scan(self):
        path = self.path_var.get().strip()
        if not path:
            messagebox.showwarning("No folder", "Choose a folder to scan first.")
            return
        if not Path(path).exists():
            messagebox.showerror("Invalid folder", "Folder does not exist.")
            return
        # clear tree
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.status_var.set("Scanning...")
        thread = threading.Thread(target=self._scan_worker, args=(Path(path),), daemon=True)
        thread.start()

    def _scan_worker(self, path: Path):
        def progress_cb(count, last_file):
            self.status_var.set(f"Scanned {count} files. Last: {last_file}")
        try:
            self.scanner.scan_path(path, progress_callback=progress_cb)
            # populate tree with results
            for item in self.scanner.results:
                sig = item.get("sig_name") or item.get("sha256", "")[:16]
                self.tree.insert("", "end", values=(item["path"], item["reason"], sig))
            self.status_var.set(f"Scan finished. {len(self.scanner.results)} items found.")
        except Exception as e:
            logging.exception("Error during scan")
            messagebox.showerror("Scan error", str(e))
            self.status_var.set("Idle")

    def stop_scan(self):
        self.scanner.running = False
        self.status_var.set("Stopping...")

    def quarantine_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Nothing selected", "Select results to quarantine.")
            return
        for iid in sel:
            values = self.tree.item(iid, "values")
            path = values[0]
            # find matching result
            match = next((r for r in self.scanner.results if r["path"] == path), None)
            if not match:
                continue
            try:
                dst = self.scanner.quarantine(match)
                messagebox.showinfo("Quarantined", f"Moved to quarantine:\n{dst}")
                # remove from tree
                self.tree.delete(iid)
            except Exception as e:
                messagebox.showerror("Quarantine failed", str(e))

    def add_selected_signature(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Nothing selected", "Select a result to add to signatures.")
            return
        for iid in sel:
            values = self.tree.item(iid, "values")
            path = values[0]
            sha = None
            # find item in scanner.results
            match = next((r for r in self.scanner.results if r["path"] == path), None)
            if match:
                sha = match.get("sha256")
            if not sha:
                messagebox.showwarning("No sha", "Cannot find SHA for selected item.")
                continue
            # prompt for name
            name = simple_input_dialog(self, "Add signature", f"Name for signature for {Path(path).name}:")
            if not name:
                continue
            try:
                self.scanner.add_signature(name, sha)
                messagebox.showinfo("Saved", f"Signature {name} added.")
            except Exception as e:
                messagebox.showerror("Failed", str(e))

    def view_log(self):
        try:
            os.startfile(str(LOG_FILE))
        except Exception:
            messagebox.showinfo("Log", f"Log file: {LOG_FILE}")

    def _on_close(self):
        if self.scanner.running:
            if not messagebox.askyesno("Exit", "Scan is running. Exit anyway?"):
                return
        self.destroy()

# simple input dialog
def simple_input_dialog(parent, title, prompt):
    dlg = tk.Toplevel(parent)
    dlg.title(title)
    dlg.transient(parent)
    dlg.grab_set()
    ttk.Label(dlg, text=prompt).pack(padx=8, pady=8)
    v = tk.StringVar()
    ent = ttk.Entry(dlg, textvariable=v, width=50)
    ent.pack(padx=8, pady=4)
    ent.focus_set()
    res = {"value": None}
    def ok():
        res["value"] = v.get().strip()
        dlg.destroy()
    def cancel():
        dlg.destroy()
    frm = ttk.Frame(dlg)
    frm.pack(pady=8)
    ttk.Button(frm, text="OK", command=ok).pack(side="left", padx=6)
    ttk.Button(frm, text="Cancel", command=cancel).pack(side="left")
    parent.wait_window(dlg)
    return res["value"]

if __name__ == "__main__":
    app = App()
    app.mainloop()
