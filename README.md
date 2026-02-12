# T.I.T.A.N.
## Taylor's Interactive Tool for Attack Navigation
T.I.T.A.N. is a centralized credential management and protocol dispatcher designed for rapid lateral movement and security auditing. It synchronizes target data between a rich GUI interface and a lightweight, arrow-key-driven CLI.

## 🛠 Features
Dual-Interface Support: Switch between a Tkinter GUI and a Curses-based CLI seamlessly.

Centralized Database: All targets, hostnames, and credentials (passwords or NT hashes) are stored in targets.json.

Smart Protocol Auditing: Verification of access across Evil-WinRM, SMB, SecretsDump, Psexec, WMI, and RDP.

Error Correction: Custom keyword scanning to detect failures (like DNS issues or Access Denied) that tools often mask with successful exit codes.

Session Logging: Every launch and audit attempt is timestamped in titan_history.log.

## 🖥 The Tools
### 1. T.I.T.A.N. GUI (TITAN-GUI.py)
The primary workstation interface for data entry and mass importing.

Ingestion: Add targets and credentials manually or import from Mimikatz/Secret dumps.

Dispatcher: One-click launch into dedicated terminal windows.

Visual Feedback: Buttons turn Green on successful protocol tests and Red on failure.

### 2. T.I.T.A.N. CLI (TITAN-CLI.py)
The "Operator Edition" for SSH sessions and headless environments.

Navigation: Fully interactive menu system using Arrow Keys.

Speed: Optimized for fast selection and dispatch without leaving the terminal.

Audit Mode: Run protocol checks on a target directly from the command line.

## 🚀 Installation & Setup
Prerequisites
Ensure you have the standard suite of Impacket tools and Evil-WinRM installed:

Bash
<pre>sudo apt update && sudo apt install impacket-scripts evil-winrm xfreerdp3 -y</pre>
Directory Structure
Per system requirements, ensure the targets.json file remains in the root project folder:

<pre>
~/TITAN/
├── TITAN-GUI.py
├── TITAN-CLI.py
├── targets.json      # Shared Database
└── titan_history.log # Centralized Logs
</pre>

### Quick-Launch Alias
Add the following to your ~/.zshrc to launch the tools from anywhere:

Bash
<pre>alias titan='python3 ~/TITAN/TITAN-GUI.py'
alias titan-cli='python3 ~/TITAN/TITAN-CLI.py'
source ~/.zshrc.</pre>

📖 Usage
Add Target: Use the GUI to input the IP and Hostname.

Add Credentials: Input a username and either a plaintext password or an NT hash.

Audit: Hit "Test All Tools" to see which protocols are accessible.

Dispatch: Select your tool of choice and launch into the target.

Note: This tool is intended for authorized security testing only. Log all actions responsibly via the built-in history file.

# **TO DO**

I want to add a kerberos Golden Ticket generator if a secretsdump was successful

Upload Secrets Dump or krbtgt hash and it will:
  1) Get KRBTGT Hash
  2) Get Domain SID
  3) Run Impacket-Ticketer
  4) Export ticket locally
  5) attempt to pop into computer with PSExec or WMIExec or something
