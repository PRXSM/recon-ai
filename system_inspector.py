"""
system_inspector.py — Phase 8
The System Inspector looks inward at the user's own machine.
It checks three things:
1. Running processes — anything suspicious?
2. Startup items — anything that shouldn't be there?
3. Recent system file changes — anything modified unexpectedly?

This tool NEVER modifies, deletes, or quarantines anything.
It observes and reports only.
Recon AI advises. The user decides.
"""

import os
import subprocess
import platform
import plistlib
import logging
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

SUSPICIOUS_PROCESSES = [
    "netcat",
    "ncat",
    "msfconsole",
    "msfvenom",
    "mimikatz",
    "cobaltstrike",
    "xmrig",
    "minerd",
    "cpuminer",
    "ngrok",
    "frp",
    "chisel",
    "revsocks",
    "ligolo",
    "empire",
    "covenant",
]

SUSPICIOUS_PROCESS_DESCRIPTIONS = {
    "netcat": "Netcat is a networking tool often used by attackers to create backdoors and reverse shells.",
    "nc": "Netcat is a networking tool often used by attackers to create backdoors.",
    "ncat": "Ncat is a networking tool often used for reverse shells and backdoors.",
    "msfconsole": "Metasploit Framework — a professional penetration testing tool. Should not be running on a personal machine.",
    "msfvenom": "Metasploit payload generator. Should not be running on a personal machine.",
    "metasploit": "Metasploit is a penetration testing framework. Concerning if you didn't install it.",
    "mimikatz": "Mimikatz is a credential theft tool used by attackers to steal passwords.",
    "xmrig": "XMRig is a Monero cryptocurrency miner. Often installed by malware without your knowledge.",
    "minerd": "A cryptocurrency mining daemon. Often installed by malware to use your CPU.",
    "monero": "Monero mining software detected. Your CPU may be being used to mine cryptocurrency.",
    "cpuminer": "CPU mining software. Your computer may be mining cryptocurrency without your consent.",
    "ngrok": "Ngrok creates tunnels to your machine. Legitimate tool but also used by attackers for remote access.",
    "cryptominer": "Cryptocurrency mining software. Often installed silently by malware.",
    "cobaltstrike": "Cobalt Strike is an advanced attack framework used by sophisticated attackers.",
    "empire": "PowerShell Empire is an attack framework. Should not be running on a personal machine.",
}

MACOS_STARTUP_PATHS = [
    "~/Library/LaunchAgents",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "/System/Library/LaunchAgents",
    "/System/Library/LaunchDaemons",
]

WINDOWS_STARTUP_PATHS = [
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    r"C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
]

LINUX_STARTUP_PATHS = [
    "/etc/init.d",
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "~/.config/autostart",
]

SENSITIVE_PATHS = [
    "/etc",
    "/usr/bin",
    "/usr/local/bin",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
]


def scan_processes():
    """
    Scan running processes and flag anything matching SUSPICIOUS_PROCESSES.
    Uses 'ps aux' on macOS/Linux and 'tasklist /FO CSV' on Windows.
    Exact binary name matching only — no partial matching.
    Returns flagged processes plus total count.
    """
    flagged = []
    total_scanned = 0
    is_windows = platform.system().lower() == "windows"

    try:
        if is_windows:
            result = subprocess.run(
                ["tasklist", "/FO", "CSV"],
                capture_output=True,
                text=True,
                timeout=10
            )
            lines = result.stdout.strip().splitlines()
            # Skip header line
            for line in lines[1:]:
                total_scanned += 1
                # CSV format: "Image Name","PID","Session Name","Session#","Mem Usage"
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) < 2:
                    continue
                binary_name = parts[0].lower()
                # Strip .exe suffix for matching
                if binary_name.endswith(".exe"):
                    binary_name = binary_name[:-4]
                pid = parts[1]

                for suspect in SUSPICIOUS_PROCESSES:
                    if binary_name == suspect.lower():
                        description = SUSPICIOUS_PROCESS_DESCRIPTIONS.get(
                            suspect.lower(),
                            f"'{suspect}' was found in a running process. This may warrant investigation."
                        )
                        flagged.append({
                            "name": binary_name,
                            "pid": pid,
                            "command": binary_name,
                            "risk": "HIGH",
                            "description": description,
                            "severity": "HIGH",
                        })
                        break

        else:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=10
            )
            lines = result.stdout.strip().splitlines()
            # Skip header line
            for line in lines[1:]:
                total_scanned += 1
                parts = line.split(None, 10)
                if len(parts) < 11:
                    continue
                pid = parts[1]
                command = parts[10].strip()
                binary = command.split()[0] if command else ""
                binary_name = os.path.basename(binary).lower()

                for suspect in SUSPICIOUS_PROCESSES:
                    if binary_name == suspect.lower():
                        description = SUSPICIOUS_PROCESS_DESCRIPTIONS.get(
                            suspect.lower(),
                            f"'{suspect}' was found in a running process. This may warrant investigation."
                        )
                        flagged.append({
                            "name": binary_name,
                            "pid": pid,
                            "command": command[:200],
                            "risk": "HIGH",
                            "description": description,
                            "severity": "HIGH",
                        })
                        break

    except Exception as e:
        logger.error(f"Process scan failed: {e}")

    return {
        "flagged": flagged,
        "total_scanned": total_scanned,
        "clean": len(flagged) == 0,
    }


def _describe_startup_item(name, program, label):
    """
    Generate a plain English description of a startup item
    based on its name, program path, and label.
    No external calls — offline only.
    """
    n = name.lower()
    p = program.lower() if program else ""

    if "apple" in n or "/system/library" in p or "/usr/libexec" in p or "/usr/sbin" in p or "/usr/bin" in p:
        return "This is a built-in macOS system service. It is part of your operating system and is safe."

    if "com.apple." in n:
        return "This is an Apple system service that runs at startup. It is part of macOS and is safe."

    if "logi" in n or "logitech" in n or "logi" in p:
        return "This is Logitech software — likely for your Logitech mouse or keyboard. Safe if you use Logitech devices."

    if "wireshark" in n or "chmodbpf" in n or "wireshark" in p:
        return "This is a Wireshark network tool helper. It runs at startup to enable packet capture. Safe if you installed Wireshark."

    if "microsoft" in n or "microsoft" in p:
        return "This is a Microsoft service — likely for Office, OneDrive, or Teams. Safe if you use Microsoft software."

    if "google" in n or "google" in p:
        return "This is a Google service — likely for Chrome or Google Drive. Safe if you use Google software."

    if "adobe" in n or "adobe" in p:
        return "This is an Adobe service — likely for Creative Cloud or Acrobat. Safe if you use Adobe software."

    if "dropbox" in n or "dropbox" in p:
        return "This is Dropbox. It starts automatically to keep your files synced. Safe if you installed Dropbox."

    if "spotify" in n or "spotify" in p:
        return "This is Spotify. It may start automatically to speed up launch time. Safe if you installed Spotify."

    if "docker" in n or "docker" in p:
        return "This is Docker. It starts automatically to manage containers. Safe if you use Docker."

    if "zoom" in n or "zoom" in p:
        return "This is Zoom. It starts automatically to speed up launch time. Safe if you use Zoom."

    if "slack" in n or "slack" in p:
        return "This is Slack. It starts automatically to keep you connected. Safe if you use Slack."

    if "1password" in n or "1password" in p:
        return "This is 1Password. It starts automatically for browser integration. Safe if you use 1Password."

    if "homebrew" in n or "homebrew" in p:
        return "This is a Homebrew service. Safe if you use Homebrew to manage packages on your Mac."

    if "ssh" in n or "sshd" in p or "ssh-agent" in p:
        return "This is OpenSSH — a built-in macOS service for secure remote connections. Safe and normal."

    if "cups" in n or "cupsd" in p or "cups" in p:
        return "This is CUPS — macOS's built-in printing system. Safe and part of the operating system."

    if "apache" in n or "httpd" in p:
        return "This is Apache web server. It comes bundled with macOS but is disabled by default. Safe."

    if "snmp" in n or "snmpd" in p:
        return "This is SNMP — a network monitoring service built into macOS. Safe and normal."

    if "cron" in n or "cron" in p:
        return "This is cron — macOS's built-in task scheduler. Safe and part of the operating system."

    if "ntalk" in n or "ntalkd" in p:
        return "This is ntalk — a legacy macOS network communication service. Safe but rarely used."

    if "tftp" in n or "tftpd" in p:
        return "This is TFTP — a file transfer service built into macOS. Disabled by default. Safe."

    if "openldap" in n or "slapd" in p:
        return "This is OpenLDAP — a directory service built into macOS. Safe and part of the operating system."

    if "bootps" in n or "bootpd" in p:
        return "This is bootpd — macOS's built-in DHCP server. Safe and part of the operating system."

    if "vix" in n or "vix" in p:
        return "This is a cron-related scheduler service. Safe and part of the operating system."

    if program and ("/tmp/" in p or "/var/tmp/" in p or "downloads" in p):
        return (
            "This startup item runs a program from an unusual location. "
            "Legitimate software rarely installs itself in temporary or download folders. "
            "Worth investigating."
        )

    if program and not os.path.exists(program):
        return (
            "This startup item points to a program that no longer exists on your system. "
            "It may be left over from an uninstalled app. Generally safe to ignore, "
            "but you can remove it if you want to clean up."
        )

    return (
        f"This startup item runs automatically when your Mac starts. "
        f"It appears to be third-party software. "
        f"If you recognize the name '{name.split('.')[-1]}', it is likely safe. "
        f"If you don't recognize it, it may be worth researching."
    )


def _is_suspicious_startup(name, program):
    """
    Returns True only for startup items with genuinely suspicious signals.
    Does NOT flag items simply for being unfamiliar.
    """
    p = program.lower() if program else ""
    n = name.lower()

    # Program running from temp or download locations
    if program and any(loc in p for loc in ["/tmp/", "/var/tmp/", "downloads", "/private/tmp/"]):
        return True

    # Known malicious tool names
    malicious = ["xmrig", "minerd", "cobaltstrike", "msfconsole", "mimikatz", "ngrok", "ncat", "netcat"]
    if any(m in n or m in p for m in malicious):
        return True

    return False


def scan_startup_items():
    """
    Read startup items from the correct paths for the current OS.
    For every startup item found, generate a plain English description
    using the program path and item name/label.
    Does NOT flag items as suspicious based on publisher prefix alone.
    Recon AI explains what each item is — the user decides what to do.
    """
    items = []
    total_scanned = 0
    system = platform.system()

    if system == "Darwin":
        for raw_path in MACOS_STARTUP_PATHS:
            path = Path(raw_path).expanduser()
            if not path.exists():
                continue
            try:
                for plist_file in path.glob("*.plist"):
                    total_scanned += 1
                    name = plist_file.stem
                    program = ""
                    label = ""
                    try:
                        with open(plist_file, "rb") as f:
                            plist = plistlib.load(f)
                        program = plist.get("Program", "")
                        if not program:
                            args = plist.get("ProgramArguments", [])
                            program = args[0] if args else ""
                        label = plist.get("Label", name)
                    except Exception:
                        label = name

                    description = _describe_startup_item(name, program, label)
                    is_suspicious = _is_suspicious_startup(name, program)

                    items.append({
                        "name": name,
                        "path": str(plist_file),
                        "program": program,
                        "label": label,
                        "description": description,
                        "suspicious": is_suspicious,
                    })
            except PermissionError:
                logger.warning(f"Permission denied reading {path}")
            except Exception as e:
                logger.error(f"Startup scan error at {path}: {e}")

    elif system == "Windows":
        username = os.environ.get("USERNAME", "")
        for raw_path in WINDOWS_STARTUP_PATHS:
            path = Path(raw_path.replace("{username}", username))
            if not path.exists():
                continue
            try:
                for entry in path.iterdir():
                    if entry.suffix.lower() not in (".lnk", ".bat"):
                        continue
                    total_scanned += 1
                    name = entry.stem
                    program = str(entry)
                    description = _describe_startup_item(name, program, name)
                    is_suspicious = _is_suspicious_startup(name, program)
                    items.append({
                        "name": name,
                        "path": str(entry),
                        "program": program,
                        "label": name,
                        "description": description,
                        "suspicious": is_suspicious,
                    })
            except PermissionError:
                logger.warning(f"Permission denied reading {path}")
            except Exception as e:
                logger.error(f"Startup scan error at {path}: {e}")

        # Windows registry Run keys
        try:
            import winreg
            registry_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            ]
            for hive, key_path in registry_keys:
                try:
                    key = winreg.OpenKey(hive, key_path)
                    i = 0
                    while True:
                        try:
                            val_name, val_data, _ = winreg.EnumValue(key, i)
                            total_scanned += 1
                            # Extract the binary path from quoted or unquoted command strings
                            if '"' in val_data:
                                program = val_data.split('"')[1]
                            else:
                                program = val_data.split()[0] if val_data.strip() else ""
                            description = _describe_startup_item(val_name, program, val_name)
                            is_suspicious = _is_suspicious_startup(val_name, program)
                            items.append({
                                "name": val_name,
                                "path": f"Registry: {key_path}",
                                "program": program,
                                "label": val_name,
                                "description": description,
                                "suspicious": is_suspicious,
                            })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except OSError:
                    pass
        except ImportError:
            pass

    elif system == "Linux":
        for raw_path in LINUX_STARTUP_PATHS:
            path = Path(raw_path).expanduser()
            if not path.exists():
                continue
            try:
                # systemd .service files
                for service_file in path.glob("*.service"):
                    total_scanned += 1
                    name = service_file.stem
                    program = ""
                    svc_description = ""
                    try:
                        with open(service_file, "r", errors="replace") as f:
                            for line in f:
                                line = line.strip()
                                if line.startswith("Description="):
                                    svc_description = line.split("=", 1)[1]
                                elif line.startswith("ExecStart="):
                                    raw_exec = line.split("=", 1)[1].strip()
                                    program = raw_exec.split()[0] if raw_exec else ""
                    except Exception:
                        pass

                    base_description = _describe_startup_item(name, program, name)
                    if svc_description:
                        description = f"{svc_description} — {base_description}"
                    else:
                        description = base_description

                    is_suspicious = _is_suspicious_startup(name, program)
                    items.append({
                        "name": name,
                        "path": str(service_file),
                        "program": program,
                        "label": svc_description or name,
                        "description": description,
                        "suspicious": is_suspicious,
                    })

                # XDG autostart .desktop files
                for desktop_file in path.glob("*.desktop"):
                    total_scanned += 1
                    name = desktop_file.stem
                    program = ""
                    desktop_name = ""
                    try:
                        with open(desktop_file, "r", errors="replace") as f:
                            for line in f:
                                line = line.strip()
                                if line.startswith("Name="):
                                    desktop_name = line.split("=", 1)[1]
                                elif line.startswith("Exec="):
                                    raw_exec = line.split("=", 1)[1].strip()
                                    program = raw_exec.split()[0] if raw_exec else ""
                    except Exception:
                        pass

                    description = _describe_startup_item(desktop_name or name, program, desktop_name or name)
                    is_suspicious = _is_suspicious_startup(desktop_name or name, program)
                    items.append({
                        "name": desktop_name or name,
                        "path": str(desktop_file),
                        "program": program,
                        "label": desktop_name or name,
                        "description": description,
                        "suspicious": is_suspicious,
                    })

            except PermissionError:
                logger.warning(f"Permission denied reading {path}")
            except Exception as e:
                logger.error(f"Startup scan error at {path}: {e}")

    flagged = [i for i in items if i["suspicious"]]

    return {
        "items": items,
        "flagged": flagged,
        "total_scanned": total_scanned,
        "clean": len(flagged) == 0,
    }


def _describe_recent_change(path_str):
    """
    Generate a plain English description of a recently modified file
    based on its path. Much more useful than a generic message.
    """
    p = path_str.lower()

    if "com.microsoft" in p or "microsoft" in p:
        return "This is a Microsoft file — likely updated by OneDrive, Office, or Defender. Normal if you use Microsoft software."

    if "com.apple" in p or "/system/library" in p:
        return "This is an Apple system file — likely updated by macOS automatically. Normal and expected."

    if "com.adobe" in p or "adobe" in p:
        return "This is an Adobe file — likely updated by Creative Cloud or Acrobat. Normal if you use Adobe software."

    if "com.google" in p or "google" in p:
        return "This is a Google file — likely updated by Chrome or Google Drive. Normal if you use Google software."

    if "com.dropbox" in p or "dropbox" in p:
        return "This is a Dropbox file — likely updated automatically. Normal if you use Dropbox."

    if "com.spotify" in p or "spotify" in p:
        return "This is a Spotify file — likely updated automatically. Normal if you use Spotify."

    if "resolv.conf" in p:
        return "This is your DNS configuration file. It changes when your network connection changes. Normal."

    if "/usr/local/bin/code" in p or "vscode" in p or "/code" in p:
        return "This is VS Code — updated when you install a new version. Normal if you use VS Code."

    if "/etc/hosts" in p:
        return "This is your hosts file — controls how domain names resolve on your machine. Unexpected changes here are worth investigating."

    if "/etc/krb5" in p:
        return "This is a Kerberos authentication file. Updated automatically by macOS for network authentication. Normal."

    if "/usr/bin" in p or "/usr/local/bin" in p:
        return "This is a system binary or command-line tool. Updated when software is installed or updated."

    if "tailscale" in p:
        return "This is Tailscale — a VPN tool. Updated automatically. Normal if you use Tailscale."

    if "1password" in p:
        return "This is 1Password — a password manager. Updated automatically. Normal if you use 1Password."

    if "zoom" in p:
        return "This is Zoom. Updated automatically. Normal if you use Zoom."

    if "slack" in p:
        return "This is Slack. Updated automatically. Normal if you use Slack."

    if "docker" in p:
        return "This is Docker. Updated automatically. Normal if you use Docker."

    if "homebrew" in p or "brew" in p:
        return "This is Homebrew — a package manager for Mac. Updated automatically. Normal."

    if "notion" in p:
        return "This is Notion. Updated automatically. Normal if you use Notion."

    if "figma" in p:
        return "This is Figma. Updated automatically. Normal if you use Figma."

    if "cursor" in p:
        return "This is Cursor — an AI code editor. Updated automatically. Normal if you use Cursor."

    if "github" in p:
        return "This is GitHub Desktop or a GitHub tool. Updated automatically. Normal if you use GitHub Desktop."

    if "jetbrains" in p or "intellij" in p or "pycharm" in p or "webstorm" in p:
        return "This is a JetBrains IDE. Updated automatically. Normal if you use JetBrains software."

    if "virtualbox" in p or "vmware" in p or "parallels" in p:
        return "This is virtualization software. Updated automatically. Normal if you use it."

    # Smart fallback — extract the most meaningful word from the path
    parts = path_str.replace("\\", "/").split("/")
    skip = {"library", "launchagents", "launchdaemons", "system",
            "usr", "bin", "local", "etc", "var", "private", "cores",
            "application support", "preferences", "ipn"}
    meaningful = next(
        (p for p in reversed(parts)
         if len(p) > 3 and p.lower() not in skip),
        ""
    )
    if meaningful:
        # Clean up plist names like com.notion.Notion.plist -> Notion
        clean = meaningful.replace(".plist", "")
        segments = clean.split(".")
        # Take the last meaningful segment, capitalize it
        name = next(
            (s.capitalize() for s in reversed(segments)
             if len(s) > 2 and s.lower() not in
             {"com", "org", "net", "app", "plist", "daemon", "agent", "helper"}),
            clean.capitalize()
        )
        return (
            f"This looks like a file belonging to {name}. "
            f"It was likely updated automatically. "
            f"Normal if you use {name}. If you don't recognize it, investigate."
        )

    # Only use generic startup message if no app name could be extracted
    if "launchagents" in p or "launchdaemons" in p:
        return "This is a startup configuration file. It may have been updated by a software installer. Worth noting if you didn't recently install anything."

    return (
        "This file was recently modified. "
        "If you didn't recognize the software at this path, it may be worth investigating."
    )


def scan_recent_changes(days=7):
    """
    Check SENSITIVE_PATHS for files modified in the last N days.
    Uses os.path.getmtime(). Read-only — never modifies anything.
    """
    flagged = []
    total_scanned = 0
    cutoff = datetime.now() - timedelta(days=days)

    # Patterns that indicate routine system updates — skip these
    system_update_patterns = [
        ".DS_Store", ".localized", "Receipts",
        "pkgutil", ".log", ".tmp", "cache",
    ]

    for raw_path in SENSITIVE_PATHS:
        path = Path(raw_path)
        if not path.exists():
            continue
        try:
            entries = list(path.iterdir())
        except PermissionError:
            logger.warning(f"Permission denied reading {path}")
            continue
        except Exception as e:
            logger.error(f"Change scan error at {path}: {e}")
            continue

        for entry in entries:
            if not entry.is_file():
                continue
            # Skip system update noise
            if any(pat in entry.name for pat in system_update_patterns):
                continue
            total_scanned += 1
            try:
                mtime = datetime.fromtimestamp(entry.stat().st_mtime)
                if mtime >= cutoff:
                    flagged.append({
                        "path": str(entry),
                        "modified": mtime.strftime("%Y-%m-%d %H:%M"),
                        "description": _describe_recent_change(str(entry)),
                    })
            except Exception:
                continue

    return {
        "flagged": flagged,
        "total_scanned": total_scanned,
        "clean": len(flagged) == 0,
        "days_checked": days,
    }


def run_system_inspection(days=7):
    """
    Runs all three checks and returns a combined result dict.
    """
    logger.info("Starting system inspection...")

    processes = scan_processes()
    startup = scan_startup_items()
    recent_changes = scan_recent_changes(days=days)

    overall_clean = (
        processes["clean"] and
        startup["clean"] and
        recent_changes["clean"]
    )

    flagged_count = (
        len(processes["flagged"]) +
        len(startup["flagged"]) +
        len(recent_changes["flagged"])
    )

    if overall_clean:
        summary = "Everything looks clean. I didn't find any suspicious processes, unexpected startup items, or unusual file changes."
    elif len(processes["flagged"]) > 0:
        names = ", ".join(p["name"] for p in processes["flagged"][:3])
        summary = f"I found {len(processes['flagged'])} suspicious process(es) running: {names}. Review these immediately."
    elif len(startup["flagged"]) > 0:
        summary = f"I found {len(startup['flagged'])} suspicious startup item(s). These run every time your system starts — worth reviewing."
    else:
        summary = f"I found {len(recent_changes['flagged'])} recent file change(s) in sensitive system paths. Check these if anything feels off."

    logger.info(f"System inspection complete. {flagged_count} item(s) flagged.")

    return {
        "processes": processes,
        "startup": startup,
        "recent_changes": recent_changes,
        "overall_clean": overall_clean,
        "summary": summary,
    }


if __name__ == "__main__":
    import json
    results = run_system_inspection()
    print(json.dumps(results, indent=2))
