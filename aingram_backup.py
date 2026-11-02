"""AIngram nightly backup: the check that root on the server can't fake.

Runs somewhere the server can't reach: your own machine, or a private GitHub
repository's scheduled job. Each night it downloads the export with a
read-only backup token and checks it:

  - the new log verifies on its own (every hash recomputed from its content);
  - it extends last night's: no entry missing or changed, no redaction undone,
    no redaction record gone;
  - every policy approval is signed by the admin address *this backup* trusts
    (set when you set it up, not read from the server), and each approved
    policy text matches its hash; none of last night's approvals vanished;
  - no key disappeared, changed voice, or came back from revocation.

If everything passes it updates the backup folder:

  ledger/entries.jsonl   every entry's header (ids, hashes, subjects, kinds,
                         times) with no content: committed to git each night,
                         so the history is independent of the server
  ledger/admin.json      policy approvals and texts, and the key list (committed)
  latest/                the full export for restoring, replaced each night and
                         kept out of git, so redacted content leaves the backup

If anything fails, nothing is overwritten, the download is kept in failed/,
ALERT.txt is written, and (with --notify) a desktop alert pops up. The exit
status is nonzero, which is what makes a GitHub job email you.

    python aingram_backup.py install --url https://SERVER --token aigb_... --admin 0x...
    python aingram_backup.py pull [--dir FOLDER] [--notify] [--no-git] [--no-latest]

Needs Python 3.11+ and eth-account (pip install -r requirements-backup.txt).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import admin_auth
import aingram_core as core

CONTENT_FIELDS = ("excerpt", "keywords", "body", "salt")
ENV_FILE = "backup.env"
CONFIG_KEYS = ("AINGRAM_BACKUP_URL", "AINGRAM_BACKUP_TOKEN", "AINGRAM_BACKUP_ADMIN", "AINGRAM_BACKUP_SERVER")
TIMEOUT = 120


class BackupError(Exception):
    pass


# ---------------------------------------------------------------- configuration

def load_config(folder: Path, env=None) -> dict:
    """backup.env in the backup folder, overridden by the environment (GitHub passes secrets that way)."""
    env = os.environ if env is None else env
    config = {}
    path = folder / ENV_FILE
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()
    for k in CONFIG_KEYS:
        if env.get(k):
            config[k] = env[k].strip()
    missing = [k for k in CONFIG_KEYS[:3] if not config.get(k)]
    if missing:
        raise BackupError(f"not configured: {', '.join(missing)} (run install, or set them in {ENV_FILE})")
    url = config["AINGRAM_BACKUP_URL"].rstrip("/")
    p = urlparse(url)
    if p.scheme != "https" and not (p.scheme == "http" and p.hostname in ("127.0.0.1", "localhost", "::1")):
        raise BackupError("AINGRAM_BACKUP_URL must be https://")
    config["AINGRAM_BACKUP_URL"] = url
    # Approvals are signed for a server name, which defaults to the public URL's host.
    config["AINGRAM_BACKUP_SERVER"] = config.get("AINGRAM_BACKUP_SERVER") or p.netloc
    return config


# ---------------------------------------------------------------- download

def download(config: dict, name: str, dest: Path) -> None:
    req = urllib.request.Request(f"{config['AINGRAM_BACKUP_URL']}/backup/{name}",
                                 headers={"Authorization": f"Bearer {config['AINGRAM_BACKUP_TOKEN']}"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r, open(dest, "wb") as f:
            shutil.copyfileobj(r, f)
    except urllib.error.HTTPError as e:
        raise BackupError(f"download of {name} failed: HTTP {e.code} (is the backup token still valid?)") from None
    except (urllib.error.URLError, OSError) as e:
        raise BackupError(f"download of {name} failed: {e}") from None


# ---------------------------------------------------------------- the checks

def ledger_records(entries: list[dict], redactions: dict[str, dict]) -> list[dict]:
    """The export with every entry's content removed: what the git history keeps."""
    out = [{"type": "entry", **{k: (None if k in CONTENT_FIELDS else v) for k, v in e.items()}} for e in entries]
    out += [{"type": "redaction", **r} for r in redactions.values()]
    return out


def write_jsonl(path: Path, records: list[dict]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=True, sort_keys=True) + "\n")


def check_entries(old_ledger: Path | None, new_export: Path) -> list[str]:
    """The new export verifies and extends last night's ledger. Headers carry each
    entry's content hash and the new export's hashes are recomputed from its content,
    so the ledger needs no content to catch an edit."""
    entries, redactions = core.load_jsonl(new_export)
    problems = [f"new export: {p}" for p in core.verify_records(entries, redactions)]
    if old_ledger is None or not old_ledger.exists():
        return problems
    old_entries, old_red = core.load_jsonl(old_ledger)
    by_seq = {e["seq"]: e for e in entries}
    for o in old_entries:
        n = by_seq.get(o["seq"])
        if n is None:
            problems.append(f"seq {o['seq']}: missing from the new export (history truncated)")
        elif any(o[c] != n[c] for c in core.HEADER_COLUMNS):
            problems.append(f"seq {o['seq']}: header changed (history rewritten)")
        elif o["redacted_at"] is not None and n["redacted_at"] is None:
            problems.append(f"seq {o['seq']}: redacted content reappeared")
    for entry_id in old_red:
        if entry_id not in redactions:
            problems.append(f"redaction of {entry_id[:12]}: record disappeared")
    return problems


def check_admin(old: dict | None, new: dict, admin_address: str, server: str) -> tuple[list[str], list[str]]:
    """(problems, notes). Approvals must be signed by the admin address this backup trusts."""
    problems, notes = [], []
    if new.get("format") != 1:
        return [f"admin.json: unknown format {new.get('format')!r}"], notes
    versions = new.get("policy_versions") or {}
    for sha, body in versions.items():
        if hashlib.sha256(body.encode("utf-8")).hexdigest() != sha:
            problems.append(f"policy {sha[:12]}: stored text does not match its hash")
    for a in new.get("policy_approvals") or []:
        try:
            action = admin_auth.verify_logged(a["message"], a["signature"], server, admin_address)
        except (admin_auth.AdminAuthError, KeyError, ValueError) as e:
            problems.append(f"policy approval not signed by the trusted admin for {server}: {e}")
            continue
        if action.get("sha256") not in versions:
            problems.append(f"approved policy {str(action.get('sha256'))[:12]}: text missing")
    if old is None:
        return problems, notes
    new_msgs = {a["message"] for a in new.get("policy_approvals") or []}
    for a in old.get("policy_approvals") or []:
        if a["message"] not in new_msgs:
            problems.append("a policy approval from an earlier night disappeared")
    for sha, body in (old.get("policy_versions") or {}).items():
        if versions.get(sha) != body:
            problems.append(f"policy {sha[:12]}: an earlier version disappeared or changed")
    new_keys = {k["key_id"]: k for k in new.get("keys") or []}
    for k in old.get("keys") or []:
        n = new_keys.pop(k["key_id"], None)
        if n is None:
            problems.append(f"key {k['key_id']}: disappeared")
        elif n["voice"] != k["voice"] or n["created_at"] != k["created_at"]:
            problems.append(f"key {k['key_id']}: changed")
        elif k["revoked_at"] is not None and n["revoked_at"] is None:
            problems.append(f"key {k['key_id']}: came back from revocation")
    for k in new_keys.values():
        notes.append(f"new key {k['key_id']} ({k['voice']}): {k['label'] or ''}")
    return problems, notes


# ---------------------------------------------------------------- the nightly run

def pull(folder: Path, *, use_git: bool = True, keep_latest: bool = True, env=None) -> list[str]:
    """Download, check, and on success update the backup folder. Returns notes; raises
    BackupError with every problem found if a check fails."""
    config = load_config(folder, env)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    with tempfile.TemporaryDirectory(prefix="aingram-backup-") as tmp:
        tmp = Path(tmp)
        download(config, "entries.jsonl", tmp / "entries.jsonl")
        download(config, "admin.json", tmp / "admin.json")
        try:
            new_admin = json.loads((tmp / "admin.json").read_text(encoding="utf-8"))
            old_admin_path = folder / "ledger" / "admin.json"
            old_admin = json.loads(old_admin_path.read_text(encoding="utf-8")) if old_admin_path.exists() else None
            problems = check_entries(folder / "ledger" / "entries.jsonl", tmp / "entries.jsonl")
            admin_problems, notes = check_admin(old_admin, new_admin, config["AINGRAM_BACKUP_ADMIN"],
                                                config["AINGRAM_BACKUP_SERVER"])
            problems += admin_problems
        except Exception as e:  # anything malformed is a failed check, never a crash without an alert
            problems, notes = [f"the download could not be read: {type(e).__name__}: {e}"], []
        if problems:
            failed = folder / "failed" / stamp
            failed.mkdir(parents=True, exist_ok=True)
            for name in ("entries.jsonl", "admin.json"):
                shutil.copy2(tmp / name, failed / name)
            _private(failed)
            raise BackupError("\n".join(problems))
        entries, redactions = core.load_jsonl(tmp / "entries.jsonl")
        ledger = folder / "ledger"
        ledger.mkdir(exist_ok=True)
        write_jsonl(ledger / "entries.jsonl", ledger_records(entries, redactions))
        (ledger / "admin.json").write_text(json.dumps(new_admin, indent=1, sort_keys=True) + "\n",
                                           encoding="utf-8", newline="\n")
        if keep_latest:
            latest = folder / "latest"
            latest.mkdir(exist_ok=True)
            for name in ("entries.jsonl", "admin.json"):
                shutil.copy2(tmp / name, latest / name)
            _private(latest)
    (folder / "ALERT.txt").unlink(missing_ok=True)
    head = f"#{entries[-1]['seq']} {entries[-1]['id'][:12]}" if entries else "empty"
    if use_git:
        _commit(folder, f"AIngram backup {stamp}, head {head}")
    return [f"backup checked and saved; head {head}", *notes]


def _private(path: Path) -> None:
    if os.name == "posix":
        os.chmod(path, 0o700)
        for p in path.iterdir():
            os.chmod(p, 0o600)


def _git(folder: Path, *args, check=True):
    return subprocess.run(["git", "-C", str(folder), *args], capture_output=True, text=True, check=check)


def _commit(folder: Path, message: str) -> None:
    if shutil.which("git") is None:
        raise BackupError("git is not installed; install it, or run with --no-git")
    if not (folder / ".git").exists():
        _git(folder, "init", "-q")
    _git(folder, "add", "ledger")
    if _git(folder, "diff", "--cached", "--quiet", check=False).returncode != 0:
        _git(folder, "-c", "user.name=AIngram backup", "-c", "user.email=backup@aingram.invalid",
             "commit", "-q", "-m", message)


def alert(folder: Path, text: str, notify: bool) -> None:
    (folder / "ALERT.txt").write_text(f"{datetime.now(timezone.utc).isoformat()}\n{text}\n", encoding="utf-8")
    if not notify:
        return
    title, body = "AIngram backup check FAILED", text[:400]
    try:
        system = platform.system()
        if system == "Windows":
            ps = ("Add-Type -AssemblyName System.Windows.Forms; "
                  "[System.Windows.Forms.MessageBox]::Show($env:AIG_BODY, $env:AIG_TITLE, 'OK', 'Warning')")
            subprocess.Popen(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps],
                             env={**os.environ, "AIG_TITLE": title, "AIG_BODY": body})
        elif system == "Darwin":
            subprocess.run(["osascript", "-e", "on run argv", "-e",
                            "display alert (item 1 of argv) message (item 2 of argv) as critical",
                            "-e", "end run", title, body], check=False)
        elif shutil.which("notify-send"):
            subprocess.run(["notify-send", "-u", "critical", title, body], check=False)
    except OSError:
        pass  # ALERT.txt and the exit status still report it


# ---------------------------------------------------------------- setup

def install(folder: Path, url: str, token: str, admin: str, at: str, schedule: bool = True) -> list[str]:
    folder.mkdir(parents=True, exist_ok=True)
    env_path = folder / ENV_FILE
    env_path.write_text(f"AINGRAM_BACKUP_URL={url}\nAINGRAM_BACKUP_TOKEN={token}\nAINGRAM_BACKUP_ADMIN={admin}\n",
                        encoding="utf-8")
    if os.name == "posix":
        os.chmod(env_path, 0o600)
    (folder / ".gitignore").write_text(f"{ENV_FILE}\nlatest/\nfailed/\nALERT.txt\n", encoding="utf-8")
    out = pull(folder)
    if schedule:
        out.append(_schedule(folder, at))
    return out


def _schedule(folder: Path, at: str) -> str:
    script, python = Path(__file__).resolve(), Path(sys.executable).resolve()
    hour, minute = (int(x) for x in at.split(":"))
    if platform.system() == "Windows":
        ps = ("$a = New-ScheduledTaskAction -Execute $env:AIG_PY -Argument $env:AIG_ARGS -WorkingDirectory $env:AIG_DIR; "
              "$t = New-ScheduledTaskTrigger -Daily -At $env:AIG_AT; "
              "$s = New-ScheduledTaskSettingsSet -StartWhenAvailable; "
              "Register-ScheduledTask -TaskName 'AIngram backup' -Action $a -Trigger $t -Settings $s -Force | Out-Null")
        args = f'"{script}" pull --dir "{folder}" --notify'
        subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=True, env={
            **os.environ, "AIG_PY": str(python), "AIG_ARGS": args, "AIG_DIR": str(folder), "AIG_AT": f"{hour:02d}:{minute:02d}"})
        return f"scheduled nightly at {hour:02d}:{minute:02d} as the Windows task 'AIngram backup' (runs late if the PC was off)"
    line = f'{minute} {hour} * * * "{python}" "{script}" pull --dir "{folder}" --notify  # AIngram backup'
    current = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
    kept = [l for l in current.splitlines() if "# AIngram backup" not in l]
    subprocess.run(["crontab", "-"], input="\n".join(kept + [line]) + "\n", text=True, check=True)
    return f"scheduled nightly at {hour:02d}:{minute:02d} in your crontab (skipped if the machine is asleep then)"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="aingram_backup", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("install", help="set up a backup folder and schedule it nightly")
    i.add_argument("--url", required=True, help="your server, e.g. https://aingram.example.com")
    i.add_argument("--token", required=True, help="a backup token from the admin page")
    i.add_argument("--admin", required=True, help="your admin wallet address (the one this backup trusts)")
    i.add_argument("--dir", default=str(Path.home() / "aingram-backup"))
    i.add_argument("--at", default="04:30", help="local time to run, HH:MM")
    i.add_argument("--no-schedule", action="store_true")
    r = sub.add_parser("pull", help="download, check and save tonight's backup")
    r.add_argument("--dir", default=".")
    r.add_argument("--notify", action="store_true", help="pop up a desktop alert if a check fails")
    r.add_argument("--no-git", action="store_true")
    r.add_argument("--no-latest", action="store_true", help="don't keep the full export (the GitHub job keeps it as an artifact)")
    args = p.parse_args(argv)
    folder = Path(args.dir).expanduser().resolve()
    try:
        if args.cmd == "install":
            out = install(folder, args.url.rstrip("/"), args.token, args.admin, args.at, not args.no_schedule)
        else:
            out = pull(folder, use_git=not args.no_git, keep_latest=not args.no_latest)
        print("\n".join(out))
        return 0
    except BackupError as e:
        print(f"AIngram backup check FAILED:\n{e}", file=sys.stderr)
        if folder.exists():
            alert(folder, str(e), getattr(args, "notify", False))
        return 1


if __name__ == "__main__":
    sys.exit(main())
