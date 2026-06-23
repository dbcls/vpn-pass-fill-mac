#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
macOS menubar resident helper for FortiClient password + token autofill (IMAP edition).

What it does:
- Runs as a menu bar app
- Watches for Forti-related windows
- Autofills the saved password from Keychain ("password" window)
- Autofills the OTP token fetched DIRECTLY from an IMAP mailbox ("token" window)
- Does NOT use the Apple Mail app or AppleScript automation for token retrieval,
  so Apple Mail does not even need to be installed/running.

Who this edition is for:
- People who do NOT use Apple Mail. Configure an IMAP account once in this tool and
  token autofill works without any mail client.
- Works with any mailbox that allows basic-auth IMAP (username + password) or an
  "app password": university/ISP/self-hosted IMAP, personal Gmail (app password), iCloud,
  Fastmail, etc.
- Does NOT work where the provider has disabled basic auth AND app passwords and requires
  OAuth2 (e.g. Google Workspace / Microsoft 365 locked down by an admin). Use the Apple
  Mail edition (forti_pass_fill_applemail.py) there.

Requirements:
    pip install rumps pyobjc
    (imaplib / email are stdlib, no extra install)

First-time permissions:
- Terminal / the packaged app needs Accessibility permission (to type into FortiClient)
- Keychain access prompt may appear on first read/write
- NO Automation (Apple Events) permission is required for token retrieval

Setup (from the menu bar):
    1. "Set IMAP Account"  -> host / port / user / folder
    2. "Set IMAP Password" -> the mailbox (app) password, stored in Keychain
    3. "Set Password"      -> the Forti VPN password, stored in Keychain
    4. "Test IMAP Login"   -> verify the connection

Run:
    python3 forti_pass_fill_imap.py > ./status.log 2>&1 &
"""
from __future__ import annotations
import email
import email.utils
import imaplib
import json
import os
import re
import subprocess
import time
from datetime import datetime
from email.header import decode_header
from typing import Optional

import rumps
from Quartz import (
    CGWindowListCopyWindowInfo,
    kCGNullWindowID,
    kCGWindowListOptionOnScreenOnly,
    kCGWindowListExcludeDesktopElements,
)

# ---- Token source ----
# 件名から AuthCode を抜き出すパターン（某組織仕様）。
SUBJECT_PATTERN = re.compile(r"AuthCode:\s*(\d+)")
# 送信者で絞りたい場合のみ設定（空なら送信者で絞らない）。アドレスは環境で変わりうるので既定は空。
TARGET_SENDER = ""
# 送信者で絞らないときに IMAP サーバ側で候補を絞り込む件名キーワード。
SEARCH_SUBJECT_KEYWORD = "AuthCode"
# OTP は短命なので、これより古い（受信からの経過秒）コードは使い回しとみなし無視する。
TOKEN_MAX_AGE_SEC = 300

# ---- IMAP defaults ----
DEFAULT_IMAP_PORT = 993
DEFAULT_IMAP_FOLDER = "INBOX"
# When a token window appears the mail may not have arrived yet. Poll a few times.
IMAP_POLL_ATTEMPTS = 5
IMAP_POLL_INTERVAL = 2.0
# How many of the most recent matching messages to scan.
IMAP_SCAN_LIMIT = 15

APP_TITLE = "🐾"  # menu bar icon (emoji)
KEYCHAIN_SERVICE = "FortiVPNAuth"        # Forti VPN password
IMAP_KEYCHAIN_SERVICE = "FortiVPNIMAP"   # IMAP mailbox password
CONFIG_PATH = os.path.expanduser("~/.forti_menu_autofill.json")
LOG_PATH = os.path.expanduser("~/forti_autofill.log")
WATCH_INTERVAL_SEC = 0.4
PASSWORD_COOLDOWN_SEC = 8.0
OWNERS = {
    "FortiClientAgent",
    "FortiTray",
}


class FortiMenuApp(rumps.App):
    def __init__(self) -> None:
        super().__init__(APP_TITLE, quit_button=None)
        self.last_password_handled: dict[int, float] = {}
        self.enabled = True
        self.last_status = "Starting"

        cfg = self._load_config()
        self.imap_host = cfg.get("imap_host", "")
        self.imap_port = int(cfg.get("imap_port", DEFAULT_IMAP_PORT))
        self.imap_user = cfg.get("imap_user", "")
        self.imap_folder = cfg.get("imap_folder", DEFAULT_IMAP_FOLDER)

        self.status_item = rumps.MenuItem("Status: starting")
        self.enable_item = rumps.MenuItem("Enabled")
        self.enable_item.state = 1
        self.menu = [
            self.status_item,
            None,
            self.enable_item,
            "Set IMAP Account",
            "Set IMAP Password",
            "Test IMAP Login",
            None,
            "Set Password",
            "Delete Password",
            "Test Keychain Read",
            None,
            "Show Last Log",
            "Quit",
        ]
        self.timer = rumps.Timer(self.on_timer, WATCH_INTERVAL_SEC)
        self.timer.start()
        self.log("watch start")
        self.update_status("running")

    # ---------- Config ----------
    def _load_config(self) -> dict:
        if not os.path.exists(CONFIG_PATH):
            return {}
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}

    def _save_config(self, data: dict) -> None:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    # ---------- Utility ----------
    def log(self, msg: str) -> None:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.last_status = f"[{ts}] {msg}"
        print(self.last_status, flush=True)
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(self.last_status + "\n")
        except Exception:
            pass
        self.status_item.title = f"Status: {msg[:80]}"

    def update_status(self, text: str) -> None:
        self.status_item.title = f"Status: {text}"

    def run_osascript(self, script: str) -> str:
        return subprocess.check_output(["osascript", "-e", script], text=True).strip()

    def notify(self, title: str, message: str) -> None:
        title_esc = title.replace("\\", "\\\\").replace('"', '\\"')
        msg_esc = message.replace("\\", "\\\\").replace('"', '\\"')
        script = f'display notification "{msg_esc}" with title "{title_esc}"'
        try:
            self.run_osascript(script)
        except Exception as e:
            self.log(f"notify error: {e}")

    def _alert(self, message: str, title: str = "Forti") -> None:
        try:
            rumps.alert(title=title, message=message)
        except Exception as e:
            self.log(f"alert error: {e}")

    def _confirm(self, message: str, title: str, ok_label: str) -> bool:
        try:
            return rumps.alert(title=title, message=message, ok=ok_label, cancel="Cancel") == 1
        except Exception as e:
            self.log(f"confirm error: {e}")
            return False

    def _prompt(self, message: str, default: str = "", secure: bool = False) -> Optional[str]:
        """Show a text-input dialog. Returns the entered text, or None if cancelled."""
        msg = message.replace("\\", "\\\\").replace('"', '\\"')
        dflt = default.replace("\\", "\\\\").replace('"', '\\"')
        hidden = " with hidden answer" if secure else ""
        script = f'''
display dialog "{msg}" ¬
    default answer "{dflt}"{hidden} ¬
    with title "Forti Setup" ¬
    buttons {{"Cancel", "OK"}} ¬
    default button "OK"
'''
        try:
            raw = self.run_osascript(script)
        except subprocess.CalledProcessError:
            return None  # user cancelled (error -128)
        match = re.search(r"text returned:(.*)", raw, re.S)
        if not match:
            return None
        return match.group(1)

    # ---------- Keychain ----------
    def get_user_name(self) -> str:
        return os.environ.get("USER") or subprocess.check_output(["whoami"], text=True).strip()

    def get_keychain_password(self, service: str) -> str:
        user = self.get_user_name()
        out = subprocess.check_output(
            ["security", "find-generic-password", "-a", user, "-s", service, "-w"],
            text=True,
        )
        return out.strip()

    def set_keychain_password(self, service: str, password: str) -> None:
        user = self.get_user_name()
        subprocess.check_call(
            [
                "security",
                "add-generic-password",
                "-a",
                user,
                "-s",
                service,
                "-w",
                password,
                "-U",
            ]
        )

    def delete_keychain_password(self, service: str) -> None:
        user = self.get_user_name()
        subprocess.check_call(
            ["security", "delete-generic-password", "-a", user, "-s", service]
        )

    # ---------- Token (IMAP) ----------
    def _decode_hdr(self, raw: Optional[str]) -> str:
        if not raw:
            return ""
        out = ""
        for txt, enc in decode_header(raw):
            if isinstance(txt, bytes):
                try:
                    out += txt.decode(enc or "utf-8", errors="replace")
                except (LookupError, TypeError):
                    out += txt.decode("utf-8", errors="replace")
            else:
                out += txt
        return out

    def _extract_code(self, msg: email.message.Message) -> str:
        # Primary: subject (matches the Apple Mail edition behaviour)
        subject = self._decode_hdr(msg.get("Subject"))
        m = SUBJECT_PATTERN.search(subject or "")
        if m:
            return m.group(1)
        # Fallback: text/plain body
        try:
            if msg.is_multipart():
                parts = [p for p in msg.walk() if p.get_content_type() == "text/plain"]
            else:
                parts = [msg]
            for part in parts:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                m = SUBJECT_PATTERN.search(text)
                if m:
                    return m.group(1)
        except Exception as e:
            self.log(f"imap: body parse error: {e}")
        return ""

    def _fetch_code_once(self, host: str, user: str, pw: str) -> str:
        cutoff = time.time() - TOKEN_MAX_AGE_SEC
        conn = None
        try:
            conn = imaplib.IMAP4_SSL(host, self.imap_port)
            conn.login(user, pw)
            conn.select(self.imap_folder, readonly=True)

            # 送信者指定があれば FROM で、無ければ件名キーワードで候補を絞る。
            if TARGET_SENDER:
                typ, data = conn.search(None, "FROM", f'"{TARGET_SENDER}"')
            else:
                typ, data = conn.search(None, "SUBJECT", f'"{SEARCH_SUBJECT_KEYWORD}"')
            if typ != "OK" or not data or not data[0]:
                return ""

            ids = data[0].split()
            for num in reversed(ids[-IMAP_SCAN_LIMIT:]):  # newest first
                typ, msgdata = conn.fetch(num, "(RFC822)")
                if typ != "OK" or not msgdata:
                    continue
                raw = next(
                    (item[1] for item in msgdata if isinstance(item, tuple) and len(item) >= 2 and item[1]),
                    None,
                )
                if not raw:
                    continue
                msg = email.message_from_bytes(raw)
                # Recency: skip stale OTP mails. If the date is unparseable, accept.
                try:
                    dt = email.utils.parsedate_to_datetime(msg.get("Date"))
                    if dt is not None and dt.timestamp() < cutoff:
                        continue
                except Exception:
                    pass
                code = self._extract_code(msg)
                if code:
                    return code
            return ""
        finally:
            if conn is not None:
                try:
                    conn.logout()
                except Exception:
                    pass

    def get_token_from_imap(self) -> str:
        if not self.imap_host or not self.imap_user:
            self.log("imap: host/user 未設定")
            self.notify("Forti", "IMAP サーバ/ユーザーが未設定です。メニューの Set IMAP Account から設定してください")
            return ""
        try:
            pw = self.get_keychain_password(IMAP_KEYCHAIN_SERVICE)
        except subprocess.CalledProcessError:
            self.log("imap: keychain にパスワード無し")
            self.notify("Forti", "IMAP パスワードが未保存です。メニューの Set IMAP Password から保存してください")
            return ""

        for attempt in range(1, IMAP_POLL_ATTEMPTS + 1):
            try:
                code = self._fetch_code_once(self.imap_host, self.imap_user, pw)
            except imaplib.IMAP4.error as e:
                # login failure etc. — no point in retrying with the same creds
                self.log(f"imap error: {e}")
                self.notify("Forti", f"IMAP 接続/ログインに失敗しました: {e}")
                return ""
            except Exception as e:
                self.log(f"imap fetch error (attempt {attempt}): {e}")
                code = ""
            if code:
                self.log(f"imap: token 取得成功 (attempt {attempt})")
                return code
            if attempt < IMAP_POLL_ATTEMPTS:
                time.sleep(IMAP_POLL_INTERVAL)
        self.log("imap: 該当する新着トークンメールが見つかりませんでした")
        return ""

    # ---------- Window watch ----------
    def list_candidate_windows(self) -> list[dict]:
        windows = CGWindowListCopyWindowInfo(
            kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements,
            kCGNullWindowID,
        )
        rows = []
        for w in windows:
            owner = str(w.get("kCGWindowOwnerName", "") or "")
            name = str(w.get("kCGWindowName", "") or "")
            wid = w.get("kCGWindowNumber")
            pid = w.get("kCGWindowOwnerPID")
            layer = w.get("kCGWindowLayer")
            alpha = w.get("kCGWindowAlpha")
            bounds = w.get("kCGWindowBounds") or {}
            if owner in OWNERS:
                rows.append(
                    {
                        "id": wid,
                        "pid": pid,
                        "owner": owner,
                        "name": name,
                        "layer": layer,
                        "alpha": alpha,
                        "bounds": bounds,
                    }
                )
        return rows

    def choose_target(self, rows: list[dict]) -> Optional[dict]:
        if not rows:
            return None
        return rows[0]

    def window_contains_word(self, proc_name: str) -> str:
        proc = proc_name.replace("\\", "\\\\").replace('"', '\\"')
        script = f'''
on run
    tell application "System Events"
        if not (exists process "{proc}") then
            return "false"
        end if
        tell process "{proc}"
            if not (exists window 1) then
                return "false"
            end if
            try
                set elems to entire contents of window 1
                repeat with e in elems
                    try
                        set t to name of e as text
                        if (do shell script "printf %s " & quoted form of t & " | tr '[:upper:]' '[:lower:]'") contains "password" then
                            return "password"
                        else if (do shell script "printf %s " & quoted form of t & " | tr '[:upper:]' '[:lower:]'") contains "token" then
                            return "token"
                        end if
                    end try
                end repeat
            end try
        end tell
    end tell
    return "false"
end run
'''
        try:
            return self.run_osascript(script).strip().lower()
        except Exception as e:
            self.log(f"window_contains_word error: proc={proc_name!r} error={e}")
            return "false"

    # ---------- Autofill ----------
    def apple_script_fill_word(self, proc_name: str, word: str) -> str:
        word = word.replace("\\", "\\\\").replace('"', '\\"')
        proc = proc_name.replace("\\", "\\\\").replace('"', '\\"')
        script = f'''
on run
    set theWord to "{word}"
    tell application "System Events"
        if not (exists process "{proc}") then
            return "no-process"
        end if
        tell process "{proc}"
            set frontmost to true
            delay 0.2
            if not (exists window 1) then
                return "no-window"
            end if
            -- Mission Control に頼らず、対象ウィンドウを明示的に前面へ
            try
                perform action "AXRaise" of window 1
                delay 0.2
            end try
            try
                set value of (text field 1 of window 1) to theWord
                key code 36
                return "ok-textfield"
            end try
            try
                click (text field 1 of window 1)
                delay 0.1
                keystroke theWord
                key code 36
                return "ok-click-keystroke"
            end try
            try
                keystroke theWord
                key code 36
                return "ok-keystroke"
            end try
        end tell
    end tell
    return "failed"
end run
'''
        return self.run_osascript(script)

    def try_fill_word_all(self, rows: list[dict], type: str, word: str) -> tuple[Optional[str], str]:
        tried: set[str] = set()
        for r in rows:
            proc_name = r["owner"]
            if not proc_name or proc_name in tried:
                continue
            tried.add(proc_name)
            try:
                if self.window_contains_word(proc_name) != type:
                    self.log(f"{type} text not found: proc={proc_name!r}")
                    continue
                result = self.apple_script_fill_word(proc_name, word)
                self.log(f"{type} fill try: proc={proc_name!r} result={result}")
                if result.startswith("ok-"):
                    return proc_name, result
            except subprocess.CalledProcessError as e:
                self.log(f"{type} fill failed: proc={proc_name!r} error={e}")
        return None, "failed"

    def on_timer(self, _sender) -> None:
        if not self.enabled:
            return
        try:
            rows = self.list_candidate_windows()
            target = self.choose_target(rows)
            if not target:
                return
            wid = int(target["id"])
            owner = target["owner"]
            name = target["name"]
            now = time.time()
            if owner not in OWNERS:
                return
            type = self.window_contains_word(owner)
            if not type or type == "false":
                return
            if now - self.last_password_handled.get(wid, 0) < PASSWORD_COOLDOWN_SEC:
                return

            fill_word = ""
            if type == "password":
                fill_word = self.get_keychain_password(KEYCHAIN_SERVICE)
            elif type == "token":
                fill_word = self.get_token_from_imap()

            if not fill_word:
                self.log(f"fill_word is empty, skipping: word={type!r}")
                if type == "token":
                    self.notify("Forti", "IMAP からトークンを取得できませんでした（メール未着 or 設定/認証不足）")
                # 取得失敗時も少し待ってから再試行する（0.4秒毎の連打を防ぐ）
                self.last_password_handled[wid] = now
                return

            self.log(f"target detected: owner={owner!r} name={name!r} id={wid}")
            proc_name, result = self.try_fill_word_all(rows, type, fill_word)
            self.log(f"fill result: proc={proc_name!r} result={result}")
            self.last_password_handled[wid] = now

        except subprocess.CalledProcessError as e:
            self.log(f"subprocess error: {e}")
        except Exception as e:
            self.log(f"error: {e}")

    # ---------- Menu actions ----------
    @rumps.clicked("Enabled")
    def toggle_enabled(self, sender: rumps.MenuItem) -> None:
        self.enabled = not self.enabled
        sender.state = 1 if self.enabled else 0
        self.update_status("running" if self.enabled else "paused")
        self.log("enabled" if self.enabled else "paused")

    @rumps.clicked("Set IMAP Account")
    def set_imap_account_menu(self, _sender) -> None:
        host = self._prompt("IMAP サーバのホスト名 (例: imap.gmail.com)", self.imap_host)
        if host is None:
            return
        port_s = self._prompt("IMAP ポート (通常 993)", str(self.imap_port))
        if port_s is None:
            return
        user = self._prompt("IMAP ユーザー名 (通常はメールアドレス)", self.imap_user)
        if user is None:
            return
        folder = self._prompt("メールボックス/フォルダ (通常 INBOX)", self.imap_folder)
        if folder is None:
            return

        try:
            port = int(port_s.strip())
        except ValueError:
            port = DEFAULT_IMAP_PORT

        self.imap_host = host.strip()
        self.imap_port = port
        self.imap_user = user.strip()
        self.imap_folder = folder.strip() or DEFAULT_IMAP_FOLDER

        config = self._load_config()
        config.update(
            {
                "imap_host": self.imap_host,
                "imap_port": self.imap_port,
                "imap_user": self.imap_user,
                "imap_folder": self.imap_folder,
            }
        )
        self._save_config(config)
        self.log(f"imap account updated: {self.imap_user!r}@{self.imap_host!r}:{self.imap_port} [{self.imap_folder}]")
        self.notify("Forti", f"IMAP 設定を保存しました ({self.imap_host})")

    @rumps.clicked("Set IMAP Password")
    def set_imap_password_menu(self, _sender) -> None:
        pw = self._prompt("IMAP メールボックスのパスワード（2段階認証環境ではアプリパスワード）を保存します。", "", secure=True)
        if pw is None:
            return
        pw = pw.strip()
        if not pw:
            self._alert("Password is empty.")
            return
        try:
            self.set_keychain_password(IMAP_KEYCHAIN_SERVICE, pw)
            self.log("imap password saved to keychain")
            self.notify("Forti", "IMAP パスワードを保存しました")
        except Exception as e:
            self.log(f"set imap password error: {e}")
            self._alert(f"保存に失敗しました: {e}")

    @rumps.clicked("Test IMAP Login")
    def test_imap_login(self, _sender) -> None:
        if not self.imap_host or not self.imap_user:
            self._alert("先に Set IMAP Account で接続先を設定してください。")
            return
        try:
            pw = self.get_keychain_password(IMAP_KEYCHAIN_SERVICE)
        except subprocess.CalledProcessError:
            self._alert("IMAP パスワードが未保存です。Set IMAP Password から保存してください。")
            return
        conn = None
        try:
            conn = imaplib.IMAP4_SSL(self.imap_host, self.imap_port)
            conn.login(self.imap_user, pw)
            conn.select(self.imap_folder, readonly=True)
            self.log("imap login test ok")
            self.notify("Forti", "IMAP ログイン成功")
        except Exception as e:
            self.log(f"imap login test error: {e}")
            self._alert(f"IMAP ログインに失敗しました: {e}")
        finally:
            if conn is not None:
                try:
                    conn.logout()
                except Exception:
                    pass

    @rumps.clicked("Set Password")
    def set_password_menu(self, _sender) -> None:
        password = self._prompt("Forti VPN password を保存または更新します。", "", secure=True)
        if password is None:
            return
        password = password.strip()
        if not password:
            self._alert("Password is empty.")
            return
        try:
            self.set_keychain_password(KEYCHAIN_SERVICE, password)
            self.log("password saved to keychain")
            self.notify("Forti", "パスワードを保存しました")
        except Exception as e:
            self.log(f"set password error: {e}")
            self._alert(f"保存に失敗しました: {e}")

    @rumps.clicked("Delete Password")
    def delete_password_menu(self, _sender) -> None:
        if not self._confirm("保存済みの Forti VPN password を削除しますか？", "Delete Password", "Delete"):
            return
        try:
            self.delete_keychain_password(KEYCHAIN_SERVICE)
            self.log("password deleted from keychain")
            self.notify("Forti", "保存したパスワードを削除しました")
        except subprocess.CalledProcessError:
            self.log("delete password: no keychain item")
            self._alert("保存済みパスワードが見つかりませんでした。")
        except Exception as e:
            self.log(f"delete password error: {e}")
            self._alert(f"削除に失敗しました: {e}")

    @rumps.clicked("Test Keychain Read")
    def test_keychain_read(self, _sender) -> None:
        try:
            pw = self.get_keychain_password(KEYCHAIN_SERVICE)
            self.log(f"keychain read ok: len={len(pw)}")
            self.notify("Forti", "キーチェーン読み取り成功")
        except Exception as e:
            self.log(f"keychain read error: {e}")
            self._alert(f"読み取りに失敗しました: {e}")

    @rumps.clicked("Show Last Log")
    def show_last_log(self, _sender) -> None:
        msg = self.last_status.replace("\\", "\\\\").replace('"', '\\"')
        script = f'display dialog "{msg}" with title "Last Log" buttons {{"OK"}} default button "OK"'
        try:
            self.run_osascript(script)
        except Exception:
            pass

    @rumps.clicked("Quit")
    def quit_app(self, _sender) -> None:
        rumps.quit_application()


if __name__ == "__main__":
    FortiMenuApp().run()
