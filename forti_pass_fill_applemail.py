#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
macOS menubar resident helper for FortiClient password autofill.
What it does:
- Runs as a menu bar app
- Watches for Forti-related windows
- Autofills only the saved password from Keychain
- Does NOT touch email / OTP flow
- Lets you set / update / delete the password from the menu bar
- Autofills only when the visible UI text inside window 1 contains "password"
Requirements:
    pip install rumps pyobjc
First-time permissions:
- Terminal / the packaged app needs Accessibility permission
- Keychain access prompt may appear on first read/write
Run:
    python3 forti_menu_autofill.py
"""
from __future__ import annotations
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from typing import Optional
import rumps
from Quartz import (
    CGWindowListCopyWindowInfo,
    kCGNullWindowID,
    kCGWindowListOptionOnScreenOnly,
    kCGWindowListExcludeDesktopElements,
)

DEFAULT_MAIL_ACCOUNT = "NIG"
# 送信者アドレスは環境で変わりうる（自分宛転送など）ので、デフォルトでは送信者で絞らず
# 件名の AuthCode パターンで判定する。特定の送信者だけに限定したい場合はここに文字列を入れる。
TARGET_SENDER = ""
SUBJECT_PATTERN = re.compile(r"AuthCode:\s*(\d+)")
# OTP は短命なので、これより古い（受信からの経過秒）メールのコードは使い回しとみなし無視する
TOKEN_MAX_AGE_SEC = 300
APP_TITLE = "🐾" # menu bar icon (emoji)
KEYCHAIN_SERVICE = "FortiVPNAuth"
CONFIG_PATH = os.path.expanduser("~/.forti_menu_autofill.json")
LOG_PATH = os.path.expanduser("~/forti_autofill.log")
WATCH_INTERVAL_SEC = 0.4
PASSWORD_COOLDOWN_SEC = 8.0
OWNERS = {
    "FortiClientAgent",
    "FortiTray",
}

GETMAIL_APPLESCRIPT_TEMPLATE = """
tell application "Mail"
    set sep to "|||"
    set rowsep to "^^^"
    set output to ""
    set targetAccount to account "{MAIL_ACCOUNT}"
    check for new mail for targetAccount
    delay 5
    set nowDate to (current date)
    set mb to mailbox "INBOX" of targetAccount
    set msgs to (messages of mb whose read status is false)
    repeat with m in msgs
        set sndr to sender of m
        set sub to subject of m
        set ago to (nowDate - (date received of m))
        set output to output & sndr & sep & sub & sep & ago & rowsep
    end repeat
    return output
end tell
"""


class FortiMenuApp(rumps.App):
    def __init__(self) -> None:
        super().__init__(APP_TITLE, quit_button=None)
        self.last_password_handled: dict[int, float] = {}
        self.enabled = True
        self.last_status = "Starting"
        self.mail_account = self._load_config().get("mail_account", DEFAULT_MAIL_ACCOUNT)
        self.status_item = rumps.MenuItem("Status: starting")
        self.enable_item = rumps.MenuItem("Enabled")
        self.enable_item.state = 1
        self.mail_account_item = rumps.MenuItem(f"Mail Account: {self.mail_account}")
        self.menu = [
            self.status_item,
            None,
            self.enable_item,
            "Set Mail Account",
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

    # ---------- Token ----------
    def get_token_from_mail(self, script: str) -> str: 
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            err = (result.stderr or "").strip()
            self.log(f"AppleScript 実行失敗: {err}")
            low = err.lower()
            if "-1743" in err or "not authorized" in low or "permission" in low:
                self.notify(
                    "Forti",
                    "Mail へのオートメーション許可が無効です。"
                    "システム設定>プライバシーとセキュリティ>オートメーションで Terminal(Python)>Mail を許可してください",
                )
            return ""

        raw = result.stdout.strip()
        if not raw:
            self.log("mail: 未読メールが見つかりませんでした")
            return ""

        # 未読メールの中から AuthCode を含むものを集め、最も新しい（受信からの経過が短い）
        # コードを採用する。古い使い回しコードは TOKEN_MAX_AGE_SEC で弾く。
        best_code: Optional[str] = None
        best_ago = float("inf")
        for row in raw.split("^^^"):
            row = row.strip()
            if not row:
                continue
            parts = row.split("|||")
            if len(parts) < 2:
                continue
            sender = parts[0].strip()
            subject = parts[1].strip()
            try:
                ago = float(parts[2].strip()) if len(parts) >= 3 and parts[2].strip() else 0.0
            except ValueError:
                ago = 0.0

            # 送信者で絞りたい場合のみ（TARGET_SENDER が空なら絞らない）
            if TARGET_SENDER and TARGET_SENDER not in sender:
                continue

            m = SUBJECT_PATTERN.search(subject)
            if not m:
                continue
            if ago > TOKEN_MAX_AGE_SEC:
                self.log(f"mail: 古いコードを無視 (ago={int(ago)}s): {subject!r}")
                continue
            if ago < best_ago:
                best_ago = ago
                best_code = m.group(1)

        if best_code is None:
            self.log("mail: 有効な AuthCode メールが見つかりませんでした")
            return ""
        self.log(f"mail: token 取得 (ago={int(best_ago)}s)")
        return best_code

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
            self.log(f"window_contains_password error: proc={proc_name!r} error={e}")
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
                script = GETMAIL_APPLESCRIPT_TEMPLATE.format(MAIL_ACCOUNT=self.mail_account)
                fill_word = self.get_token_from_mail(script)

            if not fill_word:
                self.log(f"fill_word is empty, skipping: word={type!r}")
                if type == "token":
                    self.notify("Forti", "メールからトークンを取得できませんでした（メール未着 or 許可不足）")
                # 取得失敗時も少し待ってから再試行する（0.4秒毎の通知/メール問い合わせ連打を防ぐ）
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

    @rumps.clicked("Set Mail Account")
    def set_mail_account_menu(self, _sender) -> None:
        current = self.mail_account.replace("\\", "\\\\").replace('"', '\\"')
        script = f'''
display dialog "Apple Mail のアカウント名を入力してください。" ¬
    default answer "{current}" ¬
    with title "Set Mail Account" ¬
    buttons {{"Cancel", "Save"}} ¬
    default button "Save"
'''
        try:
            raw = self.run_osascript(script)
        except subprocess.CalledProcessError:
            # ユーザーがキャンセルした場合 (error -128)
            return
        # raw = 'button returned:Save, text returned:NIG' の形式
        match = re.search(r"text returned:(.*)", raw)
        if not match:
            return
        account = match.group(1).strip()
        if not account:
            self._alert("Account name is empty.")
            return
        self.mail_account = account
        self.mail_account_item.title = f"Mail Account: {account}"
        config = self._load_config()
        config["mail_account"] = account
        self._save_config(config)
        self.log(f"mail account updated: {account!r}")
        self.notify("Forti", f"Mail アカウントを「{account}」に設定しました")

    @rumps.clicked("Set Password")
    def set_password_menu(self, _sender) -> None:
        script = '''
display dialog "Forti VPN password を保存または更新します。" ¬
    default answer "" ¬
    with hidden answer ¬
    with title "Set Forti Password" ¬
    buttons {"Cancel", "Save"} ¬
    default button "Save"
'''
        try:
            raw = self.run_osascript(script)
        except subprocess.CalledProcessError:
            return
        match = re.search(r"text returned:(.*)", raw)
        if not match:
            return
        password = match.group(1).strip()
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
