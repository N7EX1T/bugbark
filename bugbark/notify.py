import html
import json
import urllib.error
import urllib.request

from .util import UA, log


class Notifier:
    def __init__(self, cfg):
        self.c = cfg["notify"]

    @property
    def ntfy(self):
        return bool(self.c.get("ntfy_topic"))

    @property
    def telegram(self):
        return bool(self.c.get("telegram_token") and self.c.get("telegram_chat_id"))

    @property
    def enabled(self):
        return self.ntfy or self.telegram

    def send(self, title, message, priority=3, click=None, actions=None):
        """actions: list of (label, url) buttons shown under the notification."""
        log.info("Notification: %s", title)
        if not self.enabled:
            log.warning("No notification channel configured, logged only")
            return False
        ok = False
        if self.ntfy:
            try:
                self._ntfy(title, message, priority, click, actions or [])
                ok = True
            except Exception as e:
                log.error("ntfy: send failed: %s", e)
        if self.telegram:
            try:
                self._telegram(title, message, actions or [])
                ok = True
            except Exception as e:
                log.error("Telegram: send failed: %s", e)
        return ok

    def _post(self, url, payload, headers=None):
        hdrs = {"User-Agent": UA, "Content-Type": "application/json"}
        hdrs.update(headers or {})
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=hdrs)
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read()

    def _ntfy(self, title, message, priority, click, actions):
        payload = {
            "topic": self.c["ntfy_topic"],
            "title": title,
            "message": message,
            "priority": priority,
        }
        if click:
            payload["click"] = click
        if actions:
            payload["actions"] = [{"action": "view", "label": l, "url": u, "clear": False} for l, u in actions[:3]]
        headers = {}
        if self.c.get("ntfy_token"):
            headers["Authorization"] = "Bearer " + self.c["ntfy_token"]
        self._post(self.c["ntfy_server"].rstrip("/") + "/", payload, headers)

    def _telegram(self, title, message, actions):
        url = f"https://api.telegram.org/bot{self.c['telegram_token']}/sendMessage"
        text = f"<b>{html.escape(title)}</b>\n{html.escape(message)}"
        for label, link in actions:
            text += f'\n<a href="{html.escape(link, quote=True)}">{html.escape(label)}</a>'
        payload = {"chat_id": self.c["telegram_chat_id"], "text": text,
                   "parse_mode": "HTML", "disable_web_page_preview": True}
        try:
            self._post(url, payload)
        except urllib.error.HTTPError as e:
            if e.code != 400:
                raise
            # Telegram rejects some links (e.g. private addresses), so fall back to plain text
            plain = f"{title}\n{message}\n" + "\n".join(f"{l}: {u}" for l, u in actions)
            self._post(url, {"chat_id": self.c["telegram_chat_id"], "text": plain,
                             "disable_web_page_preview": True})
