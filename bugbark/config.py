import copy
import os
import tomllib

DEFAULT_VENDORS = [
    "Microsoft", "Windows", "Exchange Server", "SharePoint", "Outlook",
    "Apple", "iOS", "macOS", "Safari",
    "Google", "Chrome", "Chromium", "Android",
    "Linux kernel", "Red Hat", "Ubuntu", "Debian",
    "Cisco", "Fortinet", "FortiOS", "FortiGate", "Ivanti", "Palo Alto Networks", "PAN-OS",
    "VMware", "Broadcom", "Citrix", "NetScaler", "Juniper", "F5", "BIG-IP", "SonicWall",
    "Check Point", "Zyxel", "MikroTik",
    "Oracle", "SAP", "IBM", "Adobe", "Mozilla", "Firefox", "Thunderbird",
    "Atlassian", "Confluence", "Jira",
    "Apache", "Tomcat", "nginx", "OpenSSL", "OpenSSH", "sudo", "glibc", "Samba", "Exim",
    "Kubernetes", "Docker", "GitLab", "Jenkins",
    "Veeam", "Progress Software", "MOVEit", "Zimbra", "Roundcube",
    "WinRAR", "7-Zip", "Telegram", "WhatsApp", "Zoom", "Node.js", "OpenVPN",
    "Synology", "QNAP", "Samsung", "Qualcomm", "Intel", "AMD", "NVIDIA",
]

DEFAULTS = {
    "notify": {
        "ntfy_server": "https://ntfy.sh",
        "ntfy_topic": "",
        "ntfy_token": "",
        "telegram_token": "",
        "telegram_chat_id": "",
    },
    "web": {"host": "0.0.0.0", "port": 8080, "public_url": "", "token": ""},
    "cve": {
        "check_minutes": 15,
        "nvd_api_key": "",
        "min_cvss": 9.0,
        "epss_threshold": 0.5,
        "any_vendor_min_cvss": 0,
        "max_per_run": 8,
        "initial_days": 3,
        "keep_days": 60,
        "vendors": DEFAULT_VENDORS,
        "watch": [],
        "watch_min_cvss": 7.0,
        # "all": every major CVE; "exploited": only actively exploited ones and newly published exploits;
        # "off": nothing instant, rely on the daily digest
        "instant": "all",
        "poc_search": True,
        "github_token": "",
    },
    "digest": {"enabled": True, "hour_utc": 6},
    "monitor": {
        "interval_seconds": 60,
        "fail_threshold": 2,
        "timeout_seconds": 10,
        "sites": [],
        "ports": [],
    },
    "status_pages": {
        "interval_seconds": 300,
        "pages": {
            "GitHub": "https://www.githubstatus.com",
            "Cloudflare": "https://www.cloudflarestatus.com",
            "Discord": "https://discordstatus.com",
            "OpenAI": "https://status.openai.com",
            "Claude": "https://status.claude.com",
            "npm": "https://status.npmjs.org",
            "Reddit": "https://www.redditstatus.com",
            "Dropbox": "https://status.dropbox.com",
        },
    },
}


def _merge(base, over):
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict) and k != "pages":
            _merge(base[k], v)
        else:
            base[k] = v
    return base


# Secrets can come from the environment (e.g. GitHub Actions secrets) instead of the file
ENV_OVERRIDES = {
    "NTFY_SERVER": ("notify", "ntfy_server"),
    "NTFY_TOPIC": ("notify", "ntfy_topic"),
    "NTFY_TOKEN": ("notify", "ntfy_token"),
    "TELEGRAM_TOKEN": ("notify", "telegram_token"),
    "TELEGRAM_CHAT_ID": ("notify", "telegram_chat_id"),
    "NVD_API_KEY": ("cve", "nvd_api_key"),
    "GITHUB_TOKEN": ("cve", "github_token"),
    "BUGBARK_PUBLIC_URL": ("web", "public_url"),
    "BUGBARK_WEB_TOKEN": ("web", "token"),
}


def load_config(path):
    cfg = copy.deepcopy(DEFAULTS)
    try:
        with open(path, "rb") as f:
            _merge(cfg, tomllib.load(f))
    except FileNotFoundError:
        pass
    for var, (section, key) in ENV_OVERRIDES.items():
        if os.environ.get(var):
            cfg[section][key] = os.environ[var]
    return cfg
