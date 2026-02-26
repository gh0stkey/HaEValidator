#!/usr/bin/env python3
import json
import re
import smtplib
import socket
import subprocess
import sys

STATIC_EXTS = {
    "3g2",
    "3gp",
    "7z",
    "aac",
    "abw",
    "aif",
    "aifc",
    "aiff",
    "apk",
    "arc",
    "au",
    "avi",
    "azw",
    "bat",
    "bin",
    "bmp",
    "bz",
    "bz2",
    "cmd",
    "cmx",
    "cod",
    "csh",
    "css",
    "csv",
    "dll",
    "doc",
    "docx",
    "ear",
    "eot",
    "epub",
    "exe",
    "flac",
    "flv",
    "gif",
    "gz",
    "ico",
    "ics",
    "ief",
    "jar",
    "jfif",
    "jpe",
    "jpeg",
    "jpg",
    "less",
    "m3u",
    "mid",
    "midi",
    "mjs",
    "mkv",
    "mov",
    "mp2",
    "mp3",
    "mp4",
    "mpa",
    "mpe",
    "mpeg",
    "mpg",
    "mpkg",
    "mpp",
    "mpv2",
    "odp",
    "ods",
    "odt",
    "oga",
    "ogg",
    "ogv",
    "ogx",
    "otf",
    "pbm",
    "pdf",
    "pgm",
    "png",
    "pnm",
    "ppm",
    "ppt",
    "pptx",
    "ra",
    "ram",
    "rar",
    "ras",
    "rgb",
    "rmi",
    "rtf",
    "scss",
    "sh",
    "snd",
    "svg",
    "swf",
    "tar",
    "tif",
    "tiff",
    "ttf",
    "vsd",
    "war",
    "wav",
    "weba",
    "webm",
    "webp",
    "wmv",
    "woff",
    "woff2",
    "xbm",
    "xls",
    "xlsx",
    "xpm",
    "xul",
    "xwd",
    "zip",
}

TEST_RE = re.compile(
    r"test|example|sample|demo|fake|dummy|placeholder|tmp|temp|foo|bar|"
    r"abc|xxx|yyy|zzz|asdf|qwer|noreply|no-reply|nobody|null|void",
    re.IGNORECASE,
)

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

_mx_cache = {}
_smtp_cache = {}


def has_static_ext(email):
    email = email.lower()
    return any(f".{ext}" in email or f"@{ext}." in email for ext in STATIC_EXTS)


def get_mx_host(domain):
    if domain in _mx_cache:
        return _mx_cache[domain]

    mx_host, min_pri = None, float("inf")
    try:
        out = subprocess.run(
            ["nslookup", "-type=mx", domain],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
        for line in out.split("\n"):
            if "mail exchanger" in line.lower():
                parts = line.split("=")
                if len(parts) >= 2:
                    tokens = parts[-1].strip().split()
                    if len(tokens) >= 2:
                        pri, host = int(tokens[0]), tokens[1].rstrip(".")
                        if pri < min_pri:
                            min_pri, mx_host = pri, host
    except Exception:
        pass
    _mx_cache[domain] = mx_host
    return mx_host


def verify_smtp(email, mx_host):
    key = email.lower()
    if key in _smtp_cache:
        return _smtp_cache[key]

    for port in [25, 587, 465]:
        try:
            if port == 465:
                smtp = smtplib.SMTP_SSL(mx_host, port, timeout=10)
            else:
                smtp = smtplib.SMTP(mx_host, port, timeout=10)
                if port == 587:
                    try:
                        smtp.starttls()
                    except smtplib.SMTPException:
                        pass
            with smtp:
                smtp.helo("verify.local")
                smtp.mail("verify@verify.local")
                code, _ = smtp.rcpt(email)
                if code == 250:
                    _smtp_cache[key] = True
                    return True
        except (smtplib.SMTPException, socket.error, OSError):
            continue

    _smtp_cache[key] = False
    return False


def validate(email):
    email = email.strip()

    if has_static_ext(email) or not EMAIL_RE.match(email):
        return "none"

    if TEST_RE.search(email):
        return "low"

    mx_host = get_mx_host(email.split("@")[-1])
    if not mx_host:
        return "low"

    return "high" if verify_smtp(email, mx_host) else "medium"


def main():
    data = json.load(sys.stdin)
    results = [
        {
            "index": item.get("index", 0),
            "tags": validate(item.get("data", {}).get("match", "")),
        }
        for item in data.get("items", [])
    ]
    print(json.dumps({"results": results}))


if __name__ == "__main__":
    main()
