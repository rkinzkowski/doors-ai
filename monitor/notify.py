"""Desktop notifications for serious alerts.

Raises a native Windows toast via PowerShell's built-in WinRT APIs - no extra
packages to install. Fire-and-forget and throttled so a burst of alerts can't
spam the user. Only high/critical severities notify.
"""

import platform
import subprocess
import threading
import time

_THROTTLE_SEC = 60
_lock = threading.Lock()
_recent = {}
_enabled = True

# PowerShell's registered app id, so the toast reliably appears + lands in the
# Action Center instead of being silently dropped.
_APP_ID = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe"

_TOAST_TEMPLATE = """
$ErrorActionPreference = 'Stop'
$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$n = $t.GetElementsByTagName('text')
$null = $n.Item(0).AppendChild($t.CreateTextNode(@'
{title}
'@))
$null = $n.Item(1).AppendChild($t.CreateTextNode(@'
{message}
'@))
$toast = [Windows.UI.Notifications.ToastNotification]::new($t)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{app}').Show($toast)
"""


def set_enabled(value):
    global _enabled
    _enabled = bool(value)


def is_enabled():
    return _enabled


def _sanitize(text):
    # Close off the here-string so a crafted alert string can't inject script.
    return str(text or "").replace("'@", "' @").replace("\r", " ").replace("\n", " ")[:180]


def _show_toast(title, message):
    if platform.system() != "Windows":
        return
    script = _TOAST_TEMPLATE.format(
        title=_sanitize(title), message=_sanitize(message), app=_APP_ID
    )
    try:
        subprocess.Popen(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        print(f"[NOTIFY] Toast failed: {e}")


def notify(title, message, key=None):
    """Show a toast now, throttled per key so repeats don't spam."""
    if not _enabled:
        return
    key = key or f"{title}:{message}"
    now = time.time()
    with _lock:
        if now - _recent.get(key, 0) < _THROTTLE_SEC:
            return
        _recent[key] = now
    threading.Thread(target=_show_toast, args=(title, message), daemon=True).start()


def notify_if_serious(severity, title, message, key=None):
    if str(severity).lower() in ("high", "critical"):
        notify(title, message, key=key)
