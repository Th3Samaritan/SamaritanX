"""Owned Appium sessions for explicitly selected devices and preinstalled test apps."""
import asyncio
import re
from .mobile_dynamic import Session, assess, AppiumError
from .common import result


def capabilities(platform, app_id, device_id):
    if platform not in {"android", "ios"} or not re.fullmatch(r"[A-Za-z0-9._-]+", app_id):
        raise ValueError("invalid app or platform")
    if not isinstance(device_id, str) or not re.fullmatch(r"[A-Za-z0-9:._-]{1,160}", device_id):
        raise ValueError("explicit device ID required")
    caps = {"platformName": "Android" if platform == "android" else "iOS",
            "appium:automationName": "UiAutomator2" if platform == "android" else "XCUITest",
            "appium:udid": device_id, "appium:noReset": True, "appium:newCommandTimeout": 60}
    caps["appium:appPackage" if platform == "android" else "appium:bundleId"] = app_id
    return {"capabilities": {"alwaysMatch": caps, "firstMatch": [{}]}}


async def assess_owned(server, platform, app_id, device_id, *, aggressive=False, steps=None, transport=None):
    if not aggressive:
        raise ValueError("creating and launching a device session requires aggressive: true")
    payload = capabilities(platform, app_id, device_id)
    client = Session(server, "creating", platform, app_id, transport=transport)
    client.base = server.rstrip("/")
    report = result("mobile_dynamic", app_id)
    report.update(platform=platform, session_ownership="created", cleanup="not_created")
    session_id = None
    try:
        created = await asyncio.wait_for(client.call("POST", "/session", payload), timeout=60)
        session_id = created.get("sessionId") if isinstance(created, dict) else None
        if not isinstance(session_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", session_id):
            raise AppiumError("session creation did not return a valid session identifier; inspect server for orphaned setup")
        report = await assess(server, session_id, platform, app_id, aggressive=aggressive, steps=steps, transport=transport)
        report["session_ownership"] = "created"
        report["capabilities"] = {k: v for k, v in (created.get("capabilities") or {}).items()
                                  if k in {"platformName", "platformVersion", "appium:automationName"}}
    except Exception as exc:
        report.update(status="blocked")
        report["checks"].append({"check": "session_creation", "status": "unavailable", "reason": type(exc).__name__})
        if session_id is None:
            report["cleanup"] = "creation_outcome_unknown; inspect Appium host"
    finally:
        if session_id:
            try:
                await client.call("DELETE", "/session/" + session_id)
                report["cleanup"] = "completed"
            except Exception:
                report.update(status="partial", cleanup="failed; session remains on Appium host")
        await client.client.aclose()
    return report
