"""Run the engine on real identity-provider logs: Okta System Log events.

The engine was built and evaluated on synthetic events, but its input is deliberately close to
what identity providers already log. This adapter converts Okta System Log `LogEvent` objects
(the JSON returned by GET /api/v1/logs, or an export of it) into engine events and replays them
in time order, returning a decision and reasons for every event.

    python -m irisk.okta examples/okta_system_log_sample.json --roles examples/roles.csv
    -> results/okta_decisions.csv  + a summary of what would have been stepped up or blocked

Field mapping (Okta -> engine):
    published                                  -> ts
    actor.alternateId                          -> user
    roles file (user,role)                     -> role   (Okta logs don't carry a job role)
    eventType user.session.start               -> action "login", app "sso"
    eventType user.authentication.sso          -> action "access", app = target AppInstance name
    eventType user.mfa.okta_verify.deny_push   -> failed login with mfa "denied"
    eventType user.authentication.auth_via_mfa -> login with mfa "approved"
    outcome.result SUCCESS / ALLOW             -> success
    client.geographicalContext                 -> city, country, lat, lon
    client.userAgent os + browser              -> device
    securityContext isProxy / asOrg / isp      -> hosting network or the AS number
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .engine import HOSTING_ASN, RiskEngine

HOSTING_HINTS = re.compile(r"amazon|aws|google cloud|google llc|microsoft|azure|digitalocean|linode|akamai|"
                           r"ovh|hetzner|vultr|oracle cloud|alibaba|tencent|contabo|hosting|datacenter|data center|vpn",
                           re.I)
LOGIN_EVENTS = {"user.session.start", "user.authentication.auth_via_mfa", "user.mfa.okta_verify.deny_push",
                "user.authentication.authenticate"}
APP_EVENTS = {"user.authentication.sso", "app.oauth2.as.token.grant"}


def _ts(published: str) -> float:
    return datetime.fromisoformat(published.replace("Z", "+00:00")).timestamp()


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "app"


def to_engine_event(ev: dict, roles: dict[str, str]) -> dict | None:
    """Convert one Okta LogEvent to the engine's event dict; None for event types the engine ignores."""
    etype = ev.get("eventType", "")
    if etype not in LOGIN_EVENTS | APP_EVENTS:
        return None
    actor = ev.get("actor") or {}
    user = actor.get("alternateId") or actor.get("id")
    client = ev.get("client") or {}
    geo = client.get("geographicalContext") or {}
    loc = geo.get("geolocation") or {}
    ua = client.get("userAgent") or {}
    sec = ev.get("securityContext") or {}
    result = ((ev.get("outcome") or {}).get("result") or "").upper()

    hosting = bool(sec.get("isProxy")) or bool(HOSTING_HINTS.search(f"{sec.get('asOrg') or ''} {sec.get('isp') or ''}"))
    asn = HOSTING_ASN if hosting else f"AS{sec.get('asNumber')}" if sec.get("asNumber") else "AS-UNKNOWN"

    if etype in APP_EVENTS:
        targets = [t for t in ev.get("target") or [] if t.get("type") == "AppInstance"]
        action, app = "access", _slug(targets[0].get("displayName", "app")) if targets else "app"
    else:
        action, app = "login", "sso"
    if etype == "user.mfa.okta_verify.deny_push":
        mfa, success = "denied", False
    elif etype == "user.authentication.auth_via_mfa":
        mfa, success = "approved", result in ("SUCCESS", "ALLOW")
    else:
        mfa, success = ("session" if action == "access" else "none"), result in ("SUCCESS", "ALLOW")

    return {"ts": _ts(ev["published"]), "user": user, "role": roles.get(user, "unknown"),
            "action": action, "app": app, "success": int(success), "mfa": mfa,
            "city": geo.get("city") or "unknown", "country": geo.get("country") or "unknown",
            "lat": float(loc.get("lat") or 0.0), "lon": float(loc.get("lon") or 0.0),
            "device": f"{ua.get('os') or '?'}/{ua.get('browser') or '?'}", "asn": asn,
            "ip": client.get("ipAddress"), "download_mb": 0.0,
            "okta_uuid": ev.get("uuid"), "okta_event_type": etype}


def load_events(path: Path) -> list[dict]:
    """Accepts a JSON array (API response / export) or newline-delimited JSON."""
    text = path.read_text().strip()
    if text.startswith("["):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def load_roles(path: Path | None) -> dict[str, str]:
    if not path:
        return {}
    with open(path, newline="") as f:
        return {r["user"]: r["role"] for r in csv.DictReader(f)}


def replay(okta_events: list[dict], roles: dict[str, str], engine: RiskEngine | None = None) -> list[dict]:
    engine = engine or RiskEngine()
    events = [e for e in (to_engine_event(ev, roles) for ev in okta_events) if e]
    out = []
    for e in sorted(events, key=lambda e: e["ts"]):
        _, reasons, risk = engine.process(e)
        out.append({"time": datetime.fromtimestamp(e["ts"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "user": e["user"],
                    "event": e["okta_event_type"], "app": e["app"], "city": e["city"], "country": e["country"],
                    "risk": round(risk, 1), "decision": engine.decide(risk),
                    "reasons": "; ".join(x["why"] for x in engine.explain(reasons)), "okta_uuid": e["okta_uuid"]})
    return out


def main():
    ap = argparse.ArgumentParser(description="Replay an Okta System Log export through the risk engine.")
    ap.add_argument("log_json")
    ap.add_argument("--roles", type=Path, help="CSV with columns user,role")
    ap.add_argument("--out", type=Path, default=Path("results/okta_decisions.csv"))
    a = ap.parse_args()
    rows = replay(load_events(Path(a.log_json)), load_roles(a.roles))
    a.out.parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    flagged = [r for r in rows if r["decision"] != "allow"]
    print(f"{len(rows)} Okta events scored -> {len(flagged)} would be stepped up or blocked. Written to {a.out}")
    for r in flagged:
        print(f"  {r['time']}  {r['user']:<22} {r['decision']:<16} risk {r['risk']:>5}  {r['reasons']}")


if __name__ == "__main__":
    main()
