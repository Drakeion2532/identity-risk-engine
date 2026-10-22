from irisk.engine import RiskEngine, haversine

BASE = dict(role="engineer", action="login", app="sso", success=1, mfa="approved", asn="AS-CORP-VPN",
            download_mb=0.0)
PUNE = dict(city="Pune", country="IN", lat=18.52, lon=73.86)
MOSCOW = dict(city="Moscow", country="RU", lat=55.76, lon=37.62)


def warm(eng, user="u1", days=20):
    t = 1_700_000_000
    for d in range(days):
        ts = t + d * 86400 + 9.5 * 3600
        eng.process({**BASE, **PUNE, "user": user, "ts": ts, "device": "laptop-1"})
        eng.process({**BASE, **PUNE, "user": user, "ts": ts + 3600, "action": "access", "app": "github",
                     "mfa": "session", "device": "laptop-1", "download_mb": 5.0})
    return t + days * 86400


def test_haversine_pune_mumbai():
    assert 110 < haversine(18.52, 73.86, 19.08, 72.88) < 130


def test_normal_login_is_allowed():
    eng = RiskEngine()
    t = warm(eng)
    _, reasons, risk = eng.process({**BASE, **PUNE, "user": "u1", "ts": t + 9.5 * 3600, "device": "laptop-1"})
    assert risk < 40 and eng.decide(risk) == "allow"


def test_impossible_travel_blocked():
    eng = RiskEngine()
    t = warm(eng) + 10 * 3600
    eng.process({**BASE, **PUNE, "user": "u1", "ts": t, "device": "laptop-1"})
    _, reasons, risk = eng.process({**BASE, **MOSCOW, "user": "u1", "ts": t + 1800, "device": "x",
                                    "asn": "AS-CLOUD-HOSTING"})
    assert "impossible_travel" in reasons and eng.decide(risk) == "block_and_alert"


def test_mfa_fatigue():
    eng = RiskEngine()
    t = warm(eng)
    for k in range(5):
        eng.process({**BASE, **PUNE, "user": "u1", "ts": t + 60 * k, "device": "laptop-1", "success": 0,
                     "mfa": "denied"})
    _, reasons, risk = eng.process({**BASE, **PUNE, "user": "u1", "ts": t + 400, "device": "laptop-1"})
    assert "mfa_fatigue" in reasons and risk >= 70


def test_bulk_download_flagged():
    eng = RiskEngine()
    t = warm(eng)
    _, reasons, risk = eng.process({**BASE, **PUNE, "user": "u1", "ts": t + 3 * 3600, "action": "access",
                                    "app": "github", "mfa": "session", "device": "laptop-1",
                                    "download_mb": 2500})
    assert "bulk_download" in reasons and risk >= 40


def test_blocked_activity_does_not_poison_baseline():
    eng = RiskEngine()
    t = warm(eng) + 10 * 3600
    eng.process({**BASE, **PUNE, "user": "u1", "ts": t, "device": "laptop-1"})
    eng.process({**BASE, **MOSCOW, "user": "u1", "ts": t + 600, "device": "x", "asn": "AS-CLOUD-HOSTING"})
    assert "RU" not in eng.users["u1"].countries


# ---------------------------------------------------------------- real identity-provider logs (Okta)
from pathlib import Path

from irisk import okta

EX = Path(__file__).resolve().parent.parent / "examples"


def test_okta_event_mapping():
    ev = {"uuid": "u1", "published": "2026-09-30T20:31:00.000Z", "eventType": "user.mfa.okta_verify.deny_push",
          "actor": {"alternateId": "priya@acme.example"}, "outcome": {"result": "DENY"},
          "client": {"ipAddress": "164.92.0.7", "userAgent": {"os": "Linux", "browser": "FIREFOX"},
                     "geographicalContext": {"city": "Amsterdam", "country": "Netherlands",
                                             "geolocation": {"lat": 52.37, "lon": 4.9}}},
          "securityContext": {"asNumber": 14061, "asOrg": "DigitalOcean, LLC", "isProxy": False}}
    e = okta.to_engine_event(ev, {"priya@acme.example": "sales"})
    assert e["user"] == "priya@acme.example" and e["role"] == "sales"
    assert e["mfa"] == "denied" and e["success"] == 0 and e["action"] == "login"
    assert e["asn"] == "AS-CLOUD-HOSTING" and e["country"] == "Netherlands" and e["lat"] == 52.37
    assert okta.to_engine_event({**ev, "eventType": "user.account.update_profile"}, {}) is None


def test_okta_replay_blocks_push_bombing_but_not_a_business_trip():
    rows = okta.replay(okta.load_events(EX / "okta_system_log_sample.json"), okta.load_roles(EX / "roles.csv"))
    rahul = [r for r in rows if r["user"].startswith("rahul")]
    assert rahul and all(r["decision"] == "allow" for r in rahul)          # incl. the Bengaluru trip
    blocked = [r for r in rows if r["decision"] == "block_and_alert"]
    assert len(blocked) == 1 and blocked[0]["event"] == "user.authentication.auth_via_mfa"
    assert "MFA pushes denied recently, then approved" in blocked[0]["reasons"]
    first_attack = next(r for r in rows if r["country"] == "Netherlands")
    assert first_attack["decision"] != "allow"                               # stepped up before any push
