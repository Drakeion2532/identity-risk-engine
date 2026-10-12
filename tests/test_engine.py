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
