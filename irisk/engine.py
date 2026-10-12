"""Streaming identity risk engine.

For every event the engine compares it with the user's OWN history and their
PEER GROUP (same role), produces explainable risk signals, an anomaly score,
and a Zero-Trust decision:  allow  |  step_up_mfa  |  block_and_alert.
State is updated after scoring, so no event ever sees its own future.
"""
from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field

import numpy as np

HOSTING_ASN = "AS-CLOUD-HOSTING"
# reason code: (weight, human explanation)
SIGNALS = {
    "impossible_travel": (0.85, "travel speed between logins is physically impossible"),
    "new_country": (0.35, "first activity ever from this country"),
    "hosting_asn": (0.30, "connection from a cloud/hosting provider, not an ISP or the corporate VPN"),
    "new_device": (0.20, "device never seen for this user"),
    "brute_force": (0.70, "burst of failed logins in the last 10 minutes"),
    "multi_country_failures": (0.45, "failed logins from several countries in 10 minutes"),
    "mfa_fatigue": (0.80, "many MFA pushes denied recently, then approved"),
    "mfa_denied": (0.30, "MFA push denied"),
    "peer_rare_app": (0.55, "app used by almost nobody in the user's role"),
    "sensitive_app_first_use": (0.40, "first-ever access to a sensitive application"),
    "bulk_download": (0.65, "download volume far above the user's normal"),
    "off_hours": (0.15, "activity outside the user's normal working hours"),
    "dormant_reactivation": (0.65, "account inactive for 21+ days suddenly used"),
}
SENSITIVE = {"payroll", "erp_finance", "iam_admin", "hrms", "aws_console", "crm"}


def haversine(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def circ_hour_dist(a, b):
    d = abs(a - b) % 24
    return min(d, 24 - d)


@dataclass
class UserState:
    last_ts: float | None = None
    last_loc: tuple | None = None
    countries: set = field(default_factory=set)
    devices: set = field(default_factory=set)
    apps: set = field(default_factory=set)
    hours: deque = field(default_factory=lambda: deque(maxlen=60))
    dl_log: deque = field(default_factory=lambda: deque(maxlen=200))
    fails: deque = field(default_factory=lambda: deque(maxlen=200))      # (ts, country)
    mfa_denials: deque = field(default_factory=lambda: deque(maxlen=50))
    n_events: int = 0


class RiskEngine:
    def __init__(self, step_up=40, block=70):
        self.users = defaultdict(UserState)
        self.role_app_users = defaultdict(lambda: defaultdict(set))   # role -> app -> users
        self.role_users = defaultdict(set)
        self.step_up, self.block = step_up, block

    # ------------------------------------------------------------------
    def features(self, e) -> tuple[dict, list[str]]:
        s = self.users[e["user"]]
        t = e["ts"]
        hour = (t % 86400) / 3600
        f, reasons = {}, []
        mature = s.n_events >= 15               # enough history to judge "new"

        # geo-velocity
        speed = 0.0
        if s.last_loc and s.last_ts is not None and e["success"]:
            km = haversine(*s.last_loc, e["lat"], e["lon"])
            hrs = max((t - s.last_ts) / 3600, 1 / 60)
            speed = km / hrs if km > 300 else 0.0
        f["geo_speed_kmh"] = speed
        if speed > 1000:
            reasons.append("impossible_travel")
        f["new_country"] = int(mature and e["country"] not in s.countries)
        f["new_device"] = int(mature and e["device"] not in s.devices)
        f["hosting_asn"] = int(e["asn"] == HOSTING_ASN)
        for k in ("new_country", "new_device", "hosting_asn"):
            if f[k]:
                reasons.append(k)

        recent_fail = [c for ts, c in s.fails if t - ts <= 600]
        f["fails_10m"] = len(recent_fail) + (0 if e["success"] else 1)
        f["fail_countries_10m"] = len(set(recent_fail) | ({e["country"]} if not e["success"] else set()))
        if f["fails_10m"] >= 6:
            reasons.append("brute_force")
        if f["fail_countries_10m"] >= 3:
            reasons.append("multi_country_failures")

        den = [ts for ts in s.mfa_denials if t - ts <= 1800]
        f["mfa_denied_30m"] = len(den) + (1 if e["mfa"] == "denied" else 0)
        if e["mfa"] in ("approved", "denied_then_approved") and len(den) >= 3:
            reasons.append("mfa_fatigue")
        elif e["mfa"] == "denied":
            reasons.append("mfa_denied")

        peers = self.role_users[e["role"]]
        users_with_app = self.role_app_users[e["role"]][e["app"]]
        f["peer_app_share"] = len(users_with_app) / max(1, len(peers)) if e["action"] == "access" else 1.0
        if e["action"] == "access" and len(peers) >= 10 and f["peer_app_share"] < 0.05 and e["app"] not in s.apps:
            reasons.append("peer_rare_app")
        if e["action"] == "access" and mature and e["app"] in SENSITIVE and e["app"] not in s.apps:
            reasons.append("sensitive_app_first_use")

        mb = float(e["download_mb"])
        hist = np.array(s.dl_log) if s.dl_log else np.array([0.0])
        mu, sd = np.log1p(hist).mean(), np.log1p(hist).std() + 0.5
        f["download_z"] = (math.log1p(mb) - mu) / sd if mb > 0 else 0.0
        p95 = float(np.quantile(hist, 0.95)) if len(hist) >= 5 else 50.0
        if mb > 200 and (f["download_z"] > 3 or mb > 10 * max(p95, 10)):
            reasons.append("bulk_download")

        typical = float(np.median(s.hours)) if len(s.hours) >= 5 else 10.0
        f["hour_dev"] = circ_hour_dist(hour, typical)
        if mature and f["hour_dev"] > 6:
            reasons.append("off_hours")
        f["dormant_days"] = (t - s.last_ts) / 86400 if s.last_ts is not None else 0.0
        if f["dormant_days"] >= 21:
            reasons.append("dormant_reactivation")
        f["failed"] = int(not e["success"])
        return f, reasons

    @staticmethod
    def rule_risk(reasons):
        p_safe = 1.0
        for r in reasons:
            p_safe *= 1 - SIGNALS[r][0]
        return round(100 * (1 - p_safe), 1)

    def decide(self, risk):
        return "block_and_alert" if risk >= self.block else "step_up_mfa" if risk >= self.step_up else "allow"

    # ------------------------------------------------------------------
    def update(self, e):
        s = self.users[e["user"]]
        t = e["ts"]
        s.n_events += 1
        if e["success"] and e["mfa"] != "denied":
            # only trusted (successful) activity extends the baseline
            s.last_ts, s.last_loc = t, (e["lat"], e["lon"])
            s.countries.add(e["country"])
            s.devices.add(e["device"])
            if e["action"] == "login":
                s.hours.append((t % 86400) / 3600)
            if e["action"] == "access":
                s.apps.add(e["app"])
                self.role_app_users[e["role"]][e["app"]].add(e["user"])
            if e["download_mb"] > 0:
                s.dl_log.append(float(e["download_mb"]))
        else:
            s.fails.append((t, e["country"]))
        if e["mfa"] == "denied":
            s.mfa_denials.append(t)
        self.role_users[e["role"]].add(e["user"])

    def process(self, e):
        f, reasons = self.features(e)
        risk = self.rule_risk(reasons)
        # never learn from blocked activity: an attacker must not be able to
        # "train" the baseline into accepting their country/device/volume
        if risk < self.block:
            self.update(e)
        else:
            s = self.users[e["user"]]
            s.n_events += 1
            if not e["success"]:
                s.fails.append((e["ts"], e["country"]))
            if e["mfa"] == "denied":
                s.mfa_denials.append(e["ts"])
        return f, reasons, risk

    def explain(self, reasons):
        return [{"signal": r, "weight": SIGNALS[r][0], "why": SIGNALS[r][1]} for r in reasons]
