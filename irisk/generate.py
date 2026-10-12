"""Synthetic enterprise identity-log generator.

Produces authentication + access events for a 400-person company
(Pune HQ, Mumbai/Bengaluru/Hyderabad offices, remote staff) over 60 days,
with labelled attack scenarios injected on top of realistic normal behaviour:

  impossible_travel   login from a far city minutes after a normal login
  credential_stuffing burst of failed logins from rotating foreign IPs, then a success
  mfa_fatigue         many MFA push denials followed by an approval
  privilege_misuse    user opens admin / finance apps their role never uses
  data_exfiltration   off-hours bulk download from a sensitive app
  dormant_account     account unused for 30+ days suddenly active from a new device
  session_hijack      token replay from a hosting-provider ASN + new device mid-session

Why synthetic? Real identity logs are confidential; public sets (e.g. LANL)
lack geo/MFA/app context. The generator is seeded and fully reproducible.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

CITIES = {  # name: (lat, lon, country)
    "Pune": (18.52, 73.86, "IN"), "Mumbai": (19.08, 72.88, "IN"), "Bengaluru": (12.97, 77.59, "IN"),
    "Hyderabad": (17.39, 78.49, "IN"), "Delhi": (28.61, 77.21, "IN"), "Chennai": (13.08, 80.27, "IN"),
    "Nagpur": (21.15, 79.09, "IN"), "Dubai": (25.20, 55.27, "AE"), "Singapore": (1.35, 103.82, "SG"),
    "London": (51.51, -0.13, "GB"), "Frankfurt": (50.11, 8.68, "DE"), "New York": (40.71, -74.01, "US"),
    "San Jose": (37.34, -121.89, "US"), "Moscow": (55.76, 37.62, "RU"), "Lagos": (6.52, 3.38, "NG"),
    "Sao Paulo": (-23.55, -46.63, "BR"), "Beijing": (39.90, 116.40, "CN"), "Amsterdam": (52.37, 4.90, "NL"),
}
OFFICES = ["Pune", "Pune", "Pune", "Mumbai", "Bengaluru", "Hyderabad"]
ATTACKER_CITIES = ["Moscow", "Lagos", "Sao Paulo", "Beijing", "Amsterdam", "Frankfurt", "New York"]
ROLES = {  # role: (apps used, share of staff)
    "engineer": (["email", "jira", "github", "confluence", "aws_console", "slack"], 0.40),
    "sales": (["email", "crm", "slack", "docs", "zoom"], 0.20),
    "finance": (["email", "erp_finance", "payroll", "docs", "slack"], 0.10),
    "hr": (["email", "hrms", "payroll", "docs", "slack"], 0.08),
    "support": (["email", "ticketing", "crm", "slack"], 0.15),
    "it_admin": (["email", "iam_admin", "aws_console", "siem", "slack", "github"], 0.07),
}
SENSITIVE = {"payroll", "erp_finance", "iam_admin", "hrms", "aws_console", "crm"}
ASN_CORP, ASN_ISP, ASN_HOSTING = "AS-CORP-VPN", "AS-HOME-ISP", "AS-CLOUD-HOSTING"


def make_users(n, rng):
    roles = rng.choice(list(ROLES), size=n, p=[v[1] for v in ROLES.values()])
    users = []
    for i, r in enumerate(roles):
        users.append({"user": f"u{i:04d}", "role": r, "home": rng.choice(OFFICES),
                      "start_hour": float(rng.normal(9.5, 1.0)), "remote": rng.random() < 0.25,
                      "devices": [f"dev-{i:04d}-{k}" for k in range(rng.integers(1, 3))],
                      "dormant_from": None})
    return users


def generate(n_users=400, days=60, seed=7):
    rng = np.random.default_rng(seed)
    users = make_users(n_users, rng)
    start = datetime(2026, 1, 5)
    rows = []

    def ev(u, ts, city, action="login", success=True, app="sso", device=None, asn=None, mb=0.0,
           mfa="approved", label="normal", ip=None):
        lat, lon, cc = CITIES[city]
        rows.append({"ts": ts, "user": u["user"], "role": u["role"], "action": action, "app": app,
                     "success": int(success), "mfa": mfa, "city": city, "country": cc, "lat": lat, "lon": lon,
                     "device": device or u["devices"][0], "asn": asn or (ASN_ISP if u["remote"] else ASN_CORP),
                     "ip": ip or f"10.{rng.integers(0, 255)}.{rng.integers(0, 255)}.{rng.integers(1, 254)}",
                     "download_mb": round(mb, 1), "label": label})

    # dormant users (long leave / leavers not de-provisioned)
    for u in rng.choice(users, size=8, replace=False):
        u["dormant_from"] = int(rng.integers(5, 15))

    for d in range(days):
        day = start + timedelta(days=d)
        weekend = day.weekday() >= 5
        for u in users:
            if u["dormant_from"] is not None and d >= u["dormant_from"]:
                continue
            if weekend and rng.random() > 0.08:
                continue
            if not weekend and rng.random() < 0.06:      # leave / sick day
                continue
            h = float(np.clip(rng.normal(u["start_hour"], 0.6), 6, 13))
            ts = day + timedelta(hours=h)
            city = u["home"] if rng.random() > 0.02 else rng.choice(["Delhi", "Chennai", "Nagpur", "Mumbai"])
            dev = rng.choice(u["devices"]) if rng.random() > 0.01 else f"dev-new-{rng.integers(1e6)}"
            if rng.random() < 0.05:                       # fat-fingered password
                ev(u, ts - timedelta(seconds=40), city, success=False, mfa="none", device=dev)
            ev(u, ts, city, device=dev, mfa="approved" if rng.random() > 0.02 else "denied_then_approved")
            apps = ROLES[u["role"]][0]
            for _ in range(rng.integers(3, 9)):
                ts2 = ts + timedelta(minutes=int(rng.integers(5, 540)))
                app = rng.choice(apps)
                mb = float(rng.lognormal(1.0, 1.0)) if rng.random() < 0.3 else 0.0
                ev(u, ts2, city, action="access", app=app, device=dev, mb=mb, mfa="session")
            if rng.random() < 0.03:                       # occasional cross-team access (benign)
                other = rng.choice([a for r, (aa, _) in ROLES.items() for a in aa if a not in SENSITIVE])
                ev(u, ts + timedelta(hours=3), city, action="access", app=other, device=dev, mfa="session")
            if rng.random() < 0.01:                       # genuine business trip abroad (benign travel)
                ev(u, ts + timedelta(hours=14), rng.choice(["Dubai", "Singapore", "London"]),
                   device=dev, asn=ASN_ISP, mfa="approved")

    # ---------------- attacks ----------------
    active = [u for u in users if u["dormant_from"] is None]
    for _ in range(25):   # impossible travel
        u = rng.choice(active); d = int(rng.integers(3, days))
        ts = start + timedelta(days=d, hours=float(rng.uniform(9, 17)))
        ev(u, ts, u["home"])
        ev(u, ts + timedelta(minutes=int(rng.integers(8, 90))), rng.choice(ATTACKER_CITIES),
           device=f"dev-x-{rng.integers(1e6)}", asn=ASN_HOSTING, label="impossible_travel")
    for _ in range(20):   # credential stuffing
        u = rng.choice(active); ts = start + timedelta(days=int(rng.integers(3, days)), hours=float(rng.uniform(0, 24)))
        city = rng.choice(ATTACKER_CITIES)
        for k in range(int(rng.integers(8, 30))):
            ev(u, ts + timedelta(seconds=7 * k), rng.choice(ATTACKER_CITIES), success=False, mfa="none",
               device="headless-bot", asn=ASN_HOSTING, label="credential_stuffing")
        ev(u, ts + timedelta(minutes=5), city, device="headless-bot", asn=ASN_HOSTING, mfa="approved",
           label="credential_stuffing")
    for _ in range(20):   # MFA fatigue
        u = rng.choice(active); ts = start + timedelta(days=int(rng.integers(3, days)), hours=float(rng.uniform(0, 5)))
        city = rng.choice(ATTACKER_CITIES)
        for k in range(int(rng.integers(5, 15))):
            ev(u, ts + timedelta(minutes=k), city, success=False, mfa="denied", device=f"dev-x-{rng.integers(1e6)}",
               asn=ASN_HOSTING, label="mfa_fatigue")
        ev(u, ts + timedelta(minutes=16), city, mfa="approved", device=f"dev-x-{rng.integers(1e6)}",
           asn=ASN_HOSTING, label="mfa_fatigue")
    for _ in range(25):   # privilege misuse (insider)
        u = rng.choice([x for x in active if x["role"] in ("sales", "support", "engineer")])
        ts = start + timedelta(days=int(rng.integers(5, days)), hours=float(rng.uniform(10, 18)))
        for app in rng.choice(["iam_admin", "payroll", "erp_finance", "hrms"], size=2, replace=False):
            ev(u, ts, u["home"], action="access", app=app, mfa="session", label="privilege_misuse",
               mb=float(rng.uniform(5, 80)))
            ts += timedelta(minutes=12)
    for _ in range(20):   # data exfiltration, off hours
        u = rng.choice(active); ts = start + timedelta(days=int(rng.integers(5, days)), hours=float(rng.uniform(0.5, 4.5)))
        app = rng.choice([a for a in ROLES[u["role"]][0] if a != "slack"])
        for k in range(int(rng.integers(3, 8))):
            ev(u, ts + timedelta(minutes=6 * k), u["home"], action="access", app=app, mfa="session",
               mb=float(rng.uniform(400, 3000)), asn=ASN_ISP, label="data_exfiltration")
    for u in [x for x in users if x["dormant_from"] is not None]:   # dormant takeover
        ts = start + timedelta(days=int(rng.integers(u["dormant_from"] + 30, days + 30)) if u["dormant_from"] + 30 < days
                               else days - 1, hours=float(rng.uniform(0, 23)))
        if ts > start + timedelta(days=days):
            ts = start + timedelta(days=days - 1, hours=2)
        ev(u, ts, rng.choice(ATTACKER_CITIES + ["Delhi"]), device=f"dev-x-{rng.integers(1e6)}",
           asn=ASN_HOSTING, label="dormant_account")
        ev(u, ts + timedelta(minutes=10), u["home"], action="access", app=rng.choice(list(SENSITIVE)),
           mfa="session", mb=float(rng.uniform(50, 900)), device=f"dev-x-{rng.integers(1e6)}", asn=ASN_HOSTING,
           label="dormant_account")
    for _ in range(15):   # session hijack / token replay
        u = rng.choice(active); ts = start + timedelta(days=int(rng.integers(3, days)), hours=float(rng.uniform(11, 16)))
        ev(u, ts, u["home"], action="access", app=rng.choice(ROLES[u["role"]][0]), mfa="session")
        ev(u, ts + timedelta(minutes=3), rng.choice(ATTACKER_CITIES), action="access",
           app=rng.choice(ROLES[u["role"]][0]), mfa="session", device="unknown-ua", asn=ASN_HOSTING,
           mb=float(rng.uniform(20, 400)), label="session_hijack")

    df = pd.DataFrame(rows).sort_values("ts").reset_index(drop=True)
    df["is_attack"] = (df["label"] != "normal").astype(int)
    return df


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/identity_events.csv.gz")
    a = ap.parse_args()
    df = generate()
    df.to_csv(a.out, index=False)
    print(df.shape)
    print(df.label.value_counts())
