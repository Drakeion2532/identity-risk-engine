# Identity Risk Engine: UEBA for Zero Trust Access

[![tests](https://github.com/Drakeion2532/identity-risk-engine/actions/workflows/tests.yml/badge.svg)](https://github.com/Drakeion2532/identity-risk-engine/actions/workflows/tests.yml)

A streaming **User & Entity Behaviour Analytics (UEBA)** engine. It scores every login and app access against the user's own baseline and their role's peer group, explains why an event looks risky, and returns a **Zero Trust decision**: `allow`, `step_up_mfa` or `block_and_alert`.

It is designed to sit behind an SSO / identity provider hook (Okta, Entra ID, Saviynt, Keycloak), which is where most modern breaches start: stolen credentials, MFA fatigue and session hijacking.

## Why this matters

Stolen or weak credentials are consistently among the top ways attackers get in (see the annual Verizon Data Breach Investigations Report). Static rules ("block country X") are either too noisy or too easy to evade. This engine applies the **"never trust, always verify"** principle of Zero Trust. Every event is judged in context:

* *Is this normal **for this user**?* (their countries, devices, hours, download volumes)
* *Is this normal **for people in this role**?* (a sales rep opening `iam_admin` is not)
* *Is this physically possible?* (Pune → Moscow in 20 minutes)

## Detections

| Scenario | Signals that fire |
|---|---|
| Credential stuffing | burst of failures, failures from several countries, hosting-provider ASN, new device |
| MFA fatigue / push bombing | ≥3 MFA denials in 30 min followed by an approval |
| Impossible travel | geo-velocity > 1,000 km/h between consecutive logins (haversine) |
| Session hijack / token replay | access from a hosting ASN + new device + new country mid-session |
| Privilege misuse (insider) | app used by < 5% of the role's peer group, first-ever use of a sensitive app |
| Data exfiltration | download > 10× the user's 95th percentile or z-score > 3, off-hours |
| Dormant account takeover | account inactive for 21+ days suddenly used |

Every alert carries **human-readable reasons**, so an analyst can see why a login was blocked:

```json
{"risk": 99.2, "decision": "block_and_alert",
 "reasons": [{"signal": "impossible_travel", "why": "travel speed between logins is physically impossible"},
             {"signal": "brute_force", "why": "burst of failed logins in the last 10 minutes"},
             {"signal": "hosting_asn", "why": "connection from a cloud/hosting provider, not an ISP or the corporate VPN"}]}
```

### Design choices worth noting

* **Explainable risk fusion.** Each signal has a weight w. Risk = 100 × (1 − Π(1 − wᵢ)), so independent signals compound naturally.
* **Unsupervised second opinion.** An Isolation Forest scores the same behavioural features. It can only escalate an event when at least one explainable signal agrees, which keeps alert fatigue low.
* **Anti-poisoning.** Blocked activity never updates the baseline, so an attacker can't "teach" the model that Moscow is normal for a user.
* **Streaming and leak-free.** Each event is scored using only the past.

## Results

60 days of events for a 400-person company (111k events). The first 30 days build baselines and the last 30 days are evaluated (55,329 events, 428 malicious).

| Detector | ROC-AUC | PR-AUC | Recall @ risk ≥ 40 | Benign alerts / day |
|---|---|---|---|---|
| Rules (explainable signals) | 0.9997 | 0.960 | 100% | 3.9 |
| Isolation Forest alone | 0.9966 | 0.853 | 99.3% | 42.7 |
| **Hybrid (corroborated)** | **0.9998** | **0.976** | **100%** | **4.5** |

**Incident-level results (hybrid):** all 74 attack incidents across 7 scenarios were detected, and 73 were blocked outright (one exfiltration incident got step-up MFA instead). Of 54,901 benign events, 99.76% were allowed silently, 95 got a step-up MFA prompt and 38 were blocked. That is about 4.5 analyst touches per day for 400 users.

The Isolation Forest on its own raises about 10× more false alerts. Requiring corroboration from an explainable signal is what makes it usable.

**What the ML adds over rules alone:** the rules are already strong here (PR-AUC 0.960 at 3.9 benign alerts/day). The hybrid lifts PR-AUC to 0.976, mainly by ranking real attacks above borderline benign events, at the cost of about 0.6 extra benign alerts a day. On synthetic data whose attacks were written alongside the rules, that is a modest gain; on real logs, with attacks the rules were not written for, the unsupervised layer is where new patterns would surface first.

> **Honest caveat:** the dataset is synthetic (real identity logs are confidential), and the attack scenarios were written alongside the detectors. Treat these numbers as proof that the engine works end-to-end. They are not a real-world benchmark. The next step would be replaying real IdP logs (Okta System Log, Entra sign-in logs) through `RiskEngine.process`.

## Run it

```bash
pip install -r requirements.txt
python -m irisk.generate        # -> data/identity_events.csv.gz (already included)
python -m irisk.evaluate        # -> results/evaluation.json, results/top_alerts.csv
pytest -q

uvicorn irisk.api:app --port 8002
curl -X POST localhost:8002/evaluate -H 'content-type: application/json' -d '{
  "user":"u0007","role":"sales","city":"Moscow","device":"unknown","asn":"AS-CLOUD-HOSTING"}'
```

## Data schema (`data/identity_events.csv.gz`)

`ts, user, role, action (login|access), app, success, mfa (approved|denied|denied_then_approved|none|session), city, country, lat, lon, device, asn, ip, download_mb, label, is_attack`

## Structure

```
irisk/
  generate.py   synthetic enterprise identity-log generator with 7 attack scenarios
  engine.py     streaming per-user / peer-group baselines, risk signals, Zero-Trust decisions
  evaluate.py   replay + Isolation Forest + hybrid scoring + metrics
  api.py        FastAPI endpoint for an IdP / SSO hook
tests/          unit tests for each detection
```

## Roadmap

- [ ] Connectors for Okta System Log / Microsoft Entra sign-in logs / AWS CloudTrail
- [ ] Peer groups learned by clustering access patterns, not just job titles
- [ ] Risk decay over time and per-session continuous re-evaluation
- [ ] SIEM export (CEF / Splunk HEC)
