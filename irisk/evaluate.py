"""Replay 60 days of identity events through the engine and evaluate.

Detectors compared on the last 30 days (first 30 days = baseline warm-up):
  * Rules  – explainable Zero-Trust risk signals
  * IsolationForest – unsupervised anomaly score on the same behavioural features
  * Hybrid – max(rule risk, scaled anomaly score)
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score, average_precision_score

from .engine import RiskEngine

ROOT = Path(__file__).resolve().parents[1]
FEATS = ["geo_speed_kmh", "new_country", "new_device", "hosting_asn", "fails_10m", "fail_countries_10m",
         "mfa_denied_30m", "peer_app_share", "download_z", "hour_dev", "dormant_days", "failed"]


def replay(df):
    eng = RiskEngine()
    feats, reasons, risks = [], [], []
    for e in df.to_dict("records"):
        f, r, k = eng.process(e)
        feats.append(f); reasons.append(r); risks.append(k)
    out = df.copy()
    F = pd.DataFrame(feats)
    out = pd.concat([out.reset_index(drop=True), F], axis=1)
    out["reasons"] = ["|".join(r) for r in reasons]
    out["rule_risk"] = risks
    return out, eng


def main():
    df = pd.read_csv(ROOT / "data" / "identity_events.csv.gz", parse_dates=["ts"])
    df["ts"] = (df["ts"] - pd.Timestamp("1970-01-01")) // pd.Timedelta(seconds=1)
    scored, eng = replay(df)
    cut = scored["ts"].min() + 30 * 86400
    warm, test = scored[scored["ts"] < cut], scored[scored["ts"] >= cut].copy()

    X = lambda d: np.column_stack([np.log1p(d["geo_speed_kmh"]), d[FEATS[1:]].values])
    iso = IsolationForest(n_estimators=300, contamination="auto", random_state=0).fit(X(warm))
    raw = -iso.score_samples(X(test))
    lo, hi = np.quantile(-iso.score_samples(X(warm)), [0.5, 0.999])
    test["anomaly_risk"] = np.clip(100 * (raw - lo) / (hi - lo), 0, 100).round(1)
    # the anomaly model escalates only when at least one explainable signal
    # corroborates it; on its own it is capped below the step-up threshold
    corroborated = test["rule_risk"] > 0
    test["hybrid_risk"] = np.where(corroborated, np.maximum(test["rule_risk"], test["anomaly_risk"]),
                                   np.minimum(test["anomaly_risk"], 39)).round(1)
    test["decision"] = test["hybrid_risk"].map(eng.decide)

    y = test["is_attack"].values
    days = (test["ts"].max() - test["ts"].min()) / 86400
    res = {"events_scored": int(len(test)), "attack_events": int(y.sum()), "days": round(days, 1)}
    for col in ["rule_risk", "anomaly_risk", "hybrid_risk"]:
        flag = test[col] >= 40
        res[col] = {"roc_auc": round(roc_auc_score(y, test[col]), 4),
                    "pr_auc": round(average_precision_score(y, test[col]), 4),
                    "recall@risk>=40": round(float(flag[y == 1].mean()), 4),
                    "false_positive_rate@risk>=40": round(float(flag[y == 0].mean()), 5),
                    "benign_alerts_per_day": round(float(flag[y == 0].sum() / days), 1)}
    # incident-level recall: an attack scenario counts as caught if ANY of its events is flagged
    per = {}
    att = test[test["is_attack"] == 1].sort_values("ts").copy()
    # incident = same user + scenario, events less than 1 hour apart
    att["incident"] = (att.groupby(["user", "label"])["ts"].diff().fillna(1e9) > 3600).cumsum()
    for lab, g in att.groupby("label"):
        inc = g.groupby("incident")["hybrid_risk"].max()
        per[lab] = {"events": int(len(g)), "incidents": int(len(inc)),
                    "incidents_detected": round(float((inc >= 40).mean()), 3),
                    "incidents_blocked": round(float((inc >= 70).mean()), 3),
                    "event_recall": round(float((g["hybrid_risk"] >= 40).mean()), 3)}
    res["per_scenario_hybrid"] = per
    res["decisions_benign"] = test[test.is_attack == 0]["decision"].value_counts().to_dict()
    res["decisions_attack"] = test[test.is_attack == 1]["decision"].value_counts().to_dict()
    (ROOT / "results" / "evaluation.json").write_text(json.dumps(res, indent=2))
    cols = ["ts", "user", "role", "action", "app", "city", "country", "device", "asn", "download_mb", "label",
            "rule_risk", "anomaly_risk", "hybrid_risk", "decision", "reasons"]
    top = test.sort_values("hybrid_risk", ascending=False)[cols].head(200).copy()
    top["ts"] = pd.to_datetime(top["ts"], unit="s")
    top.to_csv(ROOT / "results" / "top_alerts.csv", index=False)
    joblib.dump({"iso": iso, "lo": lo, "hi": hi, "features": FEATS}, ROOT / "models" / "anomaly.joblib")
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
