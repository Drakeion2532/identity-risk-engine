"""Real-time risk API – call it from an IdP hook / SSO gateway on each login.

    uvicorn irisk.api:app --port 8002
    POST /evaluate  -> {"risk": 87.5, "decision": "block_and_alert", "reasons": [...]}

On start-up the engine replays the historical log to build user baselines.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from fastapi import FastAPI
from pydantic import BaseModel

from .engine import RiskEngine
from .generate import CITIES

ROOT = Path(__file__).resolve().parents[1]
app = FastAPI(title="Identity Risk Engine")
engine = RiskEngine()


@app.on_event("startup")
def warm_up():
    df = pd.read_csv(ROOT / "data" / "identity_events.csv.gz", parse_dates=["ts"])
    df["ts"] = (df["ts"] - pd.Timestamp("1970-01-01")) // pd.Timedelta(seconds=1)
    for e in df.to_dict("records"):
        engine.process(e)


class Event(BaseModel):
    user: str
    role: str
    action: str = "login"            # login | access
    app: str = "sso"
    success: bool = True
    mfa: str = "approved"            # approved | denied | none | session
    city: str
    device: str
    asn: str = "AS-HOME-ISP"
    download_mb: float = 0.0
    ts: datetime | None = None


@app.post("/evaluate")
def evaluate(ev: Event):
    lat, lon, cc = CITIES.get(ev.city, (0.0, 0.0, "??"))
    ts = (ev.ts or datetime.now(timezone.utc)).timestamp()
    e = {**ev.model_dump(exclude={"ts"}), "ts": ts, "lat": lat, "lon": lon, "country": cc,
         "success": int(ev.success)}
    f, reasons, risk = engine.process(e)
    return {"risk": risk, "decision": engine.decide(risk), "reasons": engine.explain(reasons),
            "features": {k: round(float(v), 3) for k, v in f.items()}}


@app.get("/health")
def health():
    return {"users_baselined": len(engine.users)}
