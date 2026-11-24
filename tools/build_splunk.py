"""Convert every Sigma rule in detections/sigma to Splunk SPL (Okta System Log field names).

    python tools/build_splunk.py        -> detections/splunk/<rule>.spl
"""
from pathlib import Path

from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parents[1]


def build() -> dict[str, str]:
    backend = SplunkBackend()
    out = {}
    for rule in sorted((ROOT / "detections" / "sigma").glob("*.yml")):
        coll = SigmaCollection.from_yaml(rule.read_text())
        if coll.errors:
            raise SystemExit(f"{rule.name}: {coll.errors}")
        out[rule.stem] = "\n\n".join(backend.convert(coll)).strip() + "\n"
    return out


if __name__ == "__main__":
    target = ROOT / "detections" / "splunk"
    target.mkdir(exist_ok=True)
    for name, spl in build().items():
        (target / f"{name}.spl").write_text(spl)
        print("wrote", f"detections/splunk/{name}.spl")
