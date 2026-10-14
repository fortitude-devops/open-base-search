"""Build categorical incident profiles for unsupervised VCDB analysis."""
import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

FAMILIES = ("action", "actor", "asset", "data")


def read_rows(path):
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_rows(path, rows, fields):
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def informative(value):
    if value is None:
        return False
    text = str(value).strip().lower()
    return text not in ("", "unknown", "na", "n/a", "null") and not text.endswith(" - unknown")


def build(source, output):
    raw = read_rows(source / "incidents.csv")
    profiles = {r["record_id"]: {f: set() for f in FAMILIES} for r in raw}
    for r in read_rows(source / "actions.csv"):
        if r["category"] == "unknown" or not informative(r["value"]):
            continue
        if r["dimension"] in ("category", "variety", "vector"):
            profiles[r["record_id"]]["action"].add(
                f'{r["category"]}:{r["dimension"]}:{r["value"]}')
    for r in read_rows(source / "features.csv"):
        p = profiles[r["record_id"]]
        field = r["field"]
        value = json.loads(r["value_json"])
        if field.startswith("actor."):
            category = field.split(".")[1]
            if category in ("internal", "external", "partner"):
                p["actor"].add(category)
        if not informative(value):
            continue
        if field == "asset.assets[].variety":
            p["asset"].add(str(value))
        elif field == "attribute.confidentiality.data[].variety":
            p["data"].add(str(value))
    metadata, core = [], []
    for r in raw:
        rid = r["record_id"]
        p = profiles[rid]
        eligible = (r["security_incident"] == "Confirmed" and r["data_disclosure"] == "Yes"
                    and r["analysis_status"] != "Ineligible" and r["id_collision"] != "1")
        missing = [family for family in FAMILIES if not p[family]]
        included = eligible and not missing
        if included:
            core.append(rid)
        metadata.append({**r, "eligible": int(eligible), "in_cluster_core": int(included),
                         "missing_families": ";".join(missing),
                         "recorded_tokens": sum(len(v) for v in p.values())})
    if len(core) < 20:
        raise ValueError("Fewer than 20 complete eligible cases")
    features = []
    for family in FAMILIES:
        terms = sorted({term for rid in core for term in profiles[rid][family]})
        for term in terms:
            features.append(dict(feature=f"f{len(features):04}", family=family, value=term,
                                 records=sum(term in profiles[rid][family] for rid in core)))
    matrix = [dict(record_id=rid, **{
        f["feature"]: int(f["value"] in profiles[rid][f["family"]]) for f in features}) for rid in core]
    output.mkdir(parents=True, exist_ok=True)
    write_rows(output / "matrix.csv", matrix, list(matrix[0]))
    write_rows(output / "feature_dictionary.csv", features, ["feature", "family", "value", "records"])
    write_rows(output / "metadata.csv", metadata, list(metadata[0]))
    audit = [dict(family=family, eligible_records=sum(r["eligible"] for r in metadata),
                  known_records=sum(r["eligible"] and bool(profiles[r["record_id"]][family]) for r in metadata))
             for family in FAMILIES]
    write_rows(output / "coverage.csv", audit, list(audit[0]))
    manifest = dict(source="VERIS Community Database, vz-risk and contributors",
                    url="https://github.com/vz-risk/VCDB", license="CC BY-SA 4.0",
                    source_records=len(raw), eligible_records=sum(r["eligible"] for r in metadata),
                    complete_core_records=len(core), binary_features=len(features), families=list(FAMILIES),
                    input_sha256={name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                                  for name in ("incidents.csv", "features.csv", "actions.csv")},
                    source_manifest=json.loads((source / "manifest.json").read_text()),
                    rules="Complete four-family core; unknown/NA tokens omitted; no numerical imputation. Zero means token not recorded, not proven absence. IDs and metadata excluded from distance.")
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return {k: v for k, v in manifest.items() if k not in ("source_manifest", "input_sha256")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("data_vcdb"))
    parser.add_argument("--out", type=Path, default=Path("data_clusters"))
    args = parser.parse_args()
    print(json.dumps(build(args.source, args.out), ensure_ascii=False, indent=2))
