"""Prepare structured public VCDB case reports for research; Python 3.10+."""
import argparse
import csv
import hashlib
import json
import re
import sqlite3
import sys
import tempfile
import zipfile
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.request import Request, urlopen

DEFAULT_COMMIT = "f6f98c00f66ab35f5b49977a5852ce94a5bb31d1"
REPO = "https://github.com/vz-risk/VCDB"
ACTION_TYPES = ("hacking", "malware", "social", "misuse", "physical", "error", "environmental", "unknown")
ROOTS = ("action", "actor", "asset", "attribute", "timeline", "discovery_method", "impact")
# Exclude free-text narratives, personal actor names and analyst identities.
EXCLUDE = {"notes", "name", "summary", "description"}


def get(obj, path):
    for key in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def scalar(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return value


def leaves(value, path=""):
    if isinstance(value, dict):
        for key, child in sorted(value.items()):
            if key not in EXCLUDE and not key.endswith("notes"):
                yield from leaves(child, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from leaves(child, f"{path}[{index}]")
    else:
        yield path, value


def write_csv(path, rows, columns):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def prepare(archive, output, commit):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Expected a full 40-character Git commit SHA")
    with zipfile.ZipFile(archive) as z:
        prefix = f"VCDB-{commit}/"
        names = sorted(n for n in z.namelist()
                       if n.startswith(prefix + "data/json/validated/") and n.endswith(".json"))
        if not names:
            raise ValueError("Archive does not contain validated VCDB records for this commit")
        cases = [(n, json.loads(z.read(n))) for n in names]
        license_text = z.read(prefix + "LICENSE.txt").decode("utf-8")
    counts = Counter(str(x.get("incident_id", "")).lower() for _, x in cases)
    incidents, actions, features = [], [], []
    field_records = {}
    field_known = {}
    for filename, case in cases:
        record_id = PurePosixPath(filename).stem.lower()
        source_id = str(case.get("incident_id", "")).lower()
        row = {"record_id": record_id, "incident_id": source_id,
               "id_collision": int(counts[source_id] > 1),
               "collision_group_size": counts[source_id],
               "source_url": f"{REPO}/blob/{commit}/" + filename[len(prefix):]}
        paths = {
            "organization": "victim.victim_id", "countries": "victim.country",
            "industry": "victim.industry", "employee_count": "victim.employee_count",
            "year": "timeline.incident.year", "month": "timeline.incident.month",
            "day": "timeline.incident.day", "security_incident": "security_incident",
            "data_disclosure": "attribute.confidentiality.data_disclosure",
            "data_total": "attribute.confidentiality.data_total",
            "confidence": "confidence", "analysis_status": "plus.analysis_status",
            "sub_source": "plus.sub_source", "schema_version": "schema_version",
            "discovery_unit": "timeline.discovery.unit",
            "discovery_value": "timeline.discovery.value",
            "containment_unit": "timeline.containment.unit",
            "containment_value": "timeline.containment.value",
            "reference": "reference",
        }
        row.update({column: scalar(get(case, path)) for column, path in paths.items()})
        for category in ACTION_TYPES:
            # 1 means recorded; blank means not recorded, NOT proven absent.
            row["action_" + category] = 1 if category in case.get("action", {}) else None
            detail = case.get("action", {}).get(category)
            if detail is None:
                continue
            actions.append(dict(record_id=record_id, category=category,
                                dimension="category", value=category))
            if isinstance(detail, dict):
                for dimension in ("variety", "vector", "target", "result", "cve"):
                    values = detail.get(dimension, [])
                    if not isinstance(values, list):
                        values = [values]
                    for value in sorted(set(str(v) for v in values if v is not None)):
                        actions.append(dict(record_id=record_id, category=category,
                                            dimension=dimension, value=value))
        for root in ROOTS:
            for path, value in leaves(case.get(root, {}), root):
                field = re.sub(r"\[\d+\]", "[]", path)
                features.append(dict(record_id=record_id, path=path, field=field,
                                     value_json=json.dumps(value, ensure_ascii=False)))
                field_records.setdefault(field, set()).add(record_id)
                if value is not None and str(value).strip().lower() not in ("", "unknown", "na", "n/a"):
                    field_known.setdefault(field, set()).add(record_id)
        incidents.append(row)
    if len({r["record_id"] for r in incidents}) != len(incidents):
        raise ValueError("Duplicate source filenames")
    output.mkdir(parents=True, exist_ok=True)
    tables = {"incidents": incidents, "actions": actions, "features": features}
    headers = {"incidents": list(incidents[0]),
               "actions": ["record_id", "category", "dimension", "value"],
               "features": ["record_id", "path", "field", "value_json"]}
    numeric = {"id_collision", "collision_group_size", "year", "month", "day", "data_total",
               "discovery_value", "containment_value"} | {"action_" + a for a in ACTION_TYPES}
    with closing(sqlite3.connect(output / "vcdb.sqlite")) as db, db:
        db.execute("PRAGMA foreign_keys=ON")
        # A single transaction replaces all tables together on reruns.
        db.execute("BEGIN")
        for name in ("features", "actions", "incidents"):
            db.execute(f'DROP TABLE IF EXISTS "{name}"')
        for name, records in tables.items():
            definitions = []
            for column in headers[name]:
                dtype = "NUMERIC" if column in numeric else "TEXT"
                constraint = " PRIMARY KEY" if name == "incidents" and column == "record_id" else ""
                definitions.append(f'"{column}" {dtype}{constraint}')
            if name != "incidents":
                definitions.append("FOREIGN KEY(record_id) REFERENCES incidents(record_id)")
            db.execute(f'CREATE TABLE "{name}" ({", ".join(definitions)})')
            placeholders = ",".join("?" for _ in headers[name])
            db.executemany(f'INSERT INTO "{name}" VALUES ({placeholders})',
                           ([r.get(c) for c in headers[name]] for r in records))
        db.execute("CREATE INDEX features_field ON features(field)")
        db.execute("CREATE INDEX features_record ON features(record_id)")
        db.execute("CREATE INDEX actions_record ON actions(record_id)")
    for name, records in tables.items():
        write_csv(output / f"{name}.csv", records, headers[name])
    dictionary = [dict(field=f, records_present=len(ids),
                       records_known=len(field_known.get(f, set())),
                       share_present=len(ids) / len(incidents))
                  for f, ids in sorted(field_records.items())]
    write_csv(output / "field_coverage.csv", dictionary,
              ["field", "records_present", "records_known", "share_present"])
    manifest = dict(source="VERIS Community Database (VCDB), vz-risk and contributors",
                    repository=REPO, commit=commit,
                    archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                    collected_at=datetime.now(timezone.utc).isoformat(),
                    license="CC BY-SA 4.0", records=len(incidents),
                    action_rows=len(actions), feature_rows=len(features),
                    structured_fields=len(dictionary),
                    id_collision_records=sum(r["id_collision"] for r in incidents),
                    incident_columns=len(headers["incidents"]),
                    transformations="Validated directory only; structured fields exported; free-text notes, summaries and actor names omitted. Source IDs retained, filename used as record_id. No synthetic observations.")
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    (output / "LICENSE-VCDB.txt").write_text(license_text, encoding="utf-8")
    (output / "ATTRIBUTION.txt").write_text(
        f"Derived from VERIS Community Database, vz-risk and contributors.\n{REPO}\n"
        "Data and derived data outputs: CC BY-SA 4.0\nhttps://creativecommons.org/licenses/by-sa/4.0/\n"
        + manifest["transformations"] + "\n", encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, help="Existing official repository ZIP (offline)")
    parser.add_argument("--commit", default=DEFAULT_COMMIT)
    parser.add_argument("--out", type=Path, default=Path("data_vcdb"))
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        parser.error("--commit must be a full 40-character Git SHA")
    try:
        with tempfile.TemporaryDirectory() as directory:
            archive = args.archive
            if archive is None:
                archive = Path(directory) / "vcdb.zip"
                request = Request(f"https://codeload.github.com/vz-risk/VCDB/zip/{args.commit}",
                                  headers={"User-Agent": "UniversityIncidentResearch/1.0"})
                with urlopen(request, timeout=120) as response, archive.open("wb") as target:
                    while chunk := response.read(1024 * 1024):
                        target.write(chunk)
            print(json.dumps(prepare(archive, args.out, args.commit), ensure_ascii=False, indent=2))
    except (OSError, ValueError, KeyError, sqlite3.Error, zipfile.BadZipFile) as exc:
        print(f"VCDB import failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
