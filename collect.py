"""Collect public breach metadata, never individual account records (Python 3.10+)."""
import argparse
import csv
import json
import sqlite3
import sys
from contextlib import closing
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

API = "https://haveibeenpwned.com/api/v3/breaches"
FLAGS = {"verified": "IsVerified", "fabricated": "IsFabricated",
         "spam_list": "IsSpamList", "malware": "IsMalware"}
COLUMNS = ["name", "title", "domain", "breach_date", "added_date", "pwn_count",
           *FLAGS, "source_url", "collected_at"]


def normalize(payload):
    if not isinstance(payload, list) or not payload:
        raise ValueError("Ожидался непустой список инцидентов")
    rows, classes, seen = [], [], set()
    collected = datetime.now(timezone.utc).isoformat()
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("Инцидент должен быть объектом")
        name = item.get("Name")
        if not isinstance(name, str) or not name or name in seen:
            raise ValueError("Отсутствующее или повторяющееся имя инцидента")
        seen.add(name)
        breach_date = date.fromisoformat(item["BreachDate"]).isoformat()
        added = datetime.fromisoformat(item["AddedDate"].replace("Z", "+00:00"))
        count = item["PwnCount"]
        if type(count) is not int or count < 0:
            raise ValueError(f"Некорректный PwnCount: {name}")
        flags = []
        for key in FLAGS.values():
            value = item.get(key)
            if value is not None and type(value) is not bool:
                raise ValueError(f"Некорректный флаг {key}: {name}")
            flags.append(None if value is None else int(value))
        title, domain = item["Title"], item.get("Domain", "")
        if not isinstance(title, str) or not isinstance(domain, str):
            raise ValueError(f"Некорректное название или домен: {name}")
        data_classes = item["DataClasses"]
        if not isinstance(data_classes, list) or not all(
                isinstance(c, str) and c for c in data_classes):
            raise ValueError(f"Некорректные категории данных: {name}")
        rows.append((name, title, domain, breach_date, added.isoformat(), count,
                     *flags, "https://haveibeenpwned.com/Breach/" + quote(name, safe=""),
                     collected))
        classes.extend((name, c) for c in sorted(set(data_classes)))
    return rows, classes


def save_snapshot(payload, output):
    # Validate the complete response before replacing the previous snapshot.
    rows, classes = normalize(payload)
    output.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(output / "breaches.sqlite")) as db, db:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("""CREATE TABLE IF NOT EXISTS breaches (
            name TEXT PRIMARY KEY, title TEXT NOT NULL, domain TEXT NOT NULL,
            breach_date TEXT NOT NULL, added_date TEXT NOT NULL,
            pwn_count INTEGER NOT NULL CHECK(pwn_count >= 0),
            verified INTEGER, fabricated INTEGER, spam_list INTEGER, malware INTEGER,
            source_url TEXT NOT NULL, collected_at TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS data_classes (
            name TEXT REFERENCES breaches(name), data_class TEXT NOT NULL,
            PRIMARY KEY(name, data_class))""")
        db.execute("DELETE FROM data_classes")
        db.execute("DELETE FROM breaches")
        db.executemany("INSERT INTO breaches VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        db.executemany("INSERT INTO data_classes VALUES (?,?)", classes)
    for filename, headers, records in [
        ("breaches.csv", COLUMNS, rows),
        ("data_classes.csv", ["name", "data_class"], classes),
    ]:
        temporary = output / (filename + ".tmp")
        with temporary.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(headers)
            writer.writerows(records)
        temporary.replace(output / filename)
    (output / "source.json").write_text(json.dumps({
        "source": "Have I Been Pwned", "url": API,
        "attribution": "https://haveibeenpwned.com/",
        "license": "https://creativecommons.org/licenses/by/4.0/",
        "collected_at": rows[0][-1], "incident_count": len(rows),
        "scope": "Public incident metadata only; no personal records",
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("data"))
    args = parser.parse_args()
    request = Request(API, headers={"User-Agent": "UniversityBreachMetadataStudy/1.0",
                                   "Accept": "application/json"})
    try:
        with urlopen(request, timeout=45) as response:
            payload = json.load(response)
        count = save_snapshot(payload, args.out)
    except HTTPError as exc:
        retry = exc.headers.get("Retry-After", "не указан")
        print(f"HTTP {exc.code}. Retry-After: {retry}. Повторите позже; "
              "при 401/403 проверьте доступность публичного API.", file=sys.stderr)
        return 1
    except (URLError, TimeoutError, OSError, ValueError, KeyError, TypeError,
            sqlite3.Error) as exc:
        print(f"Не удалось завершить сбор: {exc}", file=sys.stderr)
        return 1
    print(f"Сохранено инцидентов: {count}. Каталог: {args.out.resolve()}")
    print("Источник: Have I Been Pwned — https://haveibeenpwned.com/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
