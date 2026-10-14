#!/usr/bin/env python3
"""Учебная SHA-256 цепочка аудита. НЕ блокчейн и НЕ цифровая подпись."""
import argparse
import copy
import csv
import hashlib
import json
from pathlib import Path

GENESIS = "0" * 64
FORMAT = "openbasesearch-audit-v1"


def canonical_json(value):
    """UTF-8 JSON; ключи сортируются, пробелы отсутствуют, NaN запрещён.

    В эксперименте только строки, целые числа, списки и объекты. Это локальное
    соглашение формата, а не реализация межъязыкового стандарта JCS.
    """
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def build_chain(events):
    records = []
    previous = GENESIS
    for index, event in enumerate(events):
        payload = {"format": FORMAT, "index": index,
                   "previous_hash": previous, "event": copy.deepcopy(event)}
        record = dict(payload, hash=digest(payload))
        records.append(record)
        previous = record["hash"]
    return records


def make_checkpoint(records):
    return {"format": FORMAT, "count": len(records),
            "root": records[-1]["hash"] if records else GENESIS}


def verify_chain(records):
    checks = []
    previous = GENESIS
    keys = {"format", "index", "previous_hash", "event", "hash"}
    for index, record in enumerate(records):
        schema_ok = isinstance(record, dict) and set(record) == keys
        if not schema_ok:
            checks.append({"record_index": index, "schema_ok": False,
                           "record_valid": False})
            previous = None
            continue
        payload = {key: record[key] for key in keys if key != "hash"}
        try:
            calculated = digest(payload)
        except (TypeError, ValueError):
            calculated = None
        check = {"record_index": index, "schema_ok": True,
                 "format_ok": record["format"] == FORMAT,
                 "index_ok": type(record["index"]) is int and record["index"] == index,
                 "previous_hash_ok": record["previous_hash"] == previous,
                 "stored_hash": record["hash"], "calculated_hash": calculated,
                 "hash_ok": calculated is not None and record["hash"] == calculated}
        check["record_valid"] = all(check[key] for key in
                                    ("schema_ok", "format_ok", "index_ok",
                                     "previous_hash_ok", "hash_ok"))
        checks.append(check)
        previous = record["hash"]
    return {"internal_valid": all(item["record_valid"] for item in checks),
            "record_checks": checks}


def verify_against_checkpoint(records, trusted_checkpoint):
    result = verify_chain(records)
    observed = make_checkpoint(records)
    result.update({"observed_checkpoint": observed,
                   "trusted_checkpoint": copy.deepcopy(trusted_checkpoint),
                   "count_matches": observed["count"] == trusted_checkpoint["count"],
                   "root_matches": observed["root"] == trusted_checkpoint["root"],
                   "format_matches": observed["format"] == trusted_checkpoint["format"]})
    result["checkpoint_matches"] = all(result[key] for key in
                                       ("count_matches", "root_matches", "format_matches"))
    result["accepted"] = result["internal_valid"] and result["checkpoint_matches"]
    return result


def synthetic_events():
    return [
        {"event_id": "demo-001", "organization": "Synthetic Organization A",
         "action": "register_incident", "incident_id": "synthetic-001", "version": 1},
        {"event_id": "demo-002", "organization": "Synthetic Organization A",
         "action": "revise_incident", "incident_id": "synthetic-001", "version": 2},
        {"event_id": "demo-003", "organization": "Synthetic Organization B",
         "action": "register_incident", "incident_id": "synthetic-002", "version": 1},
        {"event_id": "demo-004", "organization": "Synthetic Organization B",
         "action": "review_incident", "incident_id": "synthetic-002", "version": 1},
    ]


LIMITATIONS = """Учебный эксперимент: цепочка аудита SHA-256 и доверенная контрольная точка.
Это НЕ блокчейн, НЕ распределённый реестр и НЕ цифровая подпись.
Все события синтетические; данные реальных людей и инцидентов не используются.

Хешируется JSON в UTF-8: ensure_ascii=False, sort_keys=True,
separators=(',', ':'), allow_nan=False. Поля записи: format, index,
previous_hash, event. Поле hash вычисляется по этим четырём полям.
Genesis — строка из 64 нулей. Контрольная точка содержит format, count и root
(хеш последней записи; для пустой цепочки — genesis).
Unicode не нормализуется; межъязыковая канонизация JCS не реализована.

Необходима отдельная доверенная копия контрольной точки: количество записей
и корневой хеш. Файл trusted_checkpoint.json в этой папке только моделирует
такое внешнее доверенное хранение. Его размещение рядом с журналом НЕ создаёт
независимого доверия. Если атакующий может заменить и журнал, и доверенную
контрольную точку, пересчитанная история пройдёт проверку.

Внутренняя проверка выявляет подмену без пересчёта. Полный пересчёт цепочки
и удаление хвоста требуют сверки с ранее сохранённой доверенной точкой.
Несовпадение означает отличие от зафиксированной версии, но само по себе
не отличает злонамеренную подмену от разрешённого обновления или повреждения.
Проверяется ровно зафиксированная версия: легитимное добавление новых записей
тоже изменит count/root; протокол авторизации обновлений здесь не реализован.

Хеширование не обеспечивает конфиденциальность, авторство, достоверность
исходных утверждений, права доступа, доступность или доказательство времени.
В примере отсутствуют консенсус, сеть узлов, цифровые подписи, смарт-контракт,
механизмы управления ключами и экономика блокчейна. Эксперимент показывает
свойства цепочки хешей, а не превосходство блокчейна над обычной базой данных.
Результаты — четыре заданных сценария, не статистическая оценка безопасности.
"""


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
                    + "\n", encoding="utf-8")


def run_demo(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    original = build_chain(synthetic_events())
    trusted = make_checkpoint(original)
    tampered = copy.deepcopy(original)
    tampered[1]["event"]["version"] = 99
    rewritten_events = synthetic_events()
    rewritten_events[1]["version"] = 99
    scenarios = [
        ("unchanged", "Неизменный журнал", original, True, True),
        ("tamper_without_rehash", "Подмена без пересчёта", tampered, False, True),
        ("tamper_with_full_rehash", "Подмена с полным пересчётом", build_chain(rewritten_events), True, False),
        ("tail_deleted", "Удаление последней записи", original[:-1], True, False),
    ]
    results = []
    for name, label, chain, internal_expected, checkpoint_expected in scenarios:
        result = verify_against_checkpoint(chain, trusted)
        result.update({"scenario": name, "label_ru": label,
                       "expected_internal_valid": internal_expected,
                       "expected_checkpoint_matches": checkpoint_expected})
        assert result["internal_valid"] == internal_expected
        assert result["checkpoint_matches"] == checkpoint_expected
        result["expected_outcome_observed"] = True
        results.append(result)
        write_json(output / (name + ".json"), chain)
    write_json(output / "trusted_checkpoint.json", trusted)
    write_json(output / "results.json", results)
    fields = ["scenario", "label_ru", "internal_valid", "count_matches", "root_matches",
              "checkpoint_matches", "accepted", "expected_outcome_observed"]
    with (output / "summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    (output / "limitations.txt").write_text(LIMITATIONS, encoding="utf-8")
    for result in results:
        print(f"{result['label_ru']}: internal={result['internal_valid']}, "
              f"checkpoint={result['checkpoint_matches']}, accepted={result['accepted']}")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).resolve().parent / "results_integrity")
    run_demo(parser.parse_args().output)
