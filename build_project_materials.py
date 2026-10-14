"""Export the project architecture assessment to HTML and CSV (stdlib only)."""
import csv
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def table(headers, rows):
    e = html.escape
    return '<div class="scroll"><table><thead><tr>' + ''.join('<th>'+e(x)+'</th>' for x in headers) + '</tr></thead><tbody>' + ''.join('<tr>'+''.join('<td>'+e(str(x))+'</td>' for x in row)+'</tr>' for row in rows) + '</tbody></table></div>'


def main():
    folder = ROOT / "project_materials"
    source = json.loads((folder / "blockchain_assessment.json").read_text())
    headers = ["Критерий", "База данных", "Журнал и хеш-цепочка", "Цифровая подпись", "Permissioned-блокчейн"]
    rows = [[r[key] for key in ("criterion", "database", "audit_hash_chain", "digital_signature", "permissioned_blockchain")] for r in source["comparison"]]
    with (folder / "comparison.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f); writer.writerow(headers); writer.writerows(rows)
    scenario_headers = ["Сценарий", "Задача защиты", "Традиционное решение", "Возможная роль блокчейна", "Условия", "Ограничения"]
    scenario_rows = [[r[key] for key in ("scenario", "security_task", "traditional_solution", "blockchain_role", "conditions", "limitations")] for r in source["scenarios"]]
    with (folder / "scenarios.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f); writer.writerow(scenario_headers); writer.writerows(scenario_rows)
    with (ROOT / "results_integrity/summary.csv").open(encoding="utf-8") as f:
        experiment = list(csv.DictReader(f))
    check_rows = [[r["label_ru"], *("да" if r[k] == "True" else "нет" for k in ("internal_valid", "checkpoint_matches", "accepted"))] for r in experiment]
    content = ['<section><h2>5. Применимость блокчейн-технологий</h2>',
               '<p>'+html.escape(source["conclusion"])+ '</p>',
               table(headers, rows), '<p>'+html.escape(source["interpretation"])+ '</p></section>',
               '<section><h2>6. Сценарии и меры защиты</h2>',table(scenario_headers,scenario_rows),'</section>',
               '<section><h2>7. Учебная проверка целостности</h2>',
               '<p>Проведён эксперимент на синтетическом журнале SHA-256. Независимая контрольная отметка моделируется отдельным файлом. Сеть, консенсус и цифровые подписи не реализованы.</p>',
               table(["Сценарий", "Цепочка согласована", "Контрольная отметка совпала", "Журнал принят"],check_rows),
               '<p>Полный пересчёт позволяет подменённому журналу пройти внутреннюю проверку. Независимая доверенная отметка выявляет такую подмену. Если нарушитель заменит и её, гарантия исчезает. Эксперимент не измеряет предотвращение утечек.</p></section>',
               '<section><h2>8. Материалы для защиты</h2><p><a href="deliverables/Report.docx">Отчёт DOCX</a> · <a href="deliverables/Presentation.pptx">Презентация PPTX</a> · <a href="DEFENSE_GUIDE.md">Вопросы для защиты</a></p><h3>Источники</h3><ul>']
    content += ['<li><a href="'+html.escape(s["url"],quote=True)+'">'+html.escape(s["title"])+ '</a></li>' for s in source["sources"]]
    content += ['</ul><p>Технические источники проверены 6 октября 2026 года. Данные VCDB зафиксированы отдельным снимком от 30 сентября 2026 года.</p></section>']
    (folder / "blockchain_fragment.html").write_text('\n'.join(content),encoding="utf-8")
    print("Architecture comparison, scenario table and experiment fragment updated")


if __name__ == "__main__":
    main()
