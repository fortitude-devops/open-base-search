# Local HTML report; no external assets or internet connection needed.
render_report <- function() {
  summary <- read.csv("results_clusters/cluster_summary.csv", stringsAsFactors=FALSE)
  selection <- read.csv("results_clusters/k_selection.csv")
  sensitivity <- read.csv("results_clusters/sensitivity.csv")
  profiles <- read.csv("results_clusters/feature_profiles.csv", stringsAsFactors=FALSE)
  flow <- read.csv("results_vcdb/selection.csv", stringsAsFactors=FALSE)
  core_n <- sum(summary$records)
  k <- nrow(summary)
  chosen <- selection[selection$k==k, ]
  escape <- function(x) {
    x <- gsub("&", "&amp;", as.character(x), fixed=TRUE)
    x <- gsub("<", "&lt;", x, fixed=TRUE)
    gsub(">", "&gt;", x, fixed=TRUE)
  }
  fmt <- function(x) format(x, big.mark=" ", scientific=FALSE, trim=TRUE)
  cards <- paste(sprintf('<div class="metric"><strong>%s</strong><span>%s</span></div>',
                          c(fmt(flow$records[1]), fmt(core_n), k, sprintf("%.3f",chosen$mean_silhouette)),
                          c("карточек в источнике", "карточек в кластеризации", "группы", "silhouette · разделение")), collapse="")
  group_rows <- paste(vapply(seq_len(k), function(i) {
    r <- summary[i, ]
    size <- if(is.na(r$median_records)) "неизвестно" else fmt(r$median_records)
    sprintf('<tr><td>Группа %s</td><td>%s</td><td>%.1f%%</td><td>%s</td><td>%s</td></tr>',
            r$cluster, fmt(r$records),100*r$share,size,fmt(r$size_known))
  }, character(1)), collapse="")
  ru <- c(error="Непреднамеренные ошибки", misuse="Злоупотребление доступом",
          hacking="Взлом", malware="Вредоносные программы", social="Социальная инженерия",
          physical="Физические действия", environmental="Воздействия среды")
  action_rows <- paste(vapply(names(ru), function(name) {
    p <- profiles[profiles$family=="action" & profiles$value==paste(name,"category",name,sep=":"), ]
    values <- vapply(summary$cluster, function(g) {
      value <- p$share_in_cluster[p$cluster==g]
      if(length(value)) sprintf("%.1f%%",100*value) else "—"
    }, character(1))
    paste0("<tr><td>",ru[[name]],"</td>",paste0("<td>",values,"</td>",collapse=""),"</tr>")
  }, character(1)), collapse="")
  noactor <- sensitivity$adjusted_rand[sensitivity$check=="without_actor"]
  caution <- if(length(noactor) && noactor < .5)
    sprintf("При исключении типа участника ARI падает до %.3f. Разделение существенно зависит от этого признака: это описательные группы, а не универсальная типология причин.",noactor) else
    "Группы отражают выбранные признаки и расстояние. Они не устанавливают причинность и эффективность мер защиты."
  html <- c('<!doctype html><html lang="ru"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1"><title>OpenBaseSearch — результаты анализа</title>',
    '<style>*{box-sizing:border-box}body{margin:0;background:#f3f6fa;color:#17263c;font:16px/1.6 system-ui,sans-serif}main{max-width:1100px;margin:auto;padding:40px 24px}h1{font-size:36px;line-height:1.2;margin:10px 0}h2{font-size:24px;margin:0 0 16px}p{max-width:900px}.muted{color:#53647a}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:28px 0}.metric,section{background:white;border:1px solid #dde5ef;border-radius:14px;padding:24px}.metric strong{display:block;font-size:32px;color:#235b8b}.metric span{color:#53647a}section{margin-bottom:24px}figure{margin:20px 0}img{display:block;width:100%;height:auto}figcaption{color:#53647a;font-size:14px;margin-top:8px}.scroll{overflow:auto}table{width:100%;border-collapse:collapse;font-size:15px}th,td{text-align:left;padding:12px;border-bottom:1px solid #e3e9f0}th{background:#edf3fa}.note{border-left:4px solid #cf8a16;padding:12px 18px;background:#fff6e7}a{color:#175a96}footer{font-size:14px;color:#53647a}@media(max-width:700px){.metrics{grid-template-columns:repeat(2,1fr)}main{padding:20px 12px}h1{font-size:28px}section{padding:16px}}@media print{body{background:white}main{padding:0}section{break-inside:avoid}a{color:inherit}}</style></head><body><main>',
    '<header><div class="muted">OpenBaseSearch · исследование публичных инцидентов</div><h1>Анализ и кластеризация утечек</h1><p>Группировка похожих карточек по действиям, типам участников, активам и видам раскрытых данных. Целевая переменная не требуется.</p></header>',
    paste0('<div class="metrics">',cards,'</div>'),
    '<section><h2>1. Размеры получившихся групп</h2>',
    paste0('<div class="scroll"><table><thead><tr><th>Группа</th><th>Карточек</th><th>Доля</th><th>Медиана записей</th><th>Размер известен</th></tr></thead><tbody>',group_rows,'</tbody></table></div>'),
    '<p class="muted">Медианы рассчитаны только по известным значениям. Число записей не равно числу уникальных людей.</p>',
    '<figure><img src="results_clusters/cluster_sizes.png" alt="Количество карточек в каждом кластере"><figcaption>Единица анализа — карточка источника.</figcaption></figure></section>',
    '<section><h2>2. Чем различаются группы</h2>',
    paste0('<div class="scroll"><table><thead><tr><th>Зарегистрированное действие</th>',paste0('<th>Группа ',summary$cluster,'</th>',collapse=""),'</tr></thead><tbody>',action_rows,'</tbody></table></div>'),
    '<p>Одна карточка может содержать несколько действий, поэтому проценты не обязаны складываться в 100%.</p>',
    '<figure><img src="results_clusters/action_profiles.png" alt="Доли механизмов инцидента по кластерам"><figcaption>На графике доли от 0 до 1: 0.54 означает 54% карточек группы.</figcaption></figure></section>',
    '<section><h2>3. Насколько устойчив результат</h2>',
    sprintf('<p>Средний silhouette: <b>%.3f</b>. Согласованность трёх запусков, ARI: <b>%.3f</b>. Это показатели разделения и устойчивости, а не точность предсказания.</p>',chosen$mean_silhouette,chosen$mean_ARI),
    '<figure><img src="results_clusters/k_selection.png" alt="Сравнение silhouette при разном числе кластеров"><figcaption>Пунктир отмечает выбранное число групп.</figcaption></figure>',
    paste0('<p class="note">',escape(caution),'</p></section>'),
    '<section><h2>4. Ограничения и дальнейший анализ</h2>',
    '<p>Карточки без содержательных значений во всех четырёх семействах исключены только из кластеризации. Неизвестные данные не заменены выдуманными фактами. Отбор полных карточек смещает выборку.</p>',
    '<p>Для сценариев ошибок и злоупотреблений стоит изучить права доступа, проверку получателей и контроль выгрузок. Для внешних атак — управление уязвимостями, защиту учётных записей и мониторинг. Эффективность мер нужно проверять отдельно.</p>',
    '<p><a href="results_clusters/report_ru.txt">Подробный отчёт</a> · <a href="results_clusters/assignments.csv">Карточки и кластеры CSV</a> · <a href="results_clusters/feature_profiles.csv">Все профили CSV</a> · <a href="results_clusters/k_selection.csv">Сравнение вариантов CSV</a></p></section>',
    if(file.exists("project_materials/blockchain_fragment.html")) readLines("project_materials/blockchain_fragment.html", encoding="UTF-8", warn=FALSE) else '<p>Материалы сравнения отсутствуют. Выполните python3 build_project_materials.py.</p>',
    '<footer>Источник данных: <a href="https://github.com/vz-risk/VCDB">VERIS Community Database, vz-risk and contributors</a>. Производные данные и графики: <a href="https://creativecommons.org/licenses/by-sa/4.0/">CC BY-SA 4.0</a>. Локальный отчёт не загружает внешние ресурсы.</footer>',
    '</main></body></html>')
  writeLines(enc2utf8(html), "report.html", useBytes=TRUE)
  normalizePath("report.html", winslash="/", mustWork=TRUE)
}
