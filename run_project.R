# Open OpenBaseSearch.Rproj, then run: source("run_project.R")
# Terminal: Rscript run_project.R [--no-open]
run_project <- function(open_report = TRUE) {
  required <- c("analysis_vcdb.R", "cluster_vcdb.R", "render_report.R",
                "data_clusters/matrix.csv", "data_vcdb/incidents.csv")
  missing <- required[!file.exists(required)]
  if (length(missing)) stop("Open OpenBaseSearch.Rproj first. Missing files: ", paste(missing, collapse=", "))
  if (!requireNamespace("cluster", quietly=TRUE)) {
    stop("Install the R package first: install.packages('cluster')")
  }
  message("[1/4] Анализ данных…")
  source("analysis_vcdb.R", local=new.env(parent=globalenv()), encoding="UTF-8")
  message("[2/4] Кластеризация и проверка устойчивости…")
  source("cluster_vcdb.R", local=new.env(parent=globalenv()), encoding="UTF-8")
  message("[3/4] Учебный эксперимент с журналом…")
  python <- unname(Sys.which(c("python3", "python")))
  python <- python[nzchar(python)]
  if (length(python)) {
    for (script in c("integrity_demo.py", "build_project_materials.py")) {
      status <- system2(python[1], script)
      if (status != 0) stop("Failed: ", script)
    }
  } else {
    message("Python не найден: показаны сохранённые результаты эксперимента. Для пересчёта нужен Python 3.10+.")
  }
  message("[4/4] Создание визуального отчёта…")
  report_env <- new.env(parent=globalenv())
  source("render_report.R", local=report_env, encoding="UTF-8")
  report <- report_env$render_report()
  message("Готово. Отчёт: ", report)
  if (open_report) {
    tryCatch(utils::browseURL(report),
             error=function(e) message("Не удалось открыть браузер. Откройте report.html вручную: ", conditionMessage(e)))
  }
  invisible(report)
}

run_project(open_report = !"--no-open" %in% commandArgs(trailingOnly=TRUE) &&
              isTRUE(getOption("openbasesearch.open_report", TRUE)))
