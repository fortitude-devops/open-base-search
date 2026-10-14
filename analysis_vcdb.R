# In RStudio, set the working directory to the project and source this file.
# Source: VERIS Community Database, https://github.com/vz-risk/VCDB
# Derived tables and plots: CC BY-SA 4.0. Base R; no packages required.
d <- read.csv("data_vcdb/incidents.csv", colClasses = "character",
              na.strings = "", fileEncoding = "UTF-8")
a <- read.csv("data_vcdb/actions.csv", colClasses = "character",
              na.strings = "", fileEncoding = "UTF-8")
stopifnot(!anyDuplicated(d$record_id), all(a$record_id %in% d$record_id))
d$data_total <- as.numeric(d$data_total)
d$year <- as.integer(d$year)
eligible <- is.na(d$analysis_status) | d$analysis_status != "Ineligible"
confirmed <- !is.na(d$security_incident) & d$security_incident == "Confirmed" &
             !is.na(d$data_disclosure) & d$data_disclosure == "Yes"
base <- d[eligible & confirmed, ]
primary <- base[base$id_collision == "0", ]
untargeted <- primary[is.na(primary$sub_source) |
                       !(primary$sub_source %in% c("phidbr", "priority")), ]
reviewed <- primary[!is.na(primary$analysis_status) &
                      primary$analysis_status %in% c("Reviewed", "Finalized"), ]
cohorts <- list(primary = primary, with_id_collisions = base,
                without_targeted_sources = untargeted, reviewed_only = reviewed)
dir.create("results_vcdb", showWarnings = FALSE)
save_table <- function(x, name) {
  write.csv(x, file.path("results_vcdb", paste0(name, ".csv")), row.names = FALSE, na = "")
}
counts <- function(x, dimension) {
  values <- x[[dimension]]
  values[is.na(values)] <- "Missing"
  out <- as.data.frame(table(values), stringsAsFactors = FALSE)
  names(out) <- c(dimension, "records")
  out
}
flow <- data.frame(stage = c("All validated source cards", "Confirmed disclosure, eligible",
                             "Primary: no ID collisions", "Without targeted sources",
                             "Reviewed or finalized only"),
                   records = c(nrow(d), nrow(base), nrow(primary), nrow(untargeted), nrow(reviewed)))
save_table(flow, "selection")
print(flow)

# Multi-label categories: one record may contribute to several categories.
category_rows <- unique(a[a$dimension == "category", c("record_id", "category")])
category_summary <- do.call(rbind, lapply(names(cohorts), function(label) {
  selected <- cohorts[[label]]
  groups <- category_rows[category_rows$record_id %in% selected$record_id, ]
  out <- as.data.frame(table(groups$category), stringsAsFactors = FALSE)
  names(out) <- c("category", "records")
  out$cohort <- label
  out$denominator <- nrow(selected)
  out$share <- if (nrow(selected)) out$records / nrow(selected) else NA_real_
  out
}))
save_table(category_summary, "action_categories_sensitivity")
for (dimension in c("year", "industry")) {
  before <- counts(base, dimension)
  after <- counts(primary, dimension)
  comparison <- merge(before, after, by = dimension, all = TRUE,
                      suffixes = c("_before", "_after"))
  comparison[is.na(comparison)] <- 0
  save_table(comparison, paste0(dimension, "_filter_comparison"))
}
details <- unique(a[a$dimension %in% c("variety", "vector") &
                     a$record_id %in% primary$record_id, ])
detail_counts <- aggregate(list(records = rep(1L, nrow(details))),
                           details[c("category", "dimension", "value")], sum)
detail_counts <- detail_counts[order(-detail_counts$records), ]
save_table(detail_counts, "action_details")

# Each record counted once per category; never sum totals after a many-to-many join.
size_summary <- do.call(rbind, lapply(sort(unique(category_rows$category)), function(cat) {
  ids <- category_rows$record_id[category_rows$category == cat]
  x <- primary$data_total[primary$record_id %in% ids]
  known <- x[!is.na(x)]
  qs <- if (length(known)) quantile(known, c(.25, .5, .75), names = FALSE) else rep(NA_real_, 3)
  data.frame(category = cat, records = length(x), size_known = length(known),
             missing_share = if(length(x)) mean(is.na(x)) else NA_real_,
             q25 = qs[1], median = qs[2], q75 = qs[3])
}))
save_table(size_summary, "record_counts_by_action")
missing <- data.frame(field = names(primary),
                      missing = sapply(primary, function(x) sum(is.na(x))),
                      unknown = sapply(primary, function(x) sum(tolower(as.character(x)) == "unknown", na.rm = TRUE)),
                      denominator = nrow(primary))
save_table(missing, "primary_field_quality")
save_table(d[d$id_collision == "1", c("record_id", "incident_id", "organization", "year",
                                      "analysis_status", "source_url")], "id_collisions")

by_industry <- merge(category_rows, primary[c("record_id", "industry")], by = "record_id")
by_industry$sector <- ifelse(is.na(by_industry$industry), "Missing",
                             substr(by_industry$industry, 1, 2))
industry_actions <- aggregate(list(records = rep(1L, nrow(by_industry))),
                              by_industry[c("sector", "category")], sum)
save_table(industry_actions, "industry_actions")

plot_data <- subset(category_summary, cohort == "primary")
plot_data <- plot_data[order(plot_data$records), ]
png("results_vcdb/actions.png", width = 1500, height = 900, res = 140)
par(mar = c(6, 10, 4, 2))
barplot(plot_data$records, names.arg = plot_data$category, horiz = TRUE, las = 1,
        col = "#2A6F97", xlab = "Source cards with recorded action (labels overlap)",
        main = "VCDB: actions in confirmed disclosures")
mtext("Source: VERIS Community Database | github.com/vz-risk/VCDB | CC BY-SA 4.0", side = 1, line = 4, cex = .8)
dev.off()
source("vcdb_report.R", local = TRUE)
