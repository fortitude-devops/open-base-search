# Unsupervised PAM on samples with equal-family Jaccard distances.
# Data: VERIS Community Database, https://github.com/vz-risk/VCDB, CC BY-SA 4.0.
if (!requireNamespace("cluster", quietly = TRUE)) stop("The R package 'cluster' is required")
input <- read.csv("data_clusters/matrix.csv", check.names = FALSE)
dictionary <- read.csv("data_clusters/feature_dictionary.csv", stringsAsFactors = FALSE)
meta <- read.csv("data_clusters/metadata.csv", colClasses = "character", na.strings = "")
ids <- input$record_id
X <- as.matrix(input[, -1, drop = FALSE])
storage.mode(X) <- "double"
meta_core <- meta[match(ids, meta$record_id), ]
stopifnot(!anyNA(X), !anyDuplicated(ids), identical(colnames(X), dictionary$feature),
          all(X %in% c(0, 1)), !anyNA(meta_core$record_id))
families <- split(seq_len(ncol(X)), dictionary$family)
stopifnot(all(vapply(families, function(cols) all(rowSums(X[, cols, drop=FALSE]) > 0), logical(1))))
dir.create("results_clusters", showWarnings = FALSE)
save_table <- function(x, name) write.csv(x, file.path("results_clusters", paste0(name, ".csv")), row.names=FALSE, na="")

jaccard <- function(A, B, blocks = families) {
  result <- matrix(0, nrow(A), nrow(B))
  for (cols in blocks) {
    aa <- A[, cols, drop=FALSE]
    bb <- B[, cols, drop=FALSE]
    intersection <- tcrossprod(aa, bb)
    union <- outer(rowSums(aa), rowSums(bb), "+") - intersection
    if (any(union == 0)) stop("Empty feature family in Jaccard comparison")
    result <- result + 1 - intersection / union
  }
  result / length(blocks)
}
adjusted_rand <- function(a, b) {
  tab <- table(a, b)
  choose2 <- function(x) x * (x - 1) / 2
  observed <- sum(choose2(tab)); total <- choose2(sum(tab))
  left <- sum(choose2(rowSums(tab))); right <- sum(choose2(colSums(tab)))
  expected <- left * right / total
  denom <- (left + right) / 2 - expected
  if (abs(denom) < 1e-12) return(as.numeric(observed == expected))
  (observed - expected) / denom
}
assign_to <- function(medoids, rows = seq_len(nrow(X)), blocks = families) {
  D <- jaccard(X[rows, , drop=FALSE], X[medoids, , drop=FALSE], blocks)
  max.col(-D, ties.method = "first")
}

# Geometry checks catch incorrect binary/Jaccard implementation before fitting.
check_D <- jaccard(X[1:30,,drop=FALSE], X[1:30,,drop=FALSE])
stopifnot(max(abs(check_D-t(check_D))) < 1e-12, all(diag(check_D)==0),
          all(check_D>=0 & check_D<=1),
          adjusted_rand(c(1,1,2,2),c(2,2,1,1))==1)
toy <- rbind(c(1,0,1,0), c(0,1,1,0))
stopifnot(jaccard(toy,toy,list(1:2,3:4))[1,2]==.5)

# The evaluation subset is disjoint from all fitting samples. It is used for
# exploratory k selection, not a held-out supervised accuracy claim.
set.seed(2026)
eval_ids <- sample(seq_len(nrow(X)), min(600L, floor(nrow(X) / 4)))
pool <- setdiff(seq_len(nrow(X)), eval_ids)
eval_dist <- as.dist(jaccard(X[eval_ids, , drop=FALSE], X[eval_ids, , drop=FALSE]))
seeds <- c(42L, 123L, 2026L)
ks <- 2:8
runs <- list(); metrics <- list()
for (seed in seeds) {
  set.seed(seed)
  sample_ids <- sample(pool, min(1000L, length(pool)))
  D <- as.dist(jaccard(X[sample_ids, , drop=FALSE], X[sample_ids, , drop=FALSE]))
  for (k in ks) {
    fit <- cluster::pam(D, k=k, diss=TRUE, pamonce=5, keep.diss=FALSE, keep.data=FALSE)
    medoids <- sample_ids[fit$id.med]
    assigned <- assign_to(medoids, eval_ids)
    n_groups <- length(unique(assigned))
    silhouette <- if (n_groups > 1 && n_groups < length(assigned))
      mean(cluster::silhouette(assigned, eval_dist)[, "sil_width"]) else NA_real_
    key <- paste(seed, k, sep="_")
    runs[[key]] <- list(medoids=medoids, assigned=assigned, sample=sample_ids)
    metrics[[key]] <- data.frame(seed=seed, k=k, eval_silhouette=silhouette,
                                min_eval_share=min(tabulate(assigned, nbins=k))/length(assigned))
  }
  cat("Finished fitting sample seed", seed, "\n")
}
metrics <- do.call(rbind, metrics)
save_table(metrics, "all_runs")
selection <- do.call(rbind, lapply(ks, function(k) {
  pair_scores <- combn(seeds, 2, FUN=function(s)
    adjusted_rand(runs[[paste(s[1],k,sep="_")]]$assigned,
                  runs[[paste(s[2],k,sep="_")]]$assigned))
  rows <- metrics[metrics$k == k, ]
  data.frame(k=k, mean_silhouette=mean(rows$eval_silhouette, na.rm=TRUE),
             mean_ARI=mean(pair_scores), min_cluster_share=min(rows$min_eval_share))
}))
selection$eligible <- with(selection, is.finite(mean_silhouette) & mean_ARI >= .7 & min_cluster_share >= .02)
candidates <- selection[selection$eligible, ]
fallback <- nrow(candidates) == 0
if (fallback) candidates <- selection[is.finite(selection$mean_silhouette), ]
if (!nrow(candidates)) stop("No valid clustering found")
best_k <- candidates$k[which.max(candidates$mean_silhouette)]
best_run <- metrics[metrics$k == best_k, ]
best_seed <- best_run$seed[which.max(best_run$eval_silhouette)]
best <- runs[[paste(best_seed, best_k, sep="_")]]
assignment <- assign_to(best$medoids)
distances <- jaccard(X, X[best$medoids, , drop=FALSE])
nearest <- distances[cbind(seq_len(nrow(X)), assignment)]
margin <- apply(distances, 1, function(v) sort(v)[2] - min(v))
save_table(selection, "k_selection")
save_table(data.frame(record_id=ids, cluster=assignment, distance_to_medoid=nearest,
                      assignment_margin=margin), "assignments")
save_table(data.frame(record_id=ids[eval_ids]), "evaluation_sample")
save_table(data.frame(record_id=ids[best$sample]), "selected_fitting_sample")

# Check whether clusters survive removal of detailed action subtypes/vectors.
coarse <- families
coarse$action <- which(dictionary$family == "action" & grepl(":category:", dictionary$value))
coarse_D <- as.dist(jaccard(X[best$sample, , drop=FALSE], X[best$sample, , drop=FALSE], coarse))
coarse_fit <- cluster::pam(coarse_D, k=best_k, diss=TRUE, pamonce=5, keep.diss=FALSE, keep.data=FALSE)
coarse_labels <- assign_to(best$sample[coarse_fit$id.med], eval_ids, coarse)
coarse_ari <- adjusted_rand(best$assigned, coarse_labels)
without_actor <- families[names(families) != "actor"]
noactor_D <- as.dist(jaccard(X[best$sample,,drop=FALSE], X[best$sample,,drop=FALSE], without_actor))
noactor_fit <- cluster::pam(noactor_D, k=best_k, diss=TRUE, pamonce=5, keep.diss=FALSE, keep.data=FALSE)
noactor_labels <- assign_to(best$sample[noactor_fit$id.med], eval_ids, without_actor)
noactor_ari <- adjusted_rand(best$assigned, noactor_labels)
save_table(data.frame(check=c("coarse_actions", "without_actor"),
                      adjusted_rand=c(coarse_ari,noactor_ari)), "sensitivity")

global <- colMeans(X)
profiles <- do.call(rbind, lapply(seq_len(best_k), function(g) {
  prevalence <- colMeans(X[assignment == g, , drop=FALSE])
  data.frame(cluster=g, family=dictionary$family, value=dictionary$value,
             share_in_cluster=prevalence, share_overall=global,
             difference=prevalence-global, lift=prevalence/global)
}))
save_table(profiles, "feature_profiles")
top <- do.call(rbind, lapply(seq_len(best_k), function(g) {
  p <- profiles[profiles$cluster == g & profiles$share_in_cluster >= .2, ]
  p <- p[order(-p$difference, -p$share_in_cluster), ]
  head(p, 10)
}))
save_table(top, "top_features")
summary <- do.call(rbind, lapply(seq_len(best_k), function(g) {
  rows <- which(assignment == g)
  sizes <- as.numeric(meta_core$data_total[rows])
  org <- tolower(trimws(meta_core$organization[rows])); org <- org[!is.na(org) & nzchar(org)]
  data.frame(cluster=g, records=length(rows), share=length(rows)/nrow(X),
             median_records=if(all(is.na(sizes))) NA_real_ else median(sizes, na.rm=TRUE),
             size_known=sum(!is.na(sizes)), mean_recorded_tokens=mean(as.numeric(meta_core$recorded_tokens[rows])),
             largest_known_org_share=if(length(org)) max(table(org))/length(rows) else NA_real_,
             medoid_id=ids[best$medoids[g]], medoid_source=meta_core$source_url[best$medoids[g]])
}))
save_table(summary, "cluster_summary")
for (field in c("year", "industry", "analysis_status")) {
  eligible <- meta[meta$eligible == "1", ]
  vals <- eligible[[field]]; vals[is.na(vals)] <- "Missing"
  audit <- as.data.frame(table(value=vals, included=eligible$in_cluster_core))
  save_table(audit, paste0("selection_", field))
}
actions <- read.csv("data_vcdb/actions.csv", stringsAsFactors=FALSE)
actions <- unique(actions[actions$dimension == "category", c("record_id", "category")])
action_audit <- merge(actions, meta[meta$eligible == "1", c("record_id", "in_cluster_core")], by="record_id")
save_table(as.data.frame(table(category=action_audit$category, included=action_audit$in_cluster_core)), "selection_actions")

caption <- "VERIS Community Database | github.com/vz-risk/VCDB | CC BY-SA 4.0"
png("results_clusters/cluster_sizes.png", width=1400, height=850, res=140)
par(mar=c(6,5,4,2))
barplot(summary$records, names.arg=paste("Cluster", summary$cluster), col="#2A6F97",
        ylab="Source cards", main="VCDB: incident scenario groups")
mtext(caption, side=1, line=4, cex=.8); dev.off()
png("results_clusters/k_selection.png", width=1400, height=850, res=140)
par(mar=c(6,5,4,2))
plot(selection$k, selection$mean_silhouette, type="b", pch=19,
     xlab="Number of clusters k", ylab="Mean evaluation silhouette",
     main="Cluster separation across three fitting samples")
abline(v=best_k, col="#D97706", lty=2)
mtext(caption, side=1, line=4, cex=.8); dev.off()
action_cols <- which(dictionary$family == "action" & grepl(":category:", dictionary$value))
heat <- sapply(seq_len(best_k), function(g) colMeans(X[assignment==g, action_cols, drop=FALSE]))
png("results_clusters/action_profiles.png", width=1400, height=900, res=140)
par(mar=c(6,9,4,2))
image(seq_len(best_k), seq_along(action_cols), t(heat), axes=FALSE,
      col=hcl.colors(20, "Blues", rev=TRUE), xlab="", ylab="", main="Recorded action prevalence in each cluster (0–1)", zlim=c(0,1))
axis(1, at=seq_len(best_k), labels=paste("Cluster", seq_len(best_k)))
axis(2, at=seq_along(action_cols), labels=sub(":.*", "", dictionary$value[action_cols]), las=1)
for(g in seq_len(best_k)) for(j in seq_along(action_cols)) text(g,j,sprintf("%.2f",heat[j,g]),cex=.8,col=if(heat[j,g]>.55) "white" else "black")
mtext(caption, side=1, line=4, cex=.8); dev.off()

saveRDS(list(medoid_ids=ids[best$medoids], medoid_vectors=X[best$medoids,,drop=FALSE],
             dictionary=dictionary, k=best_k, seed=best_seed, selection=selection), "results_clusters/model.rds")
writeLines(c(capture.output(sessionInfo()), "", paste("Coarse-action sensitivity ARI:", coarse_ari),
             paste("Selection fallback used:", fallback)), "results_clusters/run_details.txt")
report <- c("Анализ и кластеризация VCDB", caption, "",
            paste("Полных карточек в кластеризации:",nrow(X)), paste("Выбранное число групп:",best_k),
            paste("Средний silhouette:",round(selection$mean_silhouette[selection$k==best_k],3)),
            paste("Устойчивость между выборками (ARI):",round(selection$mean_ARI[selection$k==best_k],3)),
            paste("Чувствительность к упрощению action (ARI):",round(coarse_ari,3)),
            paste("Чувствительность к исключению actor (ARI):",round(noactor_ari,3)),
            paste("Использован запасной выбор без порога устойчивости:",fallback), "",
            "Группы описывают сходство записанных характеристик, не доказывают первопричины.",
            "Проверяйте sensitivity.csv: низкий ARI без actor означает зависимость от типа участника, а не универсальную типологию.",
            "Silhouette — мера разделения, не точность предсказания; ARI — согласованность группировок.",
            "Порог ARI 0.7 и минимум 2% — эвристики; k выбирается исследовательски.",
            "Пропуски не заполнены выдуманными фактами. Карточки без одного из 4 семейств исключены только из кластеризации.",
            "Ноль в матрице означает, что категория не записана; это не доказанное отсутствие свойства.", "")
for (g in seq_len(best_k)) {
  report <- c(report, paste("Группа", g, "— карточек:", summary$records[g]),
              capture.output(print(top[top$cluster==g,c("family","value","share_in_cluster")], row.names=FALSE)), "")
}
writeLines(enc2utf8(report), "results_clusters/report_ru.txt", useBytes=TRUE)
cat(paste(head(report, 10), collapse="\n"), "\n")
