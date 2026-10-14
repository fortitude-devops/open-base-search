# Run from the project directory in RStudio: source("analysis.R")
# Uses base R only. Source: Have I Been Pwned, https://haveibeenpwned.com/
breaches <- read.csv("data/breaches.csv", stringsAsFactors = FALSE,
                     na.strings = "", fileEncoding = "UTF-8")
classes <- read.csv("data/data_classes.csv", stringsAsFactors = FALSE,
                    fileEncoding = "UTF-8")
breaches$breach_date <- as.Date(breaches$breach_date)
breaches$year <- as.integer(format(breaches$breach_date, "%Y"))
# Only verified incidents; exclude fabricated records, spam lists and malware.
keep <- with(breaches, verified == 1 & fabricated == 0 &
             spam_list == 0 & malware == 0)
selected <- breaches[!is.na(keep) & keep, ]
if (nrow(selected) == 0) stop("No incidents pass the analysis filter")
dir.create("results", showWarnings = FALSE)
by_year <- aggregate(list(incidents = rep(1L, nrow(selected)),
                          email_occurrences = selected$pwn_count),
                     by = list(year = selected$year), FUN = sum)
class_counts <- sort(table(classes$data_class[classes$name %in% selected$name]),
                     decreasing = TRUE)
class_summary <- data.frame(data_class = names(class_counts),
                            incidents = as.integer(class_counts),
                            share_of_incidents = as.numeric(class_counts) / nrow(selected))
write.csv(by_year, "results/by_year.csv", row.names = FALSE)
write.csv(class_summary, "results/data_classes.csv", row.names = FALSE)
png("results/incidents_by_year.png", width = 1400, height = 800, res = 140)
plot(by_year$year, by_year$incidents, type = "b", pch = 19,
     xlab = "Breach year (approximate)", ylab = "Catalogued incidents",
     main = "Verified service breaches in the HIBP catalogue",
     sub = "Source: Have I Been Pwned | https://haveibeenpwned.com/ | CC BY 4.0")
dev.off()
if (length(class_counts) > 0) {
  png("results/data_classes.png", width = 1600, height = 1000, res = 140)
  par(mar = c(5, 13, 4, 2))
  top <- rev(head(class_counts, 10))
  barplot(top, horiz = TRUE, las = 1, col = "steelblue",
          xlab = "Incidents (categories overlap)", main = "Common exposed data classes",
          sub = "Source: Have I Been Pwned | https://haveibeenpwned.com/")
  dev.off()
}
cat("Source: Have I Been Pwned — https://haveibeenpwned.com/\n")
cat("All catalogue entries:", nrow(breaches), "| Selected:", nrow(selected), "\n")
cat("Email occurrences (NOT unique people):", sum(selected$pwn_count), "\n")
print(head(class_summary, 10))
