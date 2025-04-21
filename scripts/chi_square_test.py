# Filter top 10 CWEs
top_cwes <- cleaned_data %>%
  count(CWE_ID) %>%
  top_n(10, n) %>%
  pull(CWE_ID)

filtered_data <- cleaned_data %>%
  filter(CWE_ID %in% top_cwes)

contingency_table <- table(filtered_data$Severity, filtered_data$CWE_ID)
chi_test <- chisq.test(contingency_table)

# Save results
sink("reports/chi_square_results.txt")
print(chi_test)
sink()