library(httr)
library(jsonlite)

message("\n=== Starting CVE Data Fetch ===")

fetch_nvd_data <- function() {
  tryCatch({
    # Current working API endpoint (as of 2023)
    api_url <- "https://services.nvd.nist.gov/rest/json/cves/1.0"
    
    message("1. Making API request to NVD...")
    response <- GET(
      url = api_url,
      query = list(resultsPerPage = 2000),
      add_headers(
        "User-Agent" = "Mozilla/5.0",
        "Accept" = "application/json"
      ),
      timeout(30)
    )
    
    # Check response
    if (status_code(response) == 404) {
      stop("API endpoint not found (404). Check if NVD API has changed.")
    }
    if (http_status(response)$category != "Success") {
      stop("API request failed: ", status_code(response), " - ", content(response, "text"))
    }
    message("2. Received API response (status ", status_code(response), ")")
    
    # Parse response
    raw_data <- fromJSON(content(response, "text", encoding = "UTF-8"))
    
    # Debug: Show API rate limit info
    rate_limit <- headers(response)$`x-ratelimit-remaining`
    message("3. API Rate Limit Remaining: ", ifelse(is.null(rate_limit), "Unknown", rate_limit))
    
    # Process vulnerabilities
    if (!"result" %in% names(raw_data) || !"CVE_Items" %in% names(raw_data$result)) {
      stop("Unexpected API response format. Check NVD API documentation.")
    }
    
    cve_items <- raw_data$result$CVE_Items
    message("4. Found ", length(cve_items), " CVEs to process")
    
    # Process each CVE
    processed <- lapply(cve_items, function(item) {
      tryCatch({
        cve <- item$cve
        
        # Get English description
        desc <- NA
        if ("description" %in% names(cve) && 
            "description_data" %in% names(cve$description)) {
          eng_desc <- cve$description$description_data[
            sapply(cve$description$description_data, function(x) x$lang == "en")
          ]
          if (length(eng_desc) > 0) desc <- eng_desc[[1]]$value
        }
        
        # Get CVSSv3 score
        cvss_score <- NA
        severity <- NA
        if ("impact" %in% names(item) && 
            "baseMetricV3" %in% names(item$impact)) {
          cvss_score <- item$impact$baseMetricV3$cvssV3$baseScore
          severity <- item$impact$baseMetricV3$cvssV3$baseSeverity
        }
        
        data.frame(
          CVE_ID = cve$CVE_data_meta$ID,
          Description = desc,
          CVSSv3_Score = cvss_score,
          Severity = severity,
          stringsAsFactors = FALSE
        )
      }, error = function(e) {
        message("Warning: Error processing CVE - ", e$message)
        NULL
      })
    })
    
    # Combine results
    final_df <- do.call(rbind, processed[!sapply(processed, is.null)])
    final_df <- final_df[!is.na(final_df$CVSSv3_Score), ]
    
    if (nrow(final_df) == 0) {
      warning("No CVEs with CVSSv3 scores found in response")
    } else {
      final_df$HighRisk <- as.integer(final_df$Severity %in% c("CRITICAL", "HIGH"))
      message("5. Processed ", nrow(final_df), " CVEs with valid CVSSv3 scores")
    }
    
    # Save output
    if (!dir.exists("data")) dir.create("data")
    write.csv(final_df, "data/cve_dataset.csv", row.names = FALSE)
    message("6. Data saved to data/cve_dataset.csv")
    
    return(nrow(final_df))
    
  }, error = function(e) {
    message("FATAL ERROR: ", e$message)
    return(-1)
  })
}

# Execute
num_cves <- fetch_nvd_data()
if (num_cves < 0) quit(status = 1)
message("\n=== Completed ===")
quit(status = 0)