# Threat-Modeling-Risk-Analysis-Lab-with-R
# Real-Time CVE Analysis Pipeline
Analyzes NVD data to quantify risks and map MITRE ATT&CK techniques.

## Setup
1. Install R packages: `tidyverse`, `httr`, `jsonlite`, `shiny`.
2. Run scripts in order:
   - `fetch_data.R`
   - `risk_analysis.R`
   - `chi_square_test.R`
   - `attack_simulation.R`
3. Launch the dashboard: `shiny-app/app.R`.
