FROM rocker/r-ver:4.3.1
ENV R_ENABLE_JIT=0
ENV OMP_THREAD_LIMIT=1

# 1. Install system dependencies for R packages
RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
    libssl-dev \
    libxml2-dev \
    libudunits2-dev \
    libgdal-dev \
    libfontconfig1-dev \
    libharfbuzz-dev \
    libfribidi-dev

# 2. Install ALL required R packages (with error handling)
RUN R -e "install.packages('remotes')" && \
    R -e "remotes::install_cran(c('tidyverse', 'httr', 'jsonlite', 'caret', 'ggplot2', 'shiny', 'lubridate'), dependencies = TRUE)" && \
    R -e "if (!requireNamespace('tidyverse', quietly = TRUE)) stop('Package installation failed')"

# 3. Copy project files
COPY . /home/threat-modeling-lab
WORKDIR /home/threat-modeling-lab