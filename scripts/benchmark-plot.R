#! /usr/bin/Rscript

suppressPackageStartupMessages({
  library(ggplot2)
})

lf.direct <- read.csv("bench-lf-direct.tab", header=TRUE)
