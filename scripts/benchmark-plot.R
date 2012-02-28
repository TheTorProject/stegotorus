#! /usr/bin/Rscript

suppressPackageStartupMessages({
  library(plyr)
  library(ggplot2)
  library(tikzDevice)
})

peval.raw <- read.csv("perf-eval.csv", header=TRUE)

peval.u <- rename(ddply(peval.raw, .(benchmark,relay,cap),
                        function(x) fivenum(x$up)),
                  c(V1='min', V2='lhinge', V3='med', V4='uhinge', V5='max'))
peval.d <- rename(ddply(peval.raw, .(benchmark,relay,cap),
                        function(x) fivenum(x$down)),
                  c(V1='min', V2='lhinge', V3='med', V4='uhinge', V5='max'))

# pareto became unstable at 50 connections per second
peval.u <- subset(peval.u, benchmark!='files.pareto'|cap<=50)
peval.d <- subset(peval.d, benchmark!='files.pareto'|cap<=50)

peval.u$direction <- factor("KBps upstream")
peval.d$direction <- factor("KBps downstream")

peval <- rbind(peval.u, peval.d)

# force x=0 to appear on all the subplots
zeroes <- ddply(peval, .(benchmark, relay, direction),
                function(x) data.frame(cap=0,min=0,lhinge=0,med=0,
                                       uhinge=0,max=0))
peval <- rbind(peval, zeroes)

peval$benchmark <- ordered(peval$benchmark,
                           levels=c("fixedrate", "files.fixed", "files.pareto"),
                           labels=c("Fixed rate stream", "Fixed-size files",
                             "Pareto-distributed files"))

peval$Relay <- ordered(peval$relay,
                       levels=c("direct", "tor", "st.http"),
                       labels=c("Direct", "Tor", "StegoTorus (HTTP)"))

RelayFill=c("Direct"="#666666", "Tor"="#72B8E7",
              "StegoTorus (HTTP)"="#E31A1C")

RelayColors=c("Direct"="#666666", "Tor"="#1F78B4",
            "StegoTorus (HTTP)"="#E31A1C")

graf <- ggplot(peval, aes(x=cap, ymin=lhinge, ymax=uhinge, y=med)) +
  geom_ribbon(aes(fill=Relay), alpha=0.3) +
  geom_line(aes(colour=Relay)) +
  facet_grid(direction~benchmark, scales='free') +
  scale_x_continuous(expand=c(.01,0)) +
  scale_y_continuous(expand=c(0,0)) +
  scale_colour_manual(values=RelayColors) +
  scale_fill_manual(values=RelayFill) +
  theme_bw(base_size=8) +
  opts(panel.border=theme_blank(),
       legend.key=theme_blank(),
       legend.title=theme_blank(),
       legend.background=theme_rect(fill="white",colour=NA),
       legend.position=c(0.1,0.8),
       strip.background=theme_blank(),
       axis.ticks.margin=unit(0.25, "lines")
       )

tikz(file="perf-eval.tex", width=6.5, height=3, standAlone=TRUE)
print(graf)
invisible(dev.off())
