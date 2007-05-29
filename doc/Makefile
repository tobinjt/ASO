all: logparser.ps

logparser.ps: logparser.dvi
	dvips -o "$@" "$<"

logparser.dvi: logparser.tex
	# Run latex to handle \cite: latex will add \cite references to
	# logparser.aux.
	latex -interaction=nonstopmode "$<"           || rm -f "$@"
	# Run bibtex to extract the right entries from logparser-bibliography.bib
	# into logparser-bibliography.bbl
	bibtex $$( echo "$<" | sed -e 's/.tex$$//' )  || rm -f "$@"
	# Run latex again to pull in logparser-bibliography.bbl.
	latex -interaction=nonstopmode "$<"           || rm -f "$@"
	# Run latex for a third time to fix up references from logparser.tex to
	# logparser-bibliography.bbl.
	latex -interaction=nonstopmode "$<"           || rm -f "$@"
	# Finally done.

# This will cause logparser.dvi to be remade when logparser-flow-chart.ps
# changes.  There are no commands specified, make seems to run the commands from
# the logparser.dvi: logparser.tex rule, though whether that's reliable or not I
# dunno.
logparser.dvi: logparser-flow-chart.ps logparser-bibliography.bib
logparser.dvi: plot-cached-discarded.ps plot-cached-discarded-factor.ps plot-normal-shuffle-reverse.ps

logparser-flow-chart.ps: logparser-flow-chart.dot
	dot -o "$@" -Tps -x "$<"

plot-cached-discarded.ps: stats-cached.txt stats-discarded.txt
plot-cached-discarded-factor.ps: stats-cached-discarded-factor.txt
plot-normal-shuffle-reverse.ps: stats-normal.txt stats-shuffle.txt stats-reverse.txt

plot-%.ps: plot-%.gpi
	gnuplot "$<"

stats-cached-discarded-factor.txt: stats-cached.txt stats-discarded.txt
	paste -d ' ' stats-cached.txt stats-discarded.txt | awk '$$1 != "#" {print ($$9 * 100 / $$3) - 100 }' > "$@"

clean:
	rm -f *.dvi *.ps *.aux *.toc *.log *.bbl *.blg

check:
	chktex logparser.tex

2up: logparser-2up.ps

logparser-2up.ps: logparser.ps
	psnup -2 logparser.ps logparser-2up.ps
