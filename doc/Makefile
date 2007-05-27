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
logparser.dvi: logparser-flow-chart.ps 
logparser.dvi: logparser-bibliography.bib

logparser-flow-chart.ps: logparser-flow-chart.dot
	dot -o "$@" -Tps -x "$<"

clean:
	rm -f *.dvi *.ps *.aux *.toc *.log

check:
	chktex logparser.tex

2up: logparser-2up.ps

logparser-2up.ps: logparser.ps
	psnup -2 logparser.ps logparser-2up.ps
