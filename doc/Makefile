all: logparser.pdf

%.ps: %.dvi
	dvips -o "$@" "$<"

%.pdf: %.ps
	ps2pdf "$<" "$@"

%.dvi: %.tex
	# Run latex to handle \cite: latex will add \cite references to
	# logparser.aux.
	latex -interaction=nonstopmode "$<"           || (rm -f "$@"; false)
	# Run bibtex to extract the right entries from logparser-bibliography.bib
	# into logparser-bibliography.bbl
	bibtex $$( echo "$<" | sed -e 's/.tex$$//' )  || (rm -f "$@"; false)
	# Run latex again to pull in logparser-bibliography.bbl.
	latex -interaction=nonstopmode "$<"           || (rm -f "$@"; false)
	# Run latex for a third time to fix up references from logparser.tex to
	# logparser-bibliography.bbl.
	latex -interaction=nonstopmode "$<"           || (rm -f "$@"; false)
	# Finally done.

# This will cause logparser.dvi to be remade when logparser-flow-chart.ps
# changes.  There are no commands specified, make seems to run the commands from
# the logparser.dvi: logparser.tex rule, though whether that's reliable or not I
# dunno.
logparser.dvi: logparser-flow-chart.ps logparser-bibliography.bib
logparser.dvi: plot-cached-discarded.ps plot-cached-discarded-factor.ps
logparser.dvi: plot-normal-shuffle-reverse.ps plot-normal-shuffle-reverse-factor.ps
logparser.dvi: plot-normal-filesize-numlines-factor.ps plot-normal-filesize-numlines.ps

logparser-flow-chart.ps: logparser-flow-chart.dot
	dot -o "$@" -Tps -x "$<"

plot-cached-discarded.ps: stats-cached.txt stats-discarded.txt
plot-cached-discarded-factor.ps: stats-cached-discarded-factor.txt
plot-normal-shuffle-reverse.ps: stats-normal.txt stats-shuffle.txt stats-reverse.txt
plot-normal-shuffle-reverse-factor.ps: stats-normal-shuffle-reverse-factor.txt
plot-normal-filesize-numlines-factor.ps: stats-normal-filesize-numlines-factor.txt
plot-normal-filesize-numlines.ps: stats-normal.txt file-sizes.txt wc.txt

plot-%.ps: plot-%.gpi
	gnuplot "$<"

stats-normal-stripped.txt: stats-normal.txt
	sed -e '/^#/d' "$<" > "$@"

stats-normal-filesize-numlines-factor.txt: stats-normal-stripped.txt wc.txt file-sizes.txt
	paste -d ' ' $^ | awk 'BEGIN { print "# line-count file-size"; }; $$1 != "#" {print (($$3 * 10 * 1000 / $$8)), " ", (($$3 * 1000 * 1000 / $$11)) }' > "$@"

stats-cached-discarded-factor.txt: stats-cached.txt stats-discarded.txt
	paste -d ' ' $^ | awk '$$1 != "#" {print ($$9 * 100 / $$3) - 100 }' > "$@"

stats-normal-shuffle-reverse-factor.txt: stats-normal.txt stats-shuffle.txt stats-reverse.txt
	paste -d ' ' $^ | awk '$$1 != "#" {print (($$9 * 100 / $$3) - 100), " ", (($$15 * 100 / $$3) - 100) }' > "$@"

clean:
	rm -f *.dvi *.ps *.aux *.toc *.log *.bbl *.blg *.pdf *.out

check:
	chktex logparser.tex

2up: logparser-2up.ps

logparser-2up.ps: logparser.ps
	psnup -2 logparser.ps logparser-2up.ps
