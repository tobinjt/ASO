all: logparser.ps

logparser.ps: logparser.dvi
	dvips -o "$@" "$<"

logparser.dvi: logparser.tex
	# Run latex twice to handle changed labels, references, sections, etc.
	# Won't be necessary most times, but who cares.
	latex -interaction=nonstopmode "$<"
	latex -interaction=nonstopmode "$<"

# This will cause logparser.dvi to be remade when logparser-flow-chart.ps
# changes.  There are no commands specified, make seems to run the commands from
# the logparser.dvi: logparser.tex rule, though whether that's reliable or not I
# dunno.
logparser.dvi: logparser-flow-chart.ps 

logparser-flow-chart.ps: logparser-flow-chart.dot
	dot -o "$@" -Tps -x "$<"

clean:
	rm -f *.dvi *.ps *.aux *.toc *.log

check:
	lacheck logparser.tex
	chktex logparser.tex

2up:
	psnup -2 logparser.ps logparser-2up.ps
