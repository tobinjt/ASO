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
logparser.dvi: logparser-bibliography-style.bst
logparser.dvi: plot-cached-discarded.ps plot-cached-discarded-factor.ps
logparser.dvi: plot-normal-shuffle-reverse.ps plot-normal-shuffle-factor.ps plot-normal-reverse-factor.ps
logparser.dvi: plot-normal-filesize-numlines-factor.ps plot-normal-filesize-numlines.ps
logparser.dvi: plot-log22-distribution-by-rule.ps plot-log22-distribution-versus-rule-count.ps
logparser.dvi: plot-hits.ps
logparser.dvi: stats-cached-discarded-include-for-graph.tex stats-cached-discarded-include-for-discussion.tex
logparser.dvi: stats-normal-shuffle-reverse-percentage.tex

logparser-flow-chart.ps: logparser-flow-chart.dot
	dot -o "$@" -Tps -x "$<"

plot-cached-discarded.ps: stats-cached.txt stats-discarded.txt
plot-cached-discarded-factor.ps: stats-cached-discarded-factor.txt
plot-normal-shuffle-reverse.ps: stats-normal.txt stats-shuffle.txt stats-reverse.txt
plot-normal-shuffle-factor.ps: stats-normal-shuffle-reverse-factor.txt
plot-normal-reverse-factor.ps: stats-normal-shuffle-reverse-factor.txt
plot-normal-filesize-numlines-factor.ps: stats-normal-filesize-numlines-factor.txt
plot-normal-filesize-numlines.ps: stats-normal.txt file-sizes.txt wc.txt
plot-log22-distribution-by-rule.ps: stats-log22-distribution-by-rule.txt
plot-log22-distribution-versus-rule-count.ps: stats-log22-rule-count-by-program.txt
plot-hits.ps: stats-hits.txt

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

stats-log22-distribution-by-rule.txt:
	sqlite3 -separator ' ' ../sql/db.sq3 "select hits, program from rules where hits > 0 order by hits;" | nl > "$@"

stats-log22-rule-count-by-program.txt:
	sqlite3 -separator ' ' ../sql/db.sq3 "select sum(hits), count(*), program from rules group by program;" | awk '$$1 > 0 { print }' | sed -e 's,postfix/,,' | nl > "$@"

stats-hits.txt:
	sqlite3 -separator ' ' ../sql/db.sq3 "select rule_order from rules order by rule_order;" | nl > "$@"

stats-cached-discarded-stats.txt: stats-cached-discarded-factor.txt
	perl ../stats/stddev "$<" > "$@"
	echo "Row: All logs" >> "$@"

stats-cached-discarded-stats-fast.txt: stats-cached-discarded-factor.txt
	sed -e '1,21d; 23,61d; 69,$$d;' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Logs 22 and 62--68" >> "$@"

stats-cached-discarded-stats-slow.txt: stats-cached-discarded-factor.txt
	sed -e '22d; 62,68d;' "$<" | perl ../stats/stddev > "$@"
	echo "Row: All logs except 22 and 62--68" >> "$@"

stats-cached-discarded-include-for-graph.tex: stats-cached-discarded-stats.txt stats-cached-discarded-stats-fast.txt stats-cached-discarded-stats-slow.txt 
	perl mk-stats-cached-discarded-include $^ > "$@" || rm -f "$@"

stats-cached-discarded-stats2.txt: stats-cached-discarded-factor.txt
	perl ../stats/stddev "$<" > "$@"
	echo "Row:  " >> "$@"

stats-cached-discarded-include-for-discussion.tex: stats-cached-discarded-stats2.txt
	perl mk-stats-normal-shuffle-reverse-percentage $^ > "$@" || rm -f "$@"

stats-normal-shuffle-stats.txt: stats-normal-shuffle-reverse-factor.txt
	awk '{print $$1}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: shuffled" >> "$@"

stats-normal-reverse-stats.txt: stats-normal-shuffle-reverse-factor.txt
	awk '{print $$2}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: reversed" >> "$@"

stats-normal-shuffle-reverse-percentage.tex: stats-normal-shuffle-stats.txt stats-normal-reverse-stats.txt
	perl mk-stats-normal-shuffle-reverse-percentage $^ > "$@" || rm -f "$@"

stats-normal.txt: stats-normal
	DIR="$<" FILE="$@" make parse-stats

stats-cached.txt: stats-normal
	DIR="$<" FILE="$@" make parse-stats

stats-shuffle.txt: stats-shuffle
	DIR="$<" FILE="$@" make parse-stats

stats-reverse.txt: stats-reverse
	DIR="$<" FILE="$@" make parse-stats

stats-discarded.txt: stats-normal-regex
	DIR="$<" FILE="$@" make parse-stats

parse-stats:
	perl -I../stats ../stats/parse-stats --discard-first "${DIR}"/results.mail.log* > "${FILE}" || rm -f "${FILE}"

clean:
	rm -f *.dvi *.ps *.aux *.toc *.log *.bbl *.blg *.pdf *.out

veryclean: clean
	rm -f	stats-cached.txt stats-discarded.txt stats-normal.txt stats-reverse.txt stats-shuffle.txt 	\
			stats-cached-discarded-factor.txt stats-cached-discarded-include-for-discussion.tex			\
			stats-cached-discarded-include-for-graph.tex stats-cached-discarded-stats-slow.txt			\
			stats-cached-discarded-stats-fast.txt														\
			stats-cached-discarded-stats.txt stats-cached-discarded-stats2.txt							\
			stats-normal-filesize-numlines-factor.txt stats-normal-reverse-stats.txt					\
			stats-normal-shuffle-reverse-factor.txt stats-normal-shuffle-reverse-percentage.tex			\
			stats-normal-shuffle-stats.txt stats-normal-stripped.txt

check:
	chktex logparser.tex

2up: logparser-2up.ps logparser-2up.pdf

logparser-2up.ps: logparser.ps
	psnup -2 "$<" "$@"

logparser-2up.pdf: logparser-2up.ps
	ps2pdf "$<" "$@"

xpdf: logparser.pdf
	xpdf "$<" &
