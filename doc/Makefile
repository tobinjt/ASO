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

# 'make logparser.deps' correctly builds all dependencies, without running
# latex, because latex is noisy and slow.
logparser.deps: build/logparser-flow-chart.ps \
				logparser-bibliography.bib logparser-bibliography-style.bst \
				build/plot-cached-discarded.ps build/plot-cached-discarded-factor.ps  \
				build/plot-normal-shuffle-reverse.ps build/plot-normal-shuffle-factor.ps  \
				build/plot-normal-reverse-factor.ps build/plot-normal-filesize-numlines-factor.ps \
				build/plot-normal-filesize-numlines.ps build/plot-log22-distribution-by-rule.ps \
				build/plot-log22-distribution-versus-rule-count.ps build/plot-hits.ps \
				build/stats-cached-discarded-include-for-graph.tex \
				build/stats-cached-discarded-include-for-discussion.tex \
				build/stats-normal-shuffle-reverse-percentage.tex \
				build/stats-normal-filesize-line-count-include.tex
	touch "$@"

logparser.dvi: logparser.deps

build/logparser-flow-chart.ps: logparser-flow-chart.dot
	dot -o "$@" -Tps -x "$<"

build/plot-cached-discarded.ps: build/stats-cached.txt build/stats-discarded.txt
build/plot-cached-discarded-factor.ps: build/stats-cached-discarded-factor.txt
build/plot-normal-shuffle-reverse.ps: build/stats-normal.txt build/stats-shuffle.txt build/stats-reverse.txt
build/plot-normal-shuffle-factor.ps: build/stats-normal-shuffle-reverse-factor.txt
build/plot-normal-reverse-factor.ps: build/stats-normal-shuffle-reverse-factor.txt
build/plot-normal-filesize-numlines-factor.ps: build/stats-normal-filesize-numlines-factor.txt
build/plot-normal-filesize-numlines.ps: build/stats-normal.txt file-sizes.txt wc.txt
build/plot-log22-distribution-by-rule.ps: stats-log22-distribution-by-rule.txt
build/plot-log22-distribution-versus-rule-count.ps: stats-log22-rule-count-by-program.txt
build/plot-hits.ps: stats-hits.txt

build/plot-%.ps: plot-%.gpi
	gnuplot "$<"

build/stats-normal-stripped.txt: build/stats-normal.txt
	sed -e '/^#/d' "$<" > "$@"

build/stats-normal-filesize-numlines-factor.txt: build/stats-normal-stripped.txt wc.txt file-sizes.txt
	paste -d ' ' $^ | awk 'BEGIN { print "# line-count file-size"; }; $$1 != "#" {print (($$3 * 10 * 1000 / $$8)), " ", (($$3 * 1000 * 1000 / $$11)) }' > "$@"

build/stats-cached-discarded-factor.txt: build/stats-cached.txt build/stats-discarded.txt
	paste -d ' ' $^ | awk '$$1 != "#" {print ($$9 * 100 / $$3) - 100 }' > "$@"

build/stats-normal-shuffle-reverse-factor.txt: build/stats-normal.txt build/stats-shuffle.txt build/stats-reverse.txt
	paste -d ' ' $^ | awk '$$1 != "#" {print (($$9 * 100 / $$3) - 100), " ", (($$15 * 100 / $$3) - 100) }' > "$@"

stats-log22-distribution-by-rule.txt:
	sqlite3 -separator ' ' ../sql/db.sq3 "select hits, program from rules where hits > 0 order by hits;" | nl > "$@"

stats-log22-rule-count-by-program.txt:
	sqlite3 -separator ' ' ../sql/db.sq3 "select sum(hits), count(*), program from rules group by program;" | awk '$$1 > 0 { print }' | sed -e 's,postfix/,,' | nl > "$@"

stats-hits.txt:
	sqlite3 -separator ' ' ../sql/db.sq3 "select rule_order from rules order by rule_order;" | nl > "$@"

build/stats-cached-discarded-stats.txt: build/stats-cached-discarded-factor.txt
	perl ../stats/stddev "$<" > "$@"
	echo "Row: All logs" >> "$@"

build/stats-cached-discarded-stats-fast.txt: build/stats-cached-discarded-factor.txt
	sed -e '1,21d; 23,61d; 69,$$d;' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Logs 22 and 62--68" >> "$@"

build/stats-cached-discarded-stats-slow.txt: build/stats-cached-discarded-factor.txt
	sed -e '22d; 62,68d;' "$<" | perl ../stats/stddev > "$@"
	echo "Row: All logs except 22 and 62--68" >> "$@"

build/stats-cached-discarded-include-for-graph.tex: build/stats-cached-discarded-stats.txt build/stats-cached-discarded-stats-fast.txt build/stats-cached-discarded-stats-slow.txt 
	perl mk-stats-cached-discarded-include $^ > "$@" || (rm -f "$@"; false)

build/stats-normal-filesize-stddev.txt: build/stats-normal-filesize-numlines-factor.txt
	awk '!/#/ {print $$2}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: File size ratio" >> "$@"

build/stats-normal-line-count-stddev.txt: build/stats-normal-filesize-numlines-factor.txt
	awk '!/#/ {print $$1}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Number of lines ratio" >> "$@"

build/stats-normal-filesize-line-count-include.tex: build/stats-normal-filesize-stddev.txt build/stats-normal-line-count-stddev.txt
	perl mk-stats-cached-discarded-include $^ | sed -e 's/\\%//g' > "$@" || (rm -f "$@"; false)

build/stats-cached-discarded-stats2.txt: build/stats-cached-discarded-factor.txt
	perl ../stats/stddev "$<" > "$@"
	echo "Row:  " >> "$@"

build/stats-cached-discarded-include-for-discussion.tex: build/stats-cached-discarded-stats2.txt
	perl mk-stats-normal-shuffle-reverse-percentage $^ > "$@" || (rm -f "$@"; false)

build/stats-normal-shuffle-stats.txt: build/stats-normal-shuffle-reverse-factor.txt
	awk '{print $$1}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: shuffled" >> "$@"

build/stats-normal-reverse-stats.txt: build/stats-normal-shuffle-reverse-factor.txt
	awk '{print $$2}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: reversed" >> "$@"

build/stats-normal-shuffle-reverse-percentage.tex: build/stats-normal-shuffle-stats.txt build/stats-normal-reverse-stats.txt
	perl mk-stats-normal-shuffle-reverse-percentage $^ > "$@" || (rm -f "$@"; false)

build/stats-normal.txt: stats-normal
	DIR="$<" FILE="$@" make parse-stats

build/stats-cached.txt: stats-normal
	DIR="$<" FILE="$@" make parse-stats

build/stats-shuffle.txt: stats-shuffle
	DIR="$<" FILE="$@" make parse-stats

build/stats-reverse.txt: stats-reverse
	DIR="$<" FILE="$@" make parse-stats

build/stats-discarded.txt: stats-normal-regex
	DIR="$<" FILE="$@" make parse-stats

parse-stats:
	perl ../stats/parse-stats --discard-first "${DIR}" > "${FILE}" || (rm -f "${FILE}"; false)

clean:
	rm -f *.dvi *.ps *.aux *.toc *.log *.bbl *.blg *.pdf *.out

veryclean: clean
	rm -f build/*

check:
	chktex logparser.tex

2up: logparser-2up.ps logparser-2up.pdf

logparser-2up.ps: logparser.ps
	psnup -2 "$<" "$@"

logparser-2up.pdf: logparser-2up.ps
	ps2pdf "$<" "$@"

xpdf: logparser.pdf
	xpdf "$<" &
