all: logparser.pdf

%.ps: %.dvi
	dvips -o "$@" "$<"

%.pdf: %.ps
	ps2pdf "$<" "$@"

%.dvi: %.tex
	# Run latex to handle \cite: latex will add \cite references to
	# logparser.aux.
	(latex -interaction=nonstopmode "$<" || rm -f "$@") | tee "$@.out"
	[ -f "$@" ]
	# Rebuild the glossary; see foo.glg for errors
	# Sometimes glossary produces an empty foo.glo, though I cannot figure out why.
	set -e; \
	BASE=$$( basename "$@" .dvi ); \
	if [ ! -s "$$BASE.glo" ]; then \
		(latex -interaction=nonstopmode "$<" || rm -f "$@") | tee "$@.out"; \
	fi; \
	makeindex -s "$$BASE.ist" -t "$$BASE.glg" -o "$$BASE.gls" "$$BASE.glo";
	echo; echo; echo;
	# Rebuild to acronym list; see foo.alg for errors
	set -e; \
	BASE=$$( basename "$@" .dvi ); \
	makeindex -s "$$BASE.ist" -t "$$BASE.alg" -o "$$BASE.acn" "$$BASE.acr";
	echo; echo; echo;
	# Include the new glossary
	(latex -interaction=nonstopmode "$<" || rm -f "$@") | tee "$@.out"
	[ -f "$@" ]
	# Rebuild the index, if there is one; note this is done after the glossary 
	# and acronym lists are pulled in so that they can have index entries too.
	# Run bibtex to extract the right entries from logparser-bibliography.bib
	# into logparser-bibliography.bbl
	# Run latex again to pull in logparser-bibliography.bbl.
	if grep -q "LaTeX Warning: Citation .* on page .* undefined" "$@.out"; then \
		set -e; \
		bibtex $$( echo "$<" | sed -e 's/.tex$$//' ) \
            || (rm -f "$@"; false); \
		make logparser.deps; \
		( latex -interaction=nonstopmode "$<" || rm -f "$@" ) | tee "$@.out"; \
	fi
	[ -f "$@" ]
	# Run latex for a third time to fix up references from $< to
	# logparser-bibliography.bbl.
	if grep -q "LaTeX Warning: Reference .* on page .* undefined" "$@.out"; then \
		( latex -interaction=nonstopmode "$<" || rm -f "$@" ) | tee "$@.out"; \
	fi
	[ -f "$@" ]
	# Run latex for a fourth time in case labels have changed.
	if grep -q "Rerun to get cross-references right." "$@.out"; then \
		( latex -interaction=nonstopmode "$<" || rm -f "$@" ) | tee "$@.out"; \
	fi
	[ -f "$@" ]
	# Run latex for a fifth time in case tables lengths have changed.
	if grep -q "Package longtable Warning: Column widths have changed" "$@.out"; then \
		( latex -interaction=nonstopmode "$<" || rm -f "$@" ) | tee "$@.out"; \
	fi
	[ -f "$@" ]
	cat "$@.out"
	grep Overfull "$@.out" || true
	# Finally done.
	chktex -I0 -q "$<"

# 'make logparser.deps' correctly builds all dependencies, without running
# latex, because latex is noisy and slow.
logparser.dvi: logparser.deps logparser.bbl logparser-acronyms.tex
logparser.deps: build/logparser-flow-chart.ps \
				build/plot-cached-discarded.ps build/plot-cached-discarded-factor.ps  \
				build/plot-normal-shuffle-reverse.ps build/plot-normal-shuffle-factor.ps  \
				build/plot-normal-reverse-factor.ps build/plot-normal-filesize-numlines-factor.ps \
				build/plot-normal-filesize-numlines.ps build/plot-log22-distribution-by-rule.ps \
				build/plot-log22-distribution-versus-rule-count.ps build/plot-hits.ps \
				build/plot-hits-high.ps build/plot-hits-middle.ps \
				build/plot-hits-low.ps \
				build/stats-cached-discarded-include-for-graph.tex \
				build/stats-normal-filesize-line-count-include.tex \
				build/stats-normal-shuffle-reverse-include.tex \
				build/plot-log22-distribution-versus-rule-count-factor.ps \
				build/plot-log22-log-lines.ps \
				build/plot-log22-rules.ps
	touch "$@"

# Rebuild the bibtex db whenever the input changes.
logparser.bbl: logparser-bibliography.bib logparser-bibliography-style.bst
	BASE=$$( basename "$@" .bbl ); \
	if [ ! -f "$$BASE.aux" ]; then \
		latex -interaction=nonstopmode "$$BASE" || ( rm -f "$$BASE.dvi"; false ); \
	fi
	bibtex $$( basename "$@" .bbl ) || (rm -f "$@"; false);

build/logparser-flow-chart.ps: logparser-flow-chart.dot
	dot -o "$@" -Tps -x "$<"

# graph dependencies
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
build/plot-hits-high.ps: stats-hits.txt
build/plot-hits-middle.ps: stats-hits.txt
build/plot-hits-low.ps: stats-hits.txt
build/plot-log22-log-lines.ps: stats-log22-rule-count-by-program.txt
build/plot-log22-rules.ps: stats-log22-rule-count-by-program.txt

build/plot-%.ps: plot-%.gpi
	gnuplot "$<"

build/stats-normal-stripped.txt: build/stats-normal.txt
	sed -e '/^#/d' "$<" > "$@"

# Factored stats for graphs.
build/stats-normal-filesize-numlines-factor.txt: build/stats-normal-stripped.txt wc.txt file-sizes.txt
	paste -d ' ' $^ | awk 'BEGIN { print "# line-count file-size"; }; $$1 != "#" {print (($$3 * 10 * 1000 / $$8)), " ", (($$3 * 1000 * 1000 / $$11)) }' > "$@"

build/stats-cached-discarded-factor.txt: build/stats-cached.txt build/stats-discarded.txt
	paste -d ' ' $^ | awk '$$1 != "#" {print ($$9 * 100 / $$3) - 100 }' > "$@"

build/stats-normal-shuffle-reverse-factor.txt: build/stats-normal.txt build/stats-shuffle.txt build/stats-reverse.txt
	paste -d ' ' $^ | awk '$$1 != "#" {print (($$9 * 100 / $$3) - 100), " ", (($$15 * 100 / $$3) - 100) }' > "$@"

# Log 22 stats
stats-log22-distribution-by-rule.txt:
	sqlite3 -separator ' ' ../sql/db.sq3 "select hits, program from rules where hits > 0 order by hits;" | nl > "$@"

stats-log22-rule-count-by-program.txt:
	sqlite3 -separator ' ' ../sql/db.sq3 "select sum(hits), count(*), program from rules group by program;" | awk '$$1 > 0 { print }' | sed -e 's,postfix/,,' | nl > "$@"

stats-hits.txt:
	sqlite3 -separator ' ' ../sql/db.sq3 "select hits_total from rules order by hits_total;" > "$@.tmp"
	nl "$@.tmp" > "$@"
	rm "$@.tmp"

# Stats for cached/discarded regexs: all logs, logs 22,62-68, all other logs.
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

# File size and number of lines ratios: stddev, mean, etc.
build/stats-normal-filesize-stddev.txt: build/stats-normal-filesize-numlines-factor.txt
	awk '!/#/ {print $$2}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: File size ratio" >> "$@"

build/stats-normal-filesize-stddev-22_62-68.txt: build/stats-normal-filesize-numlines-factor.txt
	awk '!/#/ {print $$2}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: File size ratio (logs 22, 62--68)" >> "$@"

build/stats-normal-filesize-stddev-other.txt: build/stats-normal-filesize-numlines-factor.txt
	awk '!/#/ {print $$2}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: File size ratio (all other logs)" >> "$@"

build/stats-normal-line-count-stddev.txt: build/stats-normal-filesize-numlines-factor.txt
	awk '!/#/ {print $$1}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Number of lines ratio" >> "$@"

build/stats-normal-line-count-stddev-22_62-68.txt: build/stats-normal-filesize-numlines-factor.txt
	awk '!/#/ {print $$1}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: Number of lines ratio (logs 22, 62--68)" >> "$@"

build/stats-normal-line-count-stddev-other.txt: build/stats-normal-filesize-numlines-factor.txt
	awk '!/#/ {print $$1}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: Number of lines ratio (all other logs)" >> "$@"

build/stats-normal-filesize-line-count-include.tex: \
		build/stats-normal-filesize-stddev.txt build/stats-normal-filesize-stddev-22_62-68.txt build/stats-normal-filesize-stddev-other.txt \
		build/stats-normal-line-count-stddev.txt build/stats-normal-line-count-stddev-22_62-68.txt build/stats-normal-line-count-stddev-other.txt
	perl mk-stats-cached-discarded-include $^ | sed -e 's/\\%//g' > "$@" || (rm -f "$@"; false)

# Normal/shuffle/reverse ratios: stddev, mean, etc.
build/stats-normal-shuffle-stddev.txt: build/stats-normal-shuffle-reverse-factor.txt
	awk '!/#/ {print $$1}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Shuffle (all logs)" >> "$@"

build/stats-normal-shuffle-stddev-22_62-68.txt: build/stats-normal-shuffle-reverse-factor.txt
	awk '!/#/ {print $$1}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: Shuffle (logs 22, 62--68)" >> "$@"

build/stats-normal-shuffle-stddev-other.txt: build/stats-normal-shuffle-reverse-factor.txt
	awk '!/#/ {print $$1}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: Shuffle (all other logs)" >> "$@"

build/stats-normal-reverse-stddev.txt: build/stats-normal-shuffle-reverse-factor.txt
	awk '!/#/ {print $$2}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Reverse (all logs)" >> "$@"

build/stats-normal-reverse-stddev-22_62-68.txt: build/stats-normal-shuffle-reverse-factor.txt
	awk '!/#/ {print $$2}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: Reverse (logs 22, 62--68)" >> "$@"

build/stats-normal-reverse-stddev-other.txt: build/stats-normal-shuffle-reverse-factor.txt
	awk '!/#/ {print $$2}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: Reverse (all other logs)" >> "$@"

build/stats-normal-shuffle-reverse-include.tex: \
		build/stats-normal-shuffle-stddev.txt build/stats-normal-shuffle-stddev-22_62-68.txt build/stats-normal-shuffle-stddev-other.txt \
		build/stats-normal-reverse-stddev.txt build/stats-normal-reverse-stddev-22_62-68.txt build/stats-normal-reverse-stddev-other.txt
	perl mk-stats-cached-discarded-include $^ > "$@" || (rm -f "$@"; false)

# Build stats from the directory created by gen-stats.
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
	SRC_DIR="${DIR}" DEST_DIR="${DIR}-graphed" make extract-stats

extract-stats: 
	if [ ! -d "${DEST_DIR}" ]; then \
		mkdir -p "${DEST_DIR}"; \
	fi
	perl ../stats/extract-stats.pl "${SRC_DIR}" "${DEST_DIR}" > "${DEST_DIR}/${SRC_DIR}-synposis"


# Cleanup.
clean:
	rm -f *.dvi *.ps *.aux *.toc *.log *.bbl *.blg *.pdf *.out *.ist *.glg 
	rm -f *.gls *.glo *.cbk *.cit *.lof *.idx *.acn *.acr *.alg *.deps *.lot

veryclean: clean
	rm -f build/*

check:
	chktex -I0 -q logparser.tex

# List all acronyms not followed by {}, for visual inspection.
check-acronyms:
	sed -n -e '/newacronym/!d; s/}.*//; s/.*{//; s/$$/[^{]/; p;' logparser-acronyms.tex | grep -f - -n logparser.tex

todo:
	grep -E 'TODO|XXX' logparser.tex logparser-acronyms.tex

2up: logparser-2up.ps logparser-2up.pdf

logparser-2up.ps: logparser.ps
	psnup -2 "$<" "$@"

logparser-2up.pdf: logparser-2up.ps
	ps2pdf "$<" "$@"

xpdf: logparser.pdf
	xpdf "$<" &
