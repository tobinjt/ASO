# NOTE: you need to run 'make clean' between running 'make foo.dvi' and 'make
# foo.pdf', otherwise latex will only be run once and it will get very confused.
all: logparser.pdf

run_latex:
	("${PROGRAM}" -interaction=nonstopmode "${SOURCE}" || rm -f "${DEST}") | tee "${DEST}.out";
	[ -f "${DEST}" ]
	# Run bibtex if necessary; latex will pick up the new information on the 
	# next run, and on the third run will properly resolve \cite commands.
	if grep -q "Warning: Citation .* on page .* undefined" "${DEST}.out"; then \
		bibtex $$( basename "${SOURCE}" .tex ) || rm -f "${DEST}"; \
	fi
	[ -f "${DEST}" ]

%.dvi: %.tex
	make build PROGRAM="latex" SOURCE="$<" DEST="$@"

%.pdf: %.tex
	make build PROGRAM="pdflatex" SOURCE="$<" DEST="$@"

%.bbl: %-bibliography.bib
	bibtex $$( basename "$@" .bbl )
	touch ran_bibtex

run_makeindex:
	set -e; \
	touch "${INPUT}.old"; \
	if ! cmp -s "${INPUT}" "${INPUT}.old"; then \
		makeindex -s "${STYLE}" -t "${LOG}" -o "${OUTPUT}" "${INPUT}"; \
		cp "${INPUT}" "${INPUT}.old"; \
		touch ran_makeindex; \
	fi
	echo; echo; echo;

# Why does build need to .PHONY when build_loop and build_run don't?
.PHONY: build
build:
	make build_loop PROGRAM="${PROGRAM}" SOURCE="${SOURCE}" DEST="${DEST}"
	cat "${DEST}.out"
	grep Overfull "${DEST}.out" || true
	grep "LaTeX Warning: " "${DEST}.out" || true
	BASE=$$( basename "${SOURCE}" .tex ); \
	grep ^Warning "$$BASE.blg" || true; \
	grep '!!' "$$BASE.glg" "$$BASE.alg" || true;
	# Finally done.
	chktex -I0 -q "${SOURCE}"

build_run:
	make run_latex PROGRAM="${PROGRAM}" SOURCE="${SOURCE}" DEST="${DEST}"
	# Rebuild the glossary; see foo.glg for errors
	# Rebuild the acronym list; see foo.alg for errors
	# Sometimes glossary produces an empty foo.glo, though I cannot figure out why.
	# The source files change between different runs; it seems that including
	# the output files causes the source files to change on the next latex run.
	# I haven't investigated much further, I don't really care.
	BASE=$$( basename "${SOURCE}" .tex ); \
	make run_makeindex STYLE="$$BASE.ist" LOG="$$BASE.glg" OUTPUT="$$BASE.gls" INPUT="$$BASE.glo"; \
	make run_makeindex STYLE="$$BASE.ist" LOG="$$BASE.alg" OUTPUT="$$BASE.acn" INPUT="$$BASE.acr"
	# The next run will include the new glossary and acronyms if they've changed.

build_loop:
	# Run latex at least three times:
	# 1 \cite commands populate foo.aux; bibtex will populate foo.bbl
	#   glossary and acronym files are written, and postprocessed
	# 2 latex reads foo.bbl, updates foo.aux
	#   glossary and acronym files are now included; more \cite commands are 
	#   added to foo.aux; bibtex reads foo.aux again and updates foo.bbl
	# 3 latex can now properly deal with the first set of \cite commands; it 
	#   reads foo.bbl again, updating foo.aux
	# 4 latex now resolves \cite commands from the glossary and acronyms, 
	#   possibly causing labels to change; in a more complicated document 
	#   this might even cause new entries in the glossary and acronyms, 
	#   requiring a rebuild of those, possibly causing new bibliography 
	#   entries, . . .
	# Other reasons to run it:
	# 5 table lengths in the acronym/glossary pages may have changed
	# 6 hyperref may need to add stuff (not sure what)
	# So this loop runs four times, and may need to run more times in future
	# (e.g. if I added an index).
	make build_run PROGRAM="${PROGRAM}" SOURCE="${SOURCE}" DEST="${DEST}";
	echo; echo; echo;
	for i in $$( seq 1 4 ); do \
		echo "iteration $$i starting"; \
		make $$( echo "$$SOURCE" | sed -e 's/tex$$/bbl/' ); \
		if [ -e ran_bibtex ]; then \
			echo "ran_bibtex exists, running latex again"; \
			make build_run PROGRAM="${PROGRAM}" SOURCE="${SOURCE}" DEST="${DEST}"; \
			rm -f ran_bibtex; \
			echo; echo; echo; \
		fi; \
		if [ -e ran_makeindex ]; then \
			echo "ran_makeindex exists, running latex again"; \
			make build_run PROGRAM="${PROGRAM}" SOURCE="${SOURCE}" DEST="${DEST}"; \
			rm -f ran_makeindex; \
			echo; echo; echo; \
		fi; \
		if grep -q -f latex-warnings "${DEST}.out"; then \
			echo "warnings found, running latex again"; \
			make build_run PROGRAM="${PROGRAM}" SOURCE="${SOURCE}" DEST="${DEST}"; \
			echo; echo; echo; \
		fi; \
	done

# 'make logparser.deps' correctly builds all dependencies, without running
# latex, because latex is noisy and slow.
logparser.pdf: logparser.deps logparser-bibliography.bib logparser-bibliography-style.bst \
				logparser-acronyms.tex
logparser.dvi: logparser.deps logparser-bibliography.bib logparser-bibliography-style.bst \
				logparser-acronyms.tex
logparser.deps: \
				build/plot-cached-discarded.pdf								\
				build/plot-cached-discarded-factor.pdf						\
				build/plot-normal-shuffle-reverse.pdf						\
				build/plot-normal-shuffle-factor.pdf						\
				build/plot-normal-reverse-factor.pdf						\
				build/plot-normal-filesize-numlines-factor.pdf				\
				build/plot-normal-filesize-numlines.pdf						\
				build/plot-hits.pdf											\
				build/plot-hits-high.pdf									\
				build/plot-hits-middle.pdf									\
				build/plot-hits-low.pdf										\
				\
				build/plot-cached-discarded.ps								\
				build/plot-cached-discarded-factor.ps						\
				build/plot-normal-shuffle-reverse.ps						\
				build/plot-normal-shuffle-factor.ps							\
				build/plot-normal-reverse-factor.ps							\
				build/plot-normal-filesize-numlines-factor.ps				\
				build/plot-normal-filesize-numlines.ps						\
				build/plot-hits.ps											\
				build/plot-hits-high.ps										\
				build/plot-hits-middle.ps									\
				build/plot-hits-low.ps										\
				\
				build/stats-cached-discarded-include-for-graph.tex			\
				build/stats-normal-filesize-line-count-include.tex			\
				build/stats-normal-shuffle-reverse-include.tex				\
				build/restriction-table-include.tex							\
				\
				build/logparser-flow-chart-part-1.pdf						\
				build/logparser-flow-chart-part-1.ps						\
				build/logparser-flow-chart-part-2.pdf						\
				build/logparser-flow-chart-part-2.ps
	touch "$@"

build/logparser-flow-chart-%.pdf: logparser-flow-chart-%.dot
	dot -o "$@" -Tpdf -x "$<"

build/logparser-flow-chart-%.ps: logparser-flow-chart-%.dot
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

build/plot-%.ps: graphs/plot-%.gpi
	cd graphs && gnuplot "../$<"

build/plot-%.pdf: graphs/plot-%-pdf.gpi
	cd graphs && gnuplot "../$<"

# Stop make deleting the intermediate gnuplot file, because there's no point
# in recreating it each time make runs.
.PRECIOUS: graphs/plot-%-pdf.gpi
graphs/plot-%-pdf.gpi: graphs/plot-%.gpi
	sed -e 's/ps/pdf/g' "$<" > "$@" || rm -f "$@"

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

build/restriction-table-include.tex:
	perl mk-restriction-summary-table > "$@" || (rm -f "$@"; false)

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
	rm -f *.old

veryclean: clean
	rm -f build/*

check:
	chktex -I0 -q logparser.tex

# List all acronyms not followed by {}, for visual inspection.
check-acronyms:
	sed -n -e '/newacronym/!d; s/}.*//; s/.*{//; s/$$/[^{e]/; p;' logparser-acronyms.tex | grep -f - -n logparser.tex

.PHONY: todo
todo:
	grep -n -E 'TODO|XXX' *.tex *.bib || true

2up: logparser-2up.ps logparser-2up.pdf

logparser-2up.ps: logparser.ps
	psnup -2 "$<" "$@"

logparser-2up.pdf: logparser-2up.ps
	ps2pdf "$<" "$@"

xpdf: logparser.pdf
	xpdf "$<" &
