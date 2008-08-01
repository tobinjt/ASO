# NOTE: you need to run 'make clean' between running 'make foo.dvi' and 'make
# foo.pdf', otherwise latex will only be run once and it will get very confused.
all: logparser.pdf

logparser.pdf: logparser.deps logparser-*.tex \
		logparser-bibliography.bib logparser-bibliography-style.bst

%.pdf: %.tex
	make build PROGRAM="pdflatex" SOURCE="$<" DEST="$@" BASENAME=$$( basename "$<" .tex )

logparser.dvi: logparser.deps logparser-*.tex \
		logparser-bibliography.bib logparser-bibliography-style.bst

%.dvi: %.tex
	make build PROGRAM="latex"    SOURCE="$<" DEST="$@" BASENAME=$$( basename "$<" .tex )

# This isn't a wildcard rule because it screws up later postscript wildcard 
# rules.
logparser.ps: logparser.dvi
	dvips -o "$@" "$<"

%.bbl: %-bibliography.bib
	bibtex $$( basename "$@" .bbl )
	touch build/ran_bibtex

run_latex:
	("${PROGRAM}" -interaction=nonstopmode "${SOURCE}" || rm -f "${DEST}") | tee "${DEST}.out";
	[ -f "${DEST}" ]
	# Run bibtex if necessary; latex will pick up the new information on the
	# next run, and on the third run will properly resolve \cite commands.
	if grep -q "Warning: Citation .* on page .* undefined" "${DEST}.out"; then \
		bibtex "${BASENAME}" || rm -f "${DEST}" "${BASENAME}.bbl"; \
		touch build/ran_bibtex; \
	fi
	touch "${BASENAME}.cite.old"
	grep '^\\citation' "${BASENAME}.aux" > "${BASENAME}.cite"
	if ! cmp -s "${BASENAME}.cite.old" "${BASENAME}.cite"; then \
		bibtex "${BASENAME}" || rm -f "${DEST}" "${BASENAME}.bbl"; \
		touch build/ran_bibtex; \
	fi
	cp "${BASENAME}.cite" "${BASENAME}.cite.old"
	[ -f "${DEST}" ]
	touch "${BASENAME}.aux.old";
	if [ -s "${BASENAME}.aux.old" ]; then \
		diff -u "${BASENAME}.aux.old" "${BASENAME}.aux" || true; \
	fi;
	cp "${BASENAME}.aux" "${BASENAME}.aux.old"

run_makeindex:
	set -e; \
	touch "${INPUT}.old"; \
	if ! cmp -s "${INPUT}" "${INPUT}.old"; then \
		makeindex -s "${STYLE}" -t "${LOG}" -o "${OUTPUT}" "${INPUT}"; \
		cp "${INPUT}" "${INPUT}.old"; \
		touch build/ran_makeindex; \
	fi

# build is a directory so it needs to be marked as PHONY.
.PHONY: build
build:
	make build_loop
	make check-contractions
	grep Overfull "${DEST}.out" || true
	grep -A 1 "LaTeX Warning: " "${DEST}.out" || true
	sed -n -e '/^Package .* Warning/,/^$$/p' "${DEST}.out"
	grep ^Warning *.blg || true;
	grep '!!' *.glg *.alg || true;
	# Finally done.
	chktex -I0 -q *.tex

build_run:
	make run_latex
	# Rebuild the glossary; see foo.glg for errors
	# Rebuild the acronym list; see foo.alg for errors
	# Sometimes glossary produces an empty foo.glo, though I cannot figure out why.
	# The source files change between different runs; it seems that including
	# the output files causes the source files to change on the next latex run.
	# I haven't investigated much further, I don't really care.
	make run_makeindex STYLE="${BASENAME}.ist" LOG="${BASENAME}.glg" OUTPUT="${BASENAME}.gls" INPUT="${BASENAME}.glo"
	make run_makeindex STYLE="${BASENAME}.ist" LOG="${BASENAME}.alg" OUTPUT="${BASENAME}.acn" INPUT="${BASENAME}.acr"
	# The next time latex is run is will include the new glossary and acronyms 
	# if they've changed.

build_loop:
	# Run latex at least four times when starting from scratch:
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
	make build_run
	set -e; \
	for i in $$( seq 1 4 ); do \
		echo "iteration $$i starting"; \
		make "${BASENAME}.bbl"; \
		if [ -e build/ran_bibtex ]; then \
			echo "ran_bibtex exists, running latex again"; \
			make build_run; \
			rm -f build/ran_bibtex; \
		fi; \
		if [ -e build/ran_makeindex ]; then \
			echo "ran_makeindex exists, running latex again"; \
			make build_run; \
			rm -f build/ran_makeindex; \
		fi; \
		if grep -q -f latex-warnings "${DEST}.out"; then \
			echo "warnings found, running latex again"; \
			make build_run; \
		fi; \
	done

# 'make logparser.deps' correctly builds all dependencies, without running
# latex, because latex is noisy and slow.
logparser.deps: build/stats-cached-discarded-include-for-graph.tex	\
		build/stats-normal-filesize-line-count-include.tex	\
		build/stats-normal-shuffle-reverse-include.tex		\
		build/restriction-table-include.tex			\
		build/logparser-flow-chart-part-1.pdf			\
		build/logparser-flow-chart-part-1.ps			\
		build/logparser-flow-chart-part-2.pdf			\
		build/logparser-flow-chart-part-2.ps			\
		build/plot-mails-received.ps				\
		build/plot-mails-received.pdf				\
		build/mails-received-include-for-graph.tex		\
		build/full-ruleset-vs-minimum-ruleset-include.tex	\
		build/timing-run-include.tex				\
		build/sample-sql-output-include.tex
	touch "$@"

# Additional logparser.deps dependencies are included from Makefile.deps-pdf 
# and -ps; -ps is generated from -pdf, to avoid duplication.  Make will 
# automatically rebuild -ps if it is missing or out of date.
include Makefile.deps-pdf
include Makefile.deps-ps
Makefile.deps-ps: Makefile.deps-pdf
	sed -e 's/\.pdf/.ps/' "$<" > "$@"

build/logparser-flow-chart-%.pdf: logparser-flow-chart-%.dot
	dot -o "$@" -Tpdf -x "$<"

build/logparser-flow-chart-%.ps: logparser-flow-chart-%.dot
	dot -o "$@" -Tps -x "$<"

build/plot-%.ps: graphs/plot-%.gpi
	cd graphs && gnuplot "../$<" || (rm -f "../$@"; false)

build/plot-%.pdf: graphs/plot-%-pdf.gpi
	cd graphs && gnuplot "../$<" || (rm -f "../$@"; false)

# Stop make deleting the intermediate gnuplot file, because there's no point
# in recreating it each time make runs.
.PRECIOUS: graphs/plot-%-pdf.gpi
graphs/plot-%-pdf.gpi: graphs/plot-%.gpi
	sed -e 's/ps/pdf/g' "$<" > "$@"

build/stats-normal-stripped.txt: build/stats-normal.txt
	sed -e '/^#/d' "$<" > "$@"

# Factored stats for graphs.
build/stats-normal-filesize-numlines-factor.txt: build/stats-normal-stripped.txt wc.txt file-sizes.txt
	paste -d ' ' $^ | awk 'BEGIN { print "# line-count file-size"; }; $$1 != "#" {print ($$3 * 10 * 1000 / $$8), " ", ($$3 * 1000 * 1000 / $$11) }' > "$@"

build/stats-cached-discarded-factor.txt: build/stats-cached.txt build/stats-discarded.txt
	paste -d ' ' $^ | awk '$$1 != "#" {print ($$9 * 100 / $$3) - 100 }' > "$@"

build/stats-normal-shuffle-reverse-factor.txt: build/stats-normal.txt build/stats-shuffle.txt build/stats-reverse.txt
	paste -d ' ' $^ | awk '$$1 != "#" {print ($$3 * 100 / $$9), " ", ($$15 * 100 / $$9) }' > "$@"

# Log 22 stats
stats-log22-distribution-by-rule.txt:
	sqlite3 -separator ' ' ../sql/db.sq3 "select hits, program from rules where hits > 0 order by hits;" | nl > "$@"

stats-log22-rule-count-by-program.txt:
	sqlite3 -separator ' ' ../sql/db.sq3 "select sum(hits), count(*), program from rules group by program;" | awk '$$1 > 0 { print }' | sed -e 's,postfix/,,' | nl > "$@"

stats-hits.txt: db.full-run.sq3
	sqlite3 -separator ' ' "$<" "select hits_total from rules order by hits_total;" > "$@.tmp"
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
	echo "Row: File size vs. parsing time" >> "$@"

build/stats-normal-filesize-stddev-22_62-68.txt: build/stats-normal-filesize-numlines-factor.txt
	awk '!/#/ {print $$2}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: File size vs. parsing time (logs 22, 62--68)" >> "$@"

build/stats-normal-filesize-stddev-other.txt: build/stats-normal-filesize-numlines-factor.txt
	awk '!/#/ {print $$2}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: File size vs. parsing time (all other logs)" >> "$@"

build/stats-normal-line-count-stddev.txt: build/stats-normal-filesize-numlines-factor.txt
	awk '!/#/ {print $$1}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Number of lines vs. parsing time" >> "$@"

build/stats-normal-line-count-stddev-22_62-68.txt: build/stats-normal-filesize-numlines-factor.txt
	awk '!/#/ {print $$1}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: Number of lines vs. parsing time (logs 22, 62--68)" >> "$@"

build/stats-normal-line-count-stddev-other.txt: build/stats-normal-filesize-numlines-factor.txt
	awk '!/#/ {print $$1}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: Number of lines vs. parsing time (all other logs)" >> "$@"

build/stats-normal-filesize-line-count-include.tex: 			\
		build/stats-normal-filesize-stddev.txt			\
		build/stats-normal-filesize-stddev-22_62-68.txt		\
		build/stats-normal-filesize-stddev-other.txt 		\
		build/stats-normal-line-count-stddev.txt		\
		build/stats-normal-line-count-stddev-22_62-68.txt	\
		build/stats-normal-line-count-stddev-other.txt
	perl mk-stats-cached-discarded-include $^ | sed -e 's/\\%//g' > "$@" || (rm -f "$@"; false)

# Normal/shuffle/reverse ratios: stddev, mean, etc.
build/stats-normal-shuffle-stddev.txt: build/stats-normal-shuffle-reverse-factor.txt
	awk '!/#/ {print $$1}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Normal (all logs)" >> "$@"

build/stats-normal-shuffle-stddev-22_62-68.txt: build/stats-normal-shuffle-reverse-factor.txt
	awk '!/#/ {print $$1}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: Normal (logs 22, 62--68)" >> "$@"

build/stats-normal-shuffle-stddev-other.txt: build/stats-normal-shuffle-reverse-factor.txt
	awk '!/#/ {print $$1}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: Normal (all other logs)" >> "$@"

build/stats-normal-reverse-stddev.txt: build/stats-normal-shuffle-reverse-factor.txt
	awk '!/#/ {print $$2}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Reverse (all logs)" >> "$@"

build/stats-normal-reverse-stddev-22_62-68.txt: build/stats-normal-shuffle-reverse-factor.txt
	awk '!/#/ {print $$2}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: Reverse (logs 22, 62--68)" >> "$@"

build/stats-normal-reverse-stddev-other.txt: build/stats-normal-shuffle-reverse-factor.txt
	awk '!/#/ {print $$2}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: Reverse (all other logs)" >> "$@"

build/stats-normal-shuffle-reverse-include.tex: 		\
		build/stats-normal-shuffle-stddev.txt		\
		build/stats-normal-shuffle-stddev-22_62-68.txt	\
		build/stats-normal-shuffle-stddev-other.txt 	\
		build/stats-normal-reverse-stddev.txt		\
		build/stats-normal-reverse-stddev-22_62-68.txt	\
		build/stats-normal-reverse-stddev-other.txt
	perl mk-stats-cached-discarded-include $^ > "$@" || (rm -f "$@"; false)

build/restriction-table-include.tex: db.full-run.sq3
	perl mk-restriction-summary-table > "$@" || (rm -f "$@"; false)

# Number of mails received per day
build/mails-received-stats.txt: mails-received.txt
	awk '{print $$2}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: All days" >> "$@"

build/mails-received-weekends-stats.txt: mails-received.txt
	awk '((NR % 7) == 2) || ((NR % 7) == 3) { print $$2 }' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Weekend days" >> "$@"

build/mails-received-weekdays-stats.txt: mails-received.txt
	awk '((NR % 7) != 2) && ((NR % 7) != 3) { print $$2 }' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Week days" >> "$@"

build/mails-received-include-for-graph.tex: 		\
		build/mails-received-stats.txt		\
		build/mails-received-weekdays-stats.txt	\
		build/mails-received-weekends-stats.txt
	perl mk-stats-cached-discarded-include $^ > "$@"
	sed -i -e 's/\\%//g' "$@" || (rm -f "$@"; false)

build/action-distribution.txt: db.full-run.sq3
	sqlite3 -separator ' ' "$<" 'select action, count(action) from rules group by action order by count(action);' > "$@.tmp"
	nl "$@.tmp" > "$@" || (rm -f "$@"; false)

build/full-ruleset-vs-minimum-ruleset-include.tex: build/stats-normal-full-ruleset-vs-minimum-ruleset.txt
	awk 'BEGIN { sum = 0; } { sum += $$2; } END { printf "%.3g\\%%%%\n", sum / NR }' "$<" > "$@" || (rm -f "$@"; false)

build/stats-normal-full-ruleset-vs-minimum-ruleset.txt: build/stats-normal.txt build/stats-normal-minimum-ruleset.txt
	INPUT="$^" OUTPUT="$@" make full-ruleset-vs-minimum-ruleset

build/stats-reverse-full-ruleset-vs-minimum-ruleset.txt: build/stats-reverse.txt build/stats-reverse-minimum-ruleset.txt
	INPUT="$^" OUTPUT="$@" make full-ruleset-vs-minimum-ruleset

build/stats-shuffle-full-ruleset-vs-minimum-ruleset.txt: build/stats-shuffle.txt build/stats-shuffle-minimum-ruleset.txt
	INPUT="$^" OUTPUT="$@" make full-ruleset-vs-minimum-ruleset

full-ruleset-vs-minimum-ruleset:
	# There deliberately aren't any quotes around INPUT because it will have 
	# multiple file names
	paste -d ' ' ${INPUT} | awk '!/^#/ { print $$1, (($$3 -$$9) * 100 / $$9)}' > "${OUTPUT}"

build/timing-run-include.tex: stats-full-run/timing
	awk -F': ' '/^Total time:/ { printf "%d hours, %d minutes, %.3f seconds%\n", $$3 / (60 * 60), ($$3 / 60) % 60, $$3 % 60 }' "$<" > "$@" || (rm -f "$@"; false)

build/sample-sql-output-include.tex: db.full-run.sq3 generate-sample-sql-output.sql
	sqlite3.6.0 -separator ' & ' -bail "$<" < "generate-sample-sql-output.sql" > "$@" || ( rm -f "$@"; false )
	sed -i -e 's/, [^ ]\+ / /' -e 's/\(\.[0-9]\{3\}\)[0-9]*%$$/\1%/' -e 's/$$/ \\\\/' -e 's/_/\\_/g' -e 's/%/\\%/g' "$@"

# Build stats from the directory created by gen-stats.
# NOTE: this won't happen automatically when the directory's contents change;
# you'll need to run make realclean or delete results manually.
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

build/stats-normal-minimum-ruleset.txt: stats-normal-minimum-ruleset
	DIR="$<" FILE="$@" make parse-stats

build/stats-reverse-minimum-ruleset.txt: stats-reverse-minimum-ruleset
	DIR="$<" FILE="$@" make parse-stats

build/stats-shuffle-minimum-ruleset.txt: stats-shuffle-minimum-ruleset
	DIR="$<" FILE="$@" make parse-stats

parse-stats:
	perl ../stats/parse-stats "${DIR}" > "${FILE}" || (rm -f "${FILE}"; false)

# Cleanup.
clean:
	rm -f	*.acn *.acr *.alg *.aux *.bbl *.blg *.cbk *.cit *.deps *.dvi \
		*.glg *.glo *.gls *.idx *.ist *.lof *.log *.lot *.old *.out \
		*.pdf *.ps *.toc

realclean: veryclean
veryclean: clean
	rm -f build/*

check:
	chktex -I0 -q *.tex

# List all acronyms not followed by {}, for visual inspection.
check-acronyms:
	sed -n -e '/newacronym/!d; s/}.*//; s/.*{//; s/$$/[^{e]/; p;' logparser-acronyms.tex \
		| grep -f - -n $$(ls *.tex | grep -v ^logparser-acronyms.tex)

# Check for contractons like "don't".
check-contractions:
	ack '\w'\''(?![sS])\w' *.tex

todo:
	grep -n -E '[T]ODO|[X]XX' Makefile *.tex *.bib || true
	grep -n -E '[T]ODO|[X]XX' Makefile *.tex *.bib | wc

2up: logparser-2up.ps logparser-2up.pdf

logparser-2up.ps: logparser.ps
	psnup -2 "$<" "$@"

logparser-2up.pdf: logparser-2up.ps
	ps2pdf "$<" "$@"

xpdf: logparser.pdf
	xpdf "$<" &

spellcheck:
	for file in *.tex; do aspell -t -c "$$file"; done
