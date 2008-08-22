# Cause make to delete output files when a command fails.
.DELETE_ON_ERROR:
# NOTE: you need to run 'make clean' between running 'make foo.dvi' and 'make
# foo.pdf', otherwise latex will only be run once and it will get very confused.
all: sgai-2008.pdf sgai-2008.ps

logparser.pdf: logparser.deps logparser.pdf.deps logparser-*.tex \
		logparser-bibliography.bib logparser-bibliography-style.bst

%.pdf: %.tex
	make build PROGRAM="pdflatex" SOURCE="$<" DEST="$@" BASENAME=$$( basename "$<" .tex )

logparser.dvi: logparser.deps logparser.ps.deps logparser-*.tex \
		logparser-bibliography.bib logparser-bibliography-style.bst

sgai-2008.pdf: sgai-2008.deps sgai-2008.pdf.deps spmpsci.bst \
		logparser-bibliography.bib
sgai-2008.dvi: sgai-2008.deps sgai-2008.ps.deps spmpsci.bst \
		logparser-bibliography.bib

sgai-2008.deps:									\
			build/include-timing-run-duration.tex			\
			build/include-full-ruleset-vs-minimum-ruleset.tex
	touch "$@"

%.dvi: %.tex
	make build PROGRAM="latex"    SOURCE="$<" DEST="$@" BASENAME=$$( basename "$<" .tex )

# This isn't a wildcard rule because it screws up later postscript wildcard 
# rules.
logparser.ps: logparser.dvi
	dvips -o "$@" "$<"
sgai-2008.ps: sgai-2008.dvi
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
	if [ ! -f "${STYLE}" ]; then \
		exit; \
	fi; \
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
	make check

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
logparser.deps: \
		build/include-file-size-and-number-of-lines-vs-parsing-time.tex	\
		build/include-optimal-and-reverse-vs-shuffle.tex 		\
		build/include-cached-regexes-vs-discarded-regexes.tex		\
		build/include-restriction-summary-table.tex			\
		build/include-mails-received-table.tex				\
		build/include-full-ruleset-vs-minimum-ruleset.tex		\
		build/include-sample-sql-output.tex				\
		build/include-sample-sql-query.tex				\
		build/include-timing-run-duration.tex
	touch "$@"

# Additional dependencies are included from Makefile.deps-ps and
# build/Makefile.graph-deps-pdf; which is generated from Makefile.deps-ps, to
# avoid duplication.  Make will automatically rebuild
# build/Makefile.graph-deps-pdf if it is missing or out of date.
include build/Makefile.deps-pdf
include Makefile.deps-ps
build/Makefile.deps-pdf: Makefile.deps-ps
	sed -e 's/\.ps/.pdf/g' "$<" > "$@"

# Graph dependencies are generated to avoid having to manually update
# them every time a graph changes.
include build/Makefile.graph-deps
include build/Makefile.graph-deps-ps
include build/Makefile.graph-deps-pdf
build/Makefile.graph-deps-pdf: build/Makefile.graph-deps-ps
	sed -e 's/\.ps/.pdf/g' "$<" > "$@"

build/Makefile.graph-deps-ps: graphs/*
	set -e;											\
	for file in $^; do									\
		output=$$( sed -n -e 's!^set output "../\(.*\)"!\1!p' "$$file" );		\
		if [ -n "$$output" ]; then							\
			sed -n -e 's!^.*"../\([^"]\+\)" using.*$$!'"$$output"': \1!p' "$$file";	\
		fi;										\
	done > "$@"

build/Makefile.graph-deps: graphs/*
	set -e;												\
	for file in $^; do										\
		sed -n -e 's!^load "\(.*\)"$$!'"$$file"': graphs/\1\n\ttouch '"$$file"'!p' "$$file";	\
		sed -n -e 's!^load "\(.*\)-ps.gpi"$$!'"$$file"': graphs/\1-pdf.gpi!p' "$$file";		\
	done > "$@"

# Flowchart
build/logparser-flow-chart-%.pdf: logparser-flow-chart-%.dot
	dot -o "$@" -Tpdf -x "$<"

build/logparser-flow-chart-%.ps: logparser-flow-chart-%.dot
	dot -o "$@" -Tps -x "$<"

# Graphs
build/graph-%.ps: graphs/plot-%.gpi
	cd graphs && gnuplot "../$<"

build/graph-%.pdf: build/plot-%-pdf.gpi
	cd build && gnuplot "../$<"

# Stop make deleting the intermediate gnuplot file, because there's no point
# in recreating it each time make runs.
.PRECIOUS: build/plot-%-pdf.gpi
build/plot-%-pdf.gpi: graphs/plot-%.gpi
	sed -e '/^load/s,","../graphs/,' -e 's/ps/pdf/g' "$<" > "$@"

build/results-%: results/results-%
	perl ../stats/parse-stats "$<" > "$@"

build/results--skip_inserting_results--cache_compiled_regexes--optimal_ordering--maximum_ruleset--comment-stripped: build/results--skip_inserting_results--cache_compiled_regexes--optimal_ordering--maximum_ruleset
	sed -e '/^#/d' "$<" > "$@"

# Factored stats for graphs.
build/stats-input-size-vs-parsing-time: build/results--skip_inserting_results--cache_compiled_regexes--optimal_ordering--maximum_ruleset--comment-stripped wc.txt file-sizes.txt
	paste -d ' ' $^ | awk 'BEGIN { print "# line-count file-size"; }; {print ($$3 * 10 * 1000 / $$8), " ", ($$3 * 1000 * 1000 / $$11) }' > "$@"

build/stats-cached-regexes-vs-discarded-regexes: build/results--skip_inserting_results--cache_compiled_regexes--optimal_ordering--maximum_ruleset build/results--skip_inserting_results--discard_compiled_regexes--optimal_ordering--maximum_ruleset
	paste -d ' ' $^ | awk '$$1 != "#" {print ($$9 * 100 / $$3) - 100 }' > "$@"

build/stats-optimal-and-reverse-vs-shuffle: build/results--skip_inserting_results--cache_compiled_regexes--optimal_ordering--maximum_ruleset build/results--skip_inserting_results--cache_compiled_regexes--shuffle_ordering--maximum_ruleset build/results--skip_inserting_results--cache_compiled_regexes--reverse_ordering--maximum_ruleset
	paste -d ' ' $^ | awk 'BEGIN { print "# optimal/shuffle reverse/shuffle"; } $$1 != "#" {print ($$3 * 100 / $$9), " ", ($$15 * 100 / $$9) }' > "$@"

# Hits per rule.
build/stats-hits: db.full-run.sq3
	sqlite3 -separator ' ' "$<" "select hits_total from rules order by hits_total;" > "$@.tmp"
	nl "$@.tmp" > "$@"
	rm -f "$@.tmp"

# Stats for cached regexes vs discarded regexs: all logs, logs 22,62-68, all other logs.
build/stats-cached-regexes-vs-discarded-regexes-stddev: build/stats-cached-regexes-vs-discarded-regexes
	perl ../stats/stddev "$<" > "$@"
	echo "Row: All logs" >> "$@"

build/stats-cached-regexes-vs-discarded-regexes-logs-22-62-68-stddev: build/stats-cached-regexes-vs-discarded-regexes
	sed -e '1,21d; 23,61d; 69,$$d;' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Logs 22 and 62--68" >> "$@"

build/stats-cached-regexes-vs-discarded-regexes-other-logs-stddev: build/stats-cached-regexes-vs-discarded-regexes
	sed -e '22d; 62,68d;' "$<" | perl ../stats/stddev > "$@"
	echo "Row: All logs except 22 and 62--68" >> "$@"

build/include-cached-regexes-vs-discarded-regexes.tex: build/stats-cached-regexes-vs-discarded-regexes-stddev build/stats-cached-regexes-vs-discarded-regexes-logs-22-62-68-stddev build/stats-cached-regexes-vs-discarded-regexes-other-logs-stddev
	perl mk-stats-cached-discarded-include $^ > "$@"

# File size and number of lines ratios: stddev, mean, etc.
build/stats-file-size-vs-parsing-time-stddev: build/stats-input-size-vs-parsing-time
	awk '!/#/ {print $$2}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: File size vs. parsing time" >> "$@"

build/stats-file-size-vs-parsing-time-logs-22-62-68-stddev: build/stats-input-size-vs-parsing-time
	awk '!/#/ {print $$2}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: File size vs. parsing time (logs 22, 62--68)" >> "$@"

build/stats-file-size-vs-parsing-time-other-logs-stddev: build/stats-input-size-vs-parsing-time
	awk '!/#/ {print $$2}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: File size vs. parsing time (all other logs)" >> "$@"

build/stats-number-of-lines-vs-parsing-time-stddev: build/stats-input-size-vs-parsing-time
	awk '!/#/ {print $$1}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Number of lines vs. parsing time" >> "$@"

build/stats-number-of-lines-vs-parsing-time-logs-22-62-68-stddev: build/stats-input-size-vs-parsing-time
	awk '!/#/ {print $$1}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: Number of lines vs. parsing time (logs 22, 62--68)" >> "$@"

build/stats-number-of-lines-vs-parsing-time-other-logs-stddev: build/stats-input-size-vs-parsing-time
	awk '!/#/ {print $$1}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: Number of lines vs. parsing time (all other logs)" >> "$@"

build/include-file-size-and-number-of-lines-vs-parsing-time.tex: 			\
		build/stats-file-size-vs-parsing-time-stddev				\
		build/stats-file-size-vs-parsing-time-logs-22-62-68-stddev		\
		build/stats-file-size-vs-parsing-time-other-logs-stddev 		\
		build/stats-number-of-lines-vs-parsing-time-stddev			\
		build/stats-number-of-lines-vs-parsing-time-logs-22-62-68-stddev	\
		build/stats-number-of-lines-vs-parsing-time-other-logs-stddev
	perl mk-stats-cached-discarded-include $^ | sed -e 's/\\%//g' > "$@"

# Optimal/shuffle/reverse ratios: stddev, mean, etc.
build/stats-optimal-vs-shuffle-stddev: build/stats-optimal-and-reverse-vs-shuffle
	awk '!/#/ {print $$1}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Optimal (all logs)" >> "$@"

build/stats-optimal-vs-shuffle-logs-22-62-68-stddev: build/stats-optimal-and-reverse-vs-shuffle
	awk '!/#/ {print $$1}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: Optimal (logs 22, 62--68)" >> "$@"

build/stats-optimal-vs-shuffle-other-logs-stddev: build/stats-optimal-and-reverse-vs-shuffle
	awk '!/#/ {print $$1}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: Optimal (all other logs)" >> "$@"

build/stats-reverse-vs-shuffle-stddev: build/stats-optimal-and-reverse-vs-shuffle
	awk '!/#/ {print $$2}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Reverse (all logs)" >> "$@"

build/stats-reverse-vs-shuffle-logs-22-62-68-stddev: build/stats-optimal-and-reverse-vs-shuffle
	awk '!/#/ {print $$2}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: Reverse (logs 22, 62--68)" >> "$@"

build/stats-reverse-vs-shuffle-other-logs-stddev: build/stats-optimal-and-reverse-vs-shuffle
	awk '!/#/ {print $$2}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: Reverse (all other logs)" >> "$@"

build/include-optimal-and-reverse-vs-shuffle.tex: 			\
		build/stats-optimal-vs-shuffle-stddev			\
		build/stats-optimal-vs-shuffle-logs-22-62-68-stddev	\
		build/stats-optimal-vs-shuffle-other-logs-stddev		\
		build/stats-reverse-vs-shuffle-stddev			\
		build/stats-reverse-vs-shuffle-logs-22-62-68-stddev	\
		build/stats-reverse-vs-shuffle-other-logs-stddev	\
		
	perl mk-stats-cached-discarded-include $^ > "$@" || (rm -f "$@"; false)

build/include-restriction-summary-table.tex: db.full-run.sq3
	perl mk-restriction-summary-table > "$@"

# Number of mails received per day
build/stats-mails-received-stddev: mails-received.txt
	awk '{print $$2}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: All days" >> "$@"

build/stats-mails-received-weekends-stddev: mails-received.txt
	awk '((NR % 7) == 2) || ((NR % 7) == 3) { print $$2 }' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Weekend days" >> "$@"

build/stats-mails-received-weekdays-stddev: mails-received.txt
	awk '((NR % 7) != 2) && ((NR % 7) != 3) { print $$2 }' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Week days" >> "$@"

build/include-mails-received-table.tex:				\
		build/stats-mails-received-stddev		\
		build/stats-mails-received-weekends-stddev	\
		build/stats-mails-received-weekdays-stddev
	perl mk-stats-cached-discarded-include $^ > "$@"
	sed -i -e 's/\\%//g' "$@"

# Distribution of actions to rules.
build/stats-action-distribution: db.full-run.sq3
	sqlite3 -separator ' ' "$<" 'SELECT action, count(action) FROM rules GROUP BY action ORDER BY count(action);' > "$@.tmp"
	nl "$@.tmp" > "$@"
	rm -f "$@.tmp"
	# Turn everything to lowercase.
	sed -i -e 's/^\(.*\)$$/\L\1\E/' "$@"

# Minimum ruleset vs maximum ruleset.
build/include-full-ruleset-vs-minimum-ruleset.tex: build/stats-optimal-full-ruleset-vs-minimum-ruleset
	awk 'BEGIN { sum = 0; } { sum += $$2; } END { printf "%.3g\\%%%%\n", sum / NR }' "$<" > "$@" || (rm -f "$@"; false)

build/stats-optimal-full-ruleset-vs-minimum-ruleset: build/results--skip_inserting_results--cache_compiled_regexes--optimal_ordering--maximum_ruleset build/results--skip_inserting_results--cache_compiled_regexes--optimal_ordering--minimum_ruleset
	INPUT="$^" OUTPUT="$@" make full-ruleset-vs-minimum-ruleset

build/stats-reverse-full-ruleset-vs-minimum-ruleset: build/results--skip_inserting_results--cache_compiled_regexes--reverse_ordering--maximum_ruleset build/results--skip_inserting_results--cache_compiled_regexes--reverse_ordering--minimum_ruleset
	INPUT="$^" OUTPUT="$@" make full-ruleset-vs-minimum-ruleset

build/stats-shuffle-full-ruleset-vs-minimum-ruleset: build/results--skip_inserting_results--cache_compiled_regexes--shuffle_ordering--maximum_ruleset build/results--skip_inserting_results--cache_compiled_regexes--shuffle_ordering--minimum_ruleset
	INPUT="$^" OUTPUT="$@" make full-ruleset-vs-minimum-ruleset

full-ruleset-vs-minimum-ruleset:
	# There deliberately aren't any quotes around INPUT because it will have 
	# multiple file names
	paste -d ' ' ${INPUT} | awk '!/^#/ { print $$1, (($$3 -$$9) * 100 / $$9)}' > "${OUTPUT}"

# Duration of the full run parsing all 93 log files.
build/include-timing-run-duration.tex: results/stats-full-run/timing
	awk -F': ' '/^Total time:/ { printf "%d hours, %d minutes and %.3f seconds%\n", $$3 / (60 * 60), ($$3 / 60) % 60, $$3 % 60 }' "$<" > "$@" || (rm -f "$@"; false)

# Sample output from an SQL query.
build/include-sample-sql-output.tex: db.full-run.sq3 generate-sample-sql-output.sql
	sqlite3.6.0 -separator ' & ' -bail "$<" < "generate-sample-sql-output.sql" > "$@" || ( rm -f "$@"; false )
	sed -i -e 's/, [^ ]\+ / /' -e 's/\(\.[0-9]\{3\}\)[0-9]*%$$/\1%/' -e 's/$$/ \\\\/' -e 's/_/\\_/g' -e 's/%/\\%/g' "$@"

# The sample SQL query itself.
build/include-sample-sql-query.tex: generate-sample-sql-output.sql
	( echo '\begin{verbatim}'; cat "$<"; echo '\end{verbatim}' ) > "$@"

# Cleanup.
clean:
	rm -f	*.acn *.acr *.alg *.aux *.bbl *.blg *.cbk *.cit *.deps *.dvi \
		*.glg *.glo *.gls *.idx *.ist *.lof *.log *.lot *.old *.out \
		*.pdf *.ps *.toc *.cite

realclean: veryclean
veryclean: clean
	rm -f	build/stats-* build/include-* build/graph-*	\
		build/logparser-flow-chart* build/Makefile.*	\
		build/plot-*

check:
	chktex -I0 -q *.tex
	chktex -q --nowarn 1 --nowarn 15 --nowarn 17 *.bbl

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

xpdf: all
	xpdf logparser.pdf &
	xpdf sgai-2008.pdf &

spellcheck:
	for file in *.tex; do aspell -t -c "$$file"; done
