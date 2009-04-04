# Cause make to delete output files when a command fails.
.DELETE_ON_ERROR:
MAKEFLAGS += --no-print-directory
# NOTE: you need to run 'make clean' between running 'make foo.dvi' and 'make
# foo.pdf', otherwise latex will only be run once and it will get very confused.
all: logparser.pdf

logparser.pdf: logparser.deps logparser.pdf.deps logparser-*.tex \
		logparser-bibliography.tt2 bibtex.tt2

%.pdf: %.tex
	make build PROGRAM="pdflatex" SOURCE="$<" DEST="$@" BASENAME=$$( basename "$<" .tex )

logparser.dvi: logparser.deps logparser.ps.deps logparser-*.tex \
		logparser-bibliography.tt2 bibtex.tt2

sgai-2008-elsevier.pdf: sgai-2008.deps sgai-2008.pdf.deps elsarticle-num.bst \
		logparser-bibliography.tt2 bibtex.tt2
sgai-2008-elsevier.dvi: sgai-2008.deps sgai-2008.ps.deps elsarticle-num.bst \
		logparser-bibliography.tt2 bibtex.tt2

sgai-2008.pdf: sgai-2008.deps sgai-2008.pdf.deps spmpsci.bst \
		logparser-bibliography.tt2 bibtex.tt2
sgai-2008.dvi: sgai-2008.deps sgai-2008.ps.deps spmpsci.bst \
		logparser-bibliography.tt2 bibtex.tt2

sgai-2008.deps:									\
			build/include-timing-run-duration.tex			\
			build/include-full-ruleset-vs-minimum-ruleset.tex	\
			build/include-timing-run-throughput.tex			\
			build/include-median-throughput-log-lines.tex		\
			build/include-median-throughput-MB.tex			\
			build/include-optimal-ordering-parsing-time-reduction-logs-22-62-68.tex	\
			build/include-optimal-ordering-parsing-time-reduction-other-logs.tex	\
			build/include-top-ten-hits.tex
	touch "$@"

# 'make logparser.deps' correctly builds all dependencies, without running
# latex, because latex is noisy and slow.
logparser.deps: \
		build/include-file-size-and-number-of-log-lines-vs-parsing-time.tex	\
		build/include-optimal-and-reverse-vs-shuffle.tex 			\
		build/include-cached-regexes-vs-discarded-regexes.tex			\
		build/include-restriction-summary-table.tex				\
		build/include-mails-received-table.tex					\
		build/include-full-ruleset-vs-minimum-ruleset.tex			\
		build/include-sample-sql-output.tex					\
		build/include-sample-sql-query.tex					\
		build/include-timing-run-duration.tex					\
		build/include-timing-run-throughput.tex					\
		build/include-median-throughput-log-lines.tex				\
		build/include-median-throughput-MB.tex					\
		build/include-top-ten-hits.tex						\
		build/include-optimal-ordering-parsing-time-reduction-other-logs.tex	\
		build/include-optimal-ordering-parsing-time-reduction-logs-22-62-68.tex	\
		build/include-perfect-best-and-optimal-and-reverse-and-perfect-worst-vs-shuffle.tex	\
		build/include-per-file-action-invocation-numbers-table.tex
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
	# The output from the first sed command is piped through sort and uniq 
	# to remove duplicate commands that cause warnings from make.
	set -e;														\
	for file in $^; do												\
		sed -n -e 's!^load "\(.*\)"$$!'"$$file"': graphs/\1\n\ttouch '"$$file"'!p' "$$file" | sort | uniq;	\
		sed -n -e 's!^load "\(.*\)-ps.gpi"$$!'"$$file"': graphs/\1-pdf.gpi!p' "$$file";				\
	done > "$@"
	sed -i -e 's!graphs/../build/!build/!' "$@"


# This isn't a wildcard rule because it screws up later postscript wildcard 
# rules.
logparser.ps: logparser.dvi
	dvips -o "$@" "$<"
sgai-2008.ps: sgai-2008.dvi
	dvips -o "$@" "$<"

logparser.bbl: bibtex.tt2 logparser-bibliography.tt2 citations.tt2 
	ls -l bibtex.tt2 logparser-bibliography.tt2 citations.tt2 
	tpage --debug=3 bibtex.tt2 > logparser.bbl
	echo "Ran bibtex.tt2" >> build/run-latex-again

%.dvi: %.tex
	make build PROGRAM="latex"    SOURCE="$<" DEST="$@" BASENAME=$$( basename "$<" .tex )

run_latex:
	("${PROGRAM}" -interaction=nonstopmode "${SOURCE}" || rm -f "${DEST}") | tee "${DEST}.out";
	[ -f "${DEST}" ]
	# Run bibtex if necessary; latex will pick up the new information on the
	# next run, and on the third run will properly resolve \cite commands.
	touch "${BASENAME}.cite.old"
	grep '^\\citation' "${BASENAME}.aux" > "${BASENAME}.cite"
	rm -f build/run-bibtex
	perl -w -Mstrict -E 'my @citations; while (<>) { if (m/^\\citation\{(.*)\}/) { push @citations, split /,/, $$1; }} my %seen; map { $$seen{$$_}++; } @citations; my $$citations = join q{ = 1, }, map { qq{"$$_"}; } keys %seen; say qq([% citations = { ), $$citations, q( = 1 } -%]);' *.aux > "citations.tt2.new"
	set -e; \
	if [ ! -f citations.tt2 ]; then \
		touch citations.tt2; \
	fi; \
	if ! cmp -s citations.tt2 citations.tt2.new; then \
		echo "Rebuilt citations" >> build/run-bibtex; \
		mv -f citations.tt2.new citations.tt2; \
	else \
		rm -f citations.tt2.new; \
	fi; \
	if grep -q "Warning: Citation .* on page .* undefined" "${BASENAME}.log"; then \
		echo "Undefined citations" >> build/run-bibtex; \
	fi; \
	if ! cmp -s "${BASENAME}.cite.old" "${BASENAME}.cite"; then \
		echo "Citations have changed" >> build/run-bibtex; \
	fi; \
	if [ -e build/run-bibtex ]; then \
		echo "Running bibtex because:"; \
		cat build/run-bibtex; \
		rm -f "${BASENAME}.bbl"; \
		make "${BASENAME}.bbl"; \
		echo "Ran bibtex" >> build/run-latex-again; \
	fi
	cp "${BASENAME}.cite" "${BASENAME}.cite.old"
	[ -f "${DEST}" ]
	touch "${BASENAME}.aux.old";
	if [ -s "${BASENAME}.aux.old" ]; then \
		echo diff -u "${BASENAME}.aux.old" "${BASENAME}.aux" || true; \
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
		echo "Updated ${INPUT}" >> build/run-latex-again; \
	fi

# build is a directory so it needs to be marked as PHONY.
.PHONY: build
build:
	make build_loop
	# Finally done.
	make -s check

build_run:
	make run_latex
	# Rebuild the glossary; see foo.glg for errors
	# Rebuild the acronym list; see foo.alg for errors
	# Sometimes glossary produces an empty foo.glo, though I cannot figure out why.
	# The source files change between different runs; it seems that including
	# the output files causes the source files to change on the next latex run.
	# I haven't investigated much further, I don't really care.
	#makeglossaries `basename "${SOURCE}" .tex`
	set -e; \
	for line in `grep newglossary "${BASENAME}.aux"`; do \
		set -- `echo "$$line" | sed -e 's/\\\\@newglossary{.\+}{\(.\+\)}{\(.\+\)}{\(.\+\)}/\1 \2 \3/'`; \
		make run_makeindex STYLE="${BASENAME}.ist" LOG="${BASENAME}.$$1" OUTPUT="${BASENAME}.$$2" INPUT="${BASENAME}.$$3"; \
	done
	set -e; \
	for contents in toc lof lot; do \
		touch "${BASENAME}.$${contents}.old"; \
		if ! cmp -s "${BASENAME}.$${contents}.old" "${BASENAME}.$${contents}"; then \
			echo "Table of contents updated ($$contents)" >> build/run-latex-again; \
		fi; \
		cp "${BASENAME}.$${contents}" "${BASENAME}.$${contents}.old"; \
	done
	# The next time latex is run it will include the new glossary and acronyms 
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
	rm -f build/run-latex-again
	make build_run
	make "${BASENAME}.bbl"
	set -e; \
	for i in $$( seq 1 4 ); do \
		echo "iteration $$i starting"; \
		if grep -q -f latex-warnings "${BASENAME}.log"; then \
			echo "warnings found" >> build/run-latex-again; \
		fi; \
		if [ -e build/run-latex-again ]; then \
			echo -n "run-latex-again exists, running latex again because: "; \
			cat build/run-latex-again; \
			rm -f build/run-latex-again; \
			make build_run; \
		fi; \
	done

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

build/results--optimal_ordering--maximum_ruleset--comment-stripped: build/results--optimal_ordering--maximum_ruleset
	sed -e '/^#/d' "$<" > "$@"

# Factored stats for graphs.
build/stats-input-size-vs-parsing-time: build/results--optimal_ordering--maximum_ruleset--comment-stripped wc.txt file-sizes.txt
	paste -d ' ' $^ | awk 'BEGIN { print "# line-count file-size"; }; {print ($$3 * 10 * 1000 / $$8), " ", ($$3 * 1000 * 1000 / $$11) }' > "$@"

build/stats-cached-regexes-vs-discarded-regexes: build/results--optimal_ordering--maximum_ruleset build/results--skip_inserting_results--discard_compiled_regexes--optimal_ordering--maximum_ruleset
	paste -d ' ' $^ | awk '$$1 != "#" {print ($$9 * 100 / $$3) - 100 }' > "$@"

build/stats-optimal-and-reverse-vs-shuffle: build/results--optimal_ordering--maximum_ruleset build/results--shuffle_ordering--maximum_ruleset build/results--reverse_ordering--maximum_ruleset
	paste -d ' ' $^ | awk 'BEGIN { print "# optimal/shuffle reverse/shuffle"; } $$1 != "#" {print ($$3 * 100 / $$9), " ", ($$15 * 100 / $$9) }' > "$@"

build/stats-perfect-best-and-perfect-worst-vs-shuffle: build/results--perfect_best--maximum_ruleset build/results--shuffle_ordering--maximum_ruleset build/results--perfect_worst--maximum_ruleset
	paste -d ' ' $^ | awk 'BEGIN { print "# perfect-best/shuffle perfect-worst/shuffle"; } $$1 != "#" {print ($$3 * 100 / $$9), " ", ($$15 * 100 / $$9) }' > "$@"

# Hits per rule.
build/stats-hits: db.full-run.sq3
	sqlite3 -separator ' ' "$<" "select hits_total from rules order by hits_total;" > "$@.tmp"
	nl "$@.tmp" > "$@"
	rm -f "$@.tmp"

build/stats-hits-reversed: build/stats-hits
	tac "$<" > "$@"

# Stats for cached regexes vs discarded regexs: all logs, logs 22,62-68, all other logs.
build/stats-cached-regexes-vs-discarded-regexes-stddev: build/stats-cached-regexes-vs-discarded-regexes
	perl ../stats/stddev "$<" > "$@"
	echo "Row: All log files" >> "$@"

build/stats-cached-regexes-vs-discarded-regexes-logs-22-62-68-stddev: build/stats-cached-regexes-vs-discarded-regexes
	sed -e '1,21d; 23,61d; 69,$$d;' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Log files 22 and 62--68" >> "$@"

build/stats-cached-regexes-vs-discarded-regexes-other-logs-stddev: build/stats-cached-regexes-vs-discarded-regexes
	sed -e '22d; 62,68d;' "$<" | perl ../stats/stddev > "$@"
	echo "Row: All log files except 22 and 62--68" >> "$@"

build/include-cached-regexes-vs-discarded-regexes.tex: build/stats-cached-regexes-vs-discarded-regexes-stddev build/stats-cached-regexes-vs-discarded-regexes-logs-22-62-68-stddev build/stats-cached-regexes-vs-discarded-regexes-other-logs-stddev
	perl mk-stats-cached-discarded-include $^ > "$@"

# File size and number of lines ratios: stddev, mean, etc.
build/stats-file-size-vs-parsing-time-stddev: build/stats-input-size-vs-parsing-time
	awk '!/#/ {print $$2}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: File size vs\\@. parsing time" >> "$@"

build/stats-file-size-vs-parsing-time-logs-22-62-68-stddev: build/stats-input-size-vs-parsing-time
	awk '!/#/ {print $$2}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: File size vs\\@. parsing time (log files 22, 62--68)" >> "$@"

build/stats-file-size-vs-parsing-time-other-logs-stddev: build/stats-input-size-vs-parsing-time
	awk '!/#/ {print $$2}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: File size vs\\@. parsing time (all other log files)" >> "$@"

build/stats-number-of-log-lines-vs-parsing-time-stddev: build/stats-input-size-vs-parsing-time
	awk '!/#/ {print $$1}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: No\\@. of log lines vs\\@. parsing time" >> "$@"

build/stats-number-of-log-lines-vs-parsing-time-logs-22-62-68-stddev: build/stats-input-size-vs-parsing-time
	awk '!/#/ {print $$1}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: No\\@. of log lines vs\\@. parsing time (log files 22, 62--68)" >> "$@"

build/stats-number-of-log-lines-vs-parsing-time-other-logs-stddev: build/stats-input-size-vs-parsing-time
	awk '!/#/ {print $$1}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: No\\@. of log lines vs\\@. parsing time (all other log files)" >> "$@"

build/include-file-size-and-number-of-log-lines-vs-parsing-time.tex: 			\
		build/stats-file-size-vs-parsing-time-stddev				\
		build/stats-file-size-vs-parsing-time-logs-22-62-68-stddev		\
		build/stats-file-size-vs-parsing-time-other-logs-stddev 		\
		build/stats-number-of-log-lines-vs-parsing-time-stddev			\
		build/stats-number-of-log-lines-vs-parsing-time-logs-22-62-68-stddev	\
		build/stats-number-of-log-lines-vs-parsing-time-other-logs-stddev
	perl mk-stats-cached-discarded-include $^ | sed -e 's/\\%//g' > "$@"

# Optimal/shuffle/reverse ratios: stddev, mean, etc.
build/stats-optimal-vs-shuffle-stddev: build/stats-optimal-and-reverse-vs-shuffle
	awk '!/#/ {print $$1}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Optimal (all log files)" >> "$@"

build/stats-optimal-vs-shuffle-logs-22-62-68-stddev: build/stats-optimal-and-reverse-vs-shuffle
	awk '!/#/ {print $$1}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: Optimal (log files 22, 62--68)" >> "$@"

build/stats-optimal-vs-shuffle-other-logs-stddev: build/stats-optimal-and-reverse-vs-shuffle
	awk '!/#/ {print $$1}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: Optimal (all other log files)" >> "$@"

build/stats-reverse-vs-shuffle-stddev: build/stats-optimal-and-reverse-vs-shuffle
	awk '!/#/ {print $$2}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Reverse (all log files)" >> "$@"

build/stats-reverse-vs-shuffle-logs-22-62-68-stddev: build/stats-optimal-and-reverse-vs-shuffle
	awk '!/#/ {print $$2}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: Reverse (log files 22, 62--68)" >> "$@"

build/stats-reverse-vs-shuffle-other-logs-stddev: build/stats-optimal-and-reverse-vs-shuffle
	awk '!/#/ {print $$2}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: Reverse (all other log files)" >> "$@"

build/include-optimal-and-reverse-vs-shuffle.tex: 			\
		build/stats-optimal-vs-shuffle-stddev			\
		build/stats-optimal-vs-shuffle-logs-22-62-68-stddev	\
		build/stats-optimal-vs-shuffle-other-logs-stddev		\
		build/stats-reverse-vs-shuffle-stddev			\
		build/stats-reverse-vs-shuffle-logs-22-62-68-stddev	\
		build/stats-reverse-vs-shuffle-other-logs-stddev	\
		
	perl mk-stats-cached-discarded-include $^ > "$@" || (rm -f "$@"; false)

# Perfect-best/optimal/shuffle/reverse/perfect-worst ratios: stddev, mean, etc.
# These partially depend on optimal/shuffle/reverse ratios generated above.
build/stats-perfect-best-vs-shuffle-stddev: build/stats-perfect-best-and-perfect-worst-vs-shuffle
	awk '!/#/ {print $$1}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Perfect best (all log files)" >> "$@"

build/stats-perfect-best-vs-shuffle-logs-22-62-68-stddev: build/stats-perfect-best-and-perfect-worst-vs-shuffle
	awk '!/#/ {print $$1}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: Perfect best (log files 22, 62--68)" >> "$@"

build/stats-perfect-best-vs-shuffle-other-logs-stddev: build/stats-perfect-best-and-perfect-worst-vs-shuffle
	awk '!/#/ {print $$1}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: Perfect best (all other log files)" >> "$@"

build/stats-perfect-worst-vs-shuffle-stddev: build/stats-perfect-best-and-perfect-worst-vs-shuffle
	awk '!/#/ {print $$2}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Perfect worst (all log files)" >> "$@"

build/stats-perfect-worst-vs-shuffle-logs-22-62-68-stddev: build/stats-perfect-best-and-perfect-worst-vs-shuffle
	awk '!/#/ {print $$2}' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | perl ../stats/stddev > "$@"
	echo "Row: Perfect worst (log files 22, 62--68)" >> "$@"

build/stats-perfect-worst-vs-shuffle-other-logs-stddev: build/stats-perfect-best-and-perfect-worst-vs-shuffle
	awk '!/#/ {print $$2}' "$<" | sed -e '22d; 62,68d;' | perl ../stats/stddev > "$@"
	echo "Row: Perfect worst (all other log files)" >> "$@"

build/include-perfect-best-and-optimal-and-reverse-and-perfect-worst-vs-shuffle.tex: 			\
		build/stats-perfect-best-vs-shuffle-stddev			\
		build/stats-perfect-best-vs-shuffle-logs-22-62-68-stddev	\
		build/stats-perfect-best-vs-shuffle-other-logs-stddev		\
		build/stats-optimal-vs-shuffle-stddev				\
		build/stats-optimal-vs-shuffle-logs-22-62-68-stddev		\
		build/stats-optimal-vs-shuffle-other-logs-stddev		\
		build/stats-reverse-vs-shuffle-stddev				\
		build/stats-reverse-vs-shuffle-logs-22-62-68-stddev		\
		build/stats-reverse-vs-shuffle-other-logs-stddev		\
		build/stats-perfect-worst-vs-shuffle-stddev			\
		build/stats-perfect-worst-vs-shuffle-logs-22-62-68-stddev	\
		build/stats-perfect-worst-vs-shuffle-other-logs-stddev		\
		
	perl mk-stats-cached-discarded-include $^ > "$@" || (rm -f "$@"; false)

# Summary of most effective restrictions
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
	sqlite3 -separator ' ' "$<" 'SELECT action, count(action) FROM rules GROUP BY action ORDER BY count(action), action;' > "$@.tmp"
	nl "$@.tmp" > "$@"
	rm -f "$@.tmp"
	# Turn everything to lowercase.
	sed -i -e 's/^\(.*\)$$/\L\1\E/' "$@"

# Minimum ruleset vs maximum ruleset.
build/include-full-ruleset-vs-minimum-ruleset.tex: build/stats-optimal-full-ruleset-vs-minimum-ruleset
	awk 'BEGIN { sum = 0; } { sum += $$2; } END { printf "%.3g\\%%%%\n", sum / NR }' "$<" > "$@" || (rm -f "$@"; false)

build/stats-optimal-full-ruleset-vs-minimum-ruleset: build/results--optimal_ordering--maximum_ruleset build/results--optimal_ordering--minimum_ruleset
	INPUT="$^" OUTPUT="$@" make full-ruleset-vs-minimum-ruleset

build/stats-reverse-full-ruleset-vs-minimum-ruleset: build/results--reverse_ordering--maximum_ruleset build/results--reverse_ordering--minimum_ruleset
	INPUT="$^" OUTPUT="$@" make full-ruleset-vs-minimum-ruleset

build/stats-shuffle-full-ruleset-vs-minimum-ruleset: build/results--shuffle_ordering--maximum_ruleset build/results--shuffle_ordering--minimum_ruleset
	INPUT="$^" OUTPUT="$@" make full-ruleset-vs-minimum-ruleset

full-ruleset-vs-minimum-ruleset:
	# There deliberately aren't any quotes around INPUT because it will have 
	# multiple file names
	paste -d ' ' ${INPUT} | awk '!/^#/ { print $$1, (($$3 -$$9) * 100 / $$9)}' > "${OUTPUT}"

# Duration of the full run parsing all 93 log files.
build/include-timing-run-duration.tex: results/results-full-run/timing
	awk -F': ' '/^Total time:/ { printf "%d hours, %d minutes and %.3f seconds%\n", $$3 / (60 * 60), ($$3 / 60) % 60, $$3 % 60 }' "$<" > "$@"
build/include-timing-run-throughput.tex: results/results-full-run/timing
	awk -F': ' '/^Total time:/ { printf "%.3f~MB (%'\''.3f log lines) parsed per minute%%\n", (10076909581 / (1024 * 1024)) / ($$3 / 60), 60721709 / ($$3 / 60)}' "$<" > "$@"
build/include-median-throughput-MB.tex: build/results--optimal_ordering--maximum_ruleset--comment-stripped file-sizes.txt
	paste -d ' ' $^ | awk '{ printf "%.3f\n", ($$8 / (1024 * 1024) ) / ($$3 / 60); }' | perl ../stats/stddev | awk '/Median:/ { print $$2 "~MB%" }' > "$@"
build/include-median-throughput-log-lines.tex: build/results--optimal_ordering--maximum_ruleset--comment-stripped wc.txt
	paste -d ' ' $^ | awk '{ printf "%.3f\n", $$8 / ($$3 / 60); }' | perl ../stats/stddev | awk '/Median:/ { printf "%'\''.3f log lines%\n", $$2 }' > "$@"

build/include-optimal-ordering-parsing-time-reduction-other-logs.tex: build/stats-optimal-and-reverse-vs-shuffle 
	sed -e '/^#/d' "$<" | sed -e '22d; 62,68d;' | awk '{print $$1}' | ../stats/stddev | awk '/Median:/ { printf "%.3f%%\n", 100 - $$2 }' > "$@"
build/include-optimal-ordering-parsing-time-reduction-logs-22-62-68.tex: build/stats-optimal-and-reverse-vs-shuffle 
	sed -e '/^#/d' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | awk '{print $$1}' | ../stats/stddev | awk '/Median:/ { printf "%.3f%%\n", 100 - $$2 }' > "$@"

build/include-top-ten-hits.tex: build/stats-hits-reversed
	awk 'BEGIN { sum = 0; topten = 0 }; { sum += $$2 }; NR <= 10 { topten += $$2 }; END { printf "%'\''.3f%\n", topten * 100 / sum };' "$<" > "$@"

build/stats-rules-tried-per-log-line: results/results-full-run/timing
	perl -Mstrict -w -E 'my ($$rules_tried, $$lines_parsed); while (<>) { m/^num_lines_parsed:.*: ([^:]+)$$/ and $$lines_parsed = $$1; m/^num_rules_tried:.*: ([^:]+)$$/ and $$rules_tried = $$1; m/^Parsed logfile:/ and say $$rules_tried / $$lines_parsed; }' "$<" > "$@"

build/stats-number-of-action-invocations: results/results-full-run/timing
	perl -Mstrict -w -n -E 'our %counts; if (m/^(\w+) lines_by_action: .*: (\d+)$$/) { $$counts{$$1} += $$2; } END { my $$i = 1; map { say lc qq{$$i $$_ $$counts{$$_}}; $$i++; } sort { $$counts{$$a} <=> $$counts{$$b} or $$a cmp $$b } keys %counts; }' "$<" > "$@"

build/stats-number-of-action-invocations-excluding-22-and-62--68: results/results-full-run/timing
	perl mk-number-of-action-invocations-excluding-22-and-62--68 "$<" > "$@"

build/stats-per-file-action-invocation-numbers: results/results-full-run/timing
	perl mk-per-file-action-invocation-numbers "$<" > "$@"

build/graph-per-file-action-invocation-numbers.gpi: build/stats-per-file-action-invocation-numbers
	perl mk-per-file-action-invocation-numbers-graph "$<" > "$@"

build/graph-per-file-action-invocation-numbers.pdf: build/graph-per-file-action-invocation-numbers.gpi
build/graph-per-file-action-invocation-numbers.ps: build/graph-per-file-action-invocation-numbers.gpi

build/include-per-file-action-invocation-numbers-table.tex: build/stats-per-file-action-invocation-numbers
	perl mk-per-file-action-invocation-numbers-table "$<" > "$@"

# Sample output from an SQL query.
build/include-sample-sql-output.tex: db.full-run.sq3 generate-sample-sql-output.sql
	sqlite3.6.0 -separator ' & ' -bail "$<" < "generate-sample-sql-output.sql" > "$@"
	sed -i -e 's/, [^ ]\+ / /' -e 's/\(\.[0-9]\{3\}\)[0-9]*%$$/\1%/' -e 's/$$/ \\\\/' -e 's/_/\\_/g' -e 's/%/\\%/g' "$@"

# The sample SQL query itself.
build/include-sample-sql-query.tex: generate-sample-sql-output.sql
	( echo '\begin{verbatim}'; cat "$<"; echo '\end{verbatim}' ) > "$@"

# Database schema
build/database-schema.pdf: database-schema.ipe
	ipetoipe -pdf "$<" "$@"
build/database-schema.ps: database-schema.ipe
	ipetoipe -eps "$<" "$@"

# Cleanup.
clean:
	rm -f	*.acn *.acr *.alg *.aux *.bbl *.blg *.cbk *.cit *.deps *.dvi \
		*.glg *.glo *.gls *.idx *.ist *.lof *.log *.lot *.old *.out \
		*.pdf *.ps *.toc *.cite *.pin *.plg *.pout *.nav *.snm \
		citations.tt2

realclean: veryclean
veryclean: clean
	rm -f	build/stats-* build/include-* build/graph-*	\
		build/logparser-flow-chart* build/Makefile.*	\
		build/plot-* build/logparser*.tex

.PHONY: check
check: lines-from-paragraphs
	# Edit the log file to remove underfull hbox warnings I can't fix.
	sed -i -e '/.\/.*.bbl$$/,$$s/^Underfull.*//' *.log
	make --silent join-lines | grep -i -E 'underfull|overfull|LaTeX Warning' || true
	sed -n -e '/^Package .* Warning/,/^$$/p' *.log
	grep '!!' *.?lg || true;
	chktex -I0 -q *.tex *.bbl build/include-*.tex
	# Check for contractions.
	ack -i 'it'\''s|\w'\''(?!s)\w' logparser*.tex
	# Check for uncapitalised words in section headings, and then in bibliography entries.
	ack '\\(chapter|(sub)*section)\{([[:lower:]]|.*? [[:lower:]])' logparser*.tex
	ack '(address|author|publisher|title)\s+=\s+.* (?!(a|and|by|for|from|is|in|of|the|to))[[:lower:]]' logparser-bibliography.tt2
	# Check for:
	# * using a bare \url{} command
	# * trailing spaces or lines containing only spaces
	# * repeated .
	# * . not followed by two spaces
	ack '\\url{|[ \t]+$$|\.{2,}|\. [^ ]' logparser-*.tex
	ack -i 'XX[X]' logparser.bbl
	# Check for repeated words
	ack '\b(\w+)\b\s+\b\1\b' build/logparser*.tex
	# Check for using an instead of a before \daemon{foo}
	ack ' an \\daemon{' build/logparser*.tex

# List all acronyms not followed by {}, for visual inspection.
check-acronyms:
	sed -n -e '/newacronym/!d; s/}.*//; s/.*{//; s/$$/[^{e]/; p;' logparser-acronyms.tex \
		| grep -f - -n $$(ls logparser*.tex | grep -v ^logparser-acronyms.tex)

todo:
	grep    -n -E -i '[T]ODO|[X]XX' Makefile *.tex *.tt2 || true
	grep -c -n -E -i '[T]ODO|[X]XX' Makefile *.tex *.tt2 | grep -v ':0$$'
	grep    -n -E -i '[T]ODO|[X]XX' Makefile *.tex *.tt2 | wc -l

join-lines:
	perl -p -E 'if (m/LaTeX Warning:/ and not m/\.$$/) { chomp; }' *.log

underfull: overfull

overfull: all
	if grep -q -E -i 'underfull|overfull' *.log; then \
		make join-lines | grep -E -i '[<(]\./[^) ]*( |$$)|\]\)$$|overfull|underfull'; \
	fi

undefined-references: all
	if make join-lines | grep -q -E -i 'reference.*undefined'; then \
		make join-lines | grep -E -i '[<(]\./[^) ]*( |$$)|\]\)$$|reference.*undefined.*'; \
	fi

unused-references: all
	if make join-lines | grep -q -E -i 'Unused label'; then \
		make join-lines | grep -E -i '[<(]\./[^) ]*( |$$)|\]\)$$|Unused label'; \
	fi

2up: logparser-2up.ps logparser-2up.pdf

logparser-2up.ps: logparser.ps
	psnup -2 "$<" "$@"

logparser-2up.pdf: logparser-2up.ps
	ps2pdf "$<" "$@"

xpdf: all
	xpdf logparser.pdf &

spellcheck:
	for file in logparser*.tex; do aspell -t -c "$$file"; done

# I deliberately leave out the "r" from logparser below, because if it's 
# included then the rule won't work for logparser.tex.
build/logparse%.tex: logparse%.tex
	perl paragraphs-to-lines "$<" > "$@"
lines-from-paragraphs: $(patsubst %,build/%,$(wildcard logparser*.tex))

log-files-lines: lines-from-paragraphs
	ACK_PAGER="$$PAGER" ack -i '(?<!log[- ])(lines|files)\b(?!\{)' build/logparser*.tex

diction:
	# Is -a a good option for untex?
	for file in *.tex; do \
		untex -e "$$file" | diction --suggest --file diction-rules --no-default-file | less -M -w "-PM$$file %lt/%L"; \
	done

slides-xpdf: sgai-2008-slides.pdf
	xpdf "$<" &

slides: sgai-2008-slides.pdf

sgai-2008-slides.pdf: sgai-2008-slides.tex
	pdflatex "$<"
	pdflatex "$<"
	chktex -q "$<"
