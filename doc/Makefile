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
logparser.deps:
	touch "$@"
logparser.pdf.deps:
	touch "$@"
logparser.ps.deps:
	touch "$@"

# We generate the lists of graphs and tables that are included.
include build/Makefile.tables-included
include build/Makefile.graphs-included
include build/Makefile.other-included
build/Makefile.graphs-included: logparser*.tex
	sed -n -e 's/^[ ]*.showgraph{\([^}]\+\)}.*/logparser.ps.deps: \1.ps\nlogparser.pdf.deps: \1.pdf/p' $^ > "$@"
build/Makefile.tables-included: logparser*.tex
	sed -n -e 's/^[ ]*.showtable{\([^}]\+\)}.*/logparser.deps: \1.tex/p' $^ > "$@"
build/Makefile.other-included: logparser*.tex
	sed -n -e 's/.*\\input{\(build[^}]\+\)}.*/logparser.deps: \1.tex/p' $^ > "$@"

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
		if grep -f latex-warnings "${BASENAME}.log"; then \
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
	sed -e '/^load/s,","../graphs/,' -e 's/\([-.]\)ps/\1pdf/g' "$<" > "$@"

build/results-%: results/results-%
	perl ../stats/parse-stats "$<" > "$@"

build/results--%--comment-stripped: build/results--%
	sed -e '/^#/d' "$<" > "$@"

# Factored stats for graphs.
build/stats-input-size-vs-parsing-time: build/results--optimal_ordering--maximum_ruleset--comment-stripped wc.txt file-sizes.txt
	paste -d ' ' $^ | awk 'BEGIN { print "# line-count file-size"; }; {print ($$3 * 10 * 1000 / $$8), " ", ($$3 * 1000 * 1000 / $$11) }' > "$@"

build/stats-cached-regexes-vs-discarded-regexes: build/results--optimal_ordering--maximum_ruleset build/results--optimal_ordering--discard_compiled_regexes
	paste -d ' ' $^ | awk '$$1 != "#" {print ($$9 * 100 / $$3) - 100 }' > "$@"

build/stats-optimal-and-reverse-vs-shuffle: build/results--optimal_ordering--maximum_ruleset build/results--shuffle_ordering--maximum_ruleset build/results--reverse_ordering--maximum_ruleset
	paste -d ' ' $^ | awk 'BEGIN { print "# optimal/shuffle reverse/shuffle"; } $$1 != "#" {print ($$3 * 100 / $$9), " ", ($$15 * 100 / $$9) }' > "$@"

build/stats-perfect-best-and-perfect-worst-vs-shuffle: build/results--perfect_best--maximum_ruleset build/results--shuffle_ordering--maximum_ruleset build/results--perfect_worst--maximum_ruleset
	paste -d ' ' $^ | awk 'BEGIN { print "# perfect-best/shuffle perfect-worst/shuffle"; } $$1 != "#" {print ($$3 * 100 / $$9), " ", ($$15 * 100 / $$9) }' > "$@"


build/stats-file-size-optimal-shuffle-reverse: file-sizes.txt build/results--optimal_ordering--maximum_ruleset--comment-stripped build/results--shuffle_ordering--maximum_ruleset--comment-stripped build/results--reverse_ordering--maximum_ruleset--comment-stripped
	paste -d ' ' $^ | awk 'BEGIN { print "# filesize optimal shuffle reverse"; } {print $$2, $$5, $$11, $$17 }' > "$@"

build/stats-file-size-discarded: file-sizes.txt build/results--optimal_ordering--discard_compiled_regexes--comment-stripped
	paste -d ' ' $^ | awk 'BEGIN { print "# filesize discarded"; } {print $$2, $$5 }' > "$@"

build/stats-file-size-oracle: file-sizes.txt build/results--perfect_best--maximum_ruleset--comment-stripped
	paste -d ' ' $^ | awk 'BEGIN { print "# filesize oracle"; } {print $$2, $$5 }' > "$@"

build/stats-perfect-best-vs-optimal: build/results--optimal_ordering--maximum_ruleset build/results--perfect_best--maximum_ruleset
	paste -d ' ' $^ | awk 'BEGIN { print "# optimal/perfect-best"; } $$1 != "#" {print ($$3 * 100 / $$9) - 100 }' > "$@"

build/stats-perfect-worst-vs-reverse: build/results--reverse_ordering--maximum_ruleset build/results--perfect_worst--maximum_ruleset
	paste -d ' ' $^ | awk 'BEGIN { print "# reverse/perfect-worst"; } $$1 != "#" {print 100 - ($$3 * 100 / $$9) }' > "$@"

build/stats-perfect-best-vs-optimal-stddev: build/stats-perfect-best-vs-optimal
	perl mk-mean-stddev-for-three-groups-of-log-files "Percentage increase" "$<" > "$@"

build/stats-perfect-worst-vs-reverse-stddev: build/stats-perfect-worst-vs-reverse
	perl mk-mean-stddev-for-three-groups-of-log-files "Percentage decrease" "$<" > "$@"

build/include-perfect-best-vs-optimal-stddev.tex: build/stats-perfect-best-vs-optimal-stddev
	perl mk-stats-cached-discarded-include "$^" > "$@"

build/include-perfect-worst-vs-reverse-stddev.tex: build/stats-perfect-worst-vs-reverse-stddev
	perl mk-stats-cached-discarded-include "$^" > "$@"

build/include-perfect-best-vs-optimal-mean.tex: build/stats-perfect-best-vs-optimal-stddev
	awk 'BEGIN { mean = 0 } /Mean:/ { if ($$2 > mean) { mean = $$2 } } END { printf "%.0f\\%%%%\n", mean }' "$<" > "$@"

# Median file size and number of log lines
build/include-median-file-size.tex: file-sizes.txt
	awk '{print $$2}' "$<" | perl mk-mean-stddev-for-three-groups-of-log-files "ignored" | awk '/Median/ { printf "%.3f MB%%\n", $$2 / (1024 * 1024); exit; }' > "$@"

build/include-median-number-of-log-lines.tex: wc.txt
	awk '{print $$2}' "$<" | perl mk-mean-stddev-for-three-groups-of-log-files "ignored" | awk '/Median/ { printf "%'\''d%%\n", $$2; exit; }' > "$@"

build/include-total-size-of-93-log-files.tex: file-sizes.txt
	awk 'BEGIN { total_size = 0 } { total_size += $$2 } END { printf "%.3f GB%%\n", total_size / (1024 * 1024 * 1024) }' "$<" > "$@"

build/include-median-mails-accepted-over-smtp.tex: mails-received.txt
	awk '((NR % 7) != 2) && ((NR % 7) != 3) { print $$2 }' "$<" | perl ../stats/stddev | awk '/Median/ { printf "%'\''d%%\n", $$2 }' > "$@"

# Hits per rule.
build/stats-hits: db.full-run.sq3
	sqlite3 -separator ' ' "$<" "select hits_total from rules order by hits_total;" > "$@.tmp"
	nl "$@.tmp" > "$@"
	rm -f "$@.tmp"

build/stats-hits-reversed: build/stats-hits
	tac "$<" > "$@"

# Stats for cached regexes vs discarded regexs: all logs, logs 22,62-68, all other logs.
build/include-cached-regexes-vs-discarded-regexes.tex: build/stats-cached-regexes-vs-discarded-regexes
	perl mk-mean-stddev-for-three-groups-of-log-files "Not caching compiled regexes" "$<" | perl mk-stats-cached-discarded-include > "$@"

build/include-cached-regexes-vs-discarded-regexes-mean.tex: build/stats-cached-regexes-vs-discarded-regexes
	perl mk-mean-stddev-for-three-groups-of-log-files "ignored" "$<" | awk '/Mean:/ { mean = $$2 } END { printf "%.3f\\%%%%\n", mean }' > "$@"

build/include-cached-regexes-vs-discarded-regexes-mean-reduction.tex: build/include-cached-regexes-vs-discarded-regexes-mean.tex
	awk '{ non_cached_parsing_time = $$1 + 100; cached_percentage_parsing_time = 100 * 100 / non_cached_parsing_time; cached_percentage_reduction = 100 - cached_percentage_parsing_time; printf "%.3f\\%%%%\n", cached_percentage_reduction }' "$<" > "$@"

# File size and number of lines ratios: stddev, mean, etc.
build/stats-file-size-vs-parsing-time-stddev: build/stats-input-size-vs-parsing-time
	awk '!/^#/ {print $$2}' "$<" | perl mk-mean-stddev-for-three-groups-of-log-files "Log file size vs\\@. parsing time" > "$@"

build/stats-number-of-log-lines-vs-parsing-time-stddev: build/stats-input-size-vs-parsing-time
	awk '!/^#/ {print $$1}' "$<" | perl mk-mean-stddev-for-three-groups-of-log-files "No\\@. of log lines vs\\@. parsing time" > "$@"

build/include-file-size-and-number-of-log-lines-vs-parsing-time.tex: 			\
		build/stats-file-size-vs-parsing-time-stddev				\
		build/stats-number-of-log-lines-vs-parsing-time-stddev
	perl mk-stats-cached-discarded-include $^ | sed -e 's/\\%//g' > "$@"

# Mean number of bytes per log line
build/stats-mean-bytes-per-log-line: file-sizes.txt wc.txt
	paste -d ' ' $^ | awk '{printf "%.3f\n", $$2 / $$4}' > "$@"

build/stats-parsing-time-vs-number-of-log-lines: build/results--optimal_ordering--maximum_ruleset--comment-stripped wc.txt
	paste -d ' ' $^ | awk '{print $$3, $$8}' > "$@"

build/stats-parsing-time-vs-file-size: build/results--optimal_ordering--maximum_ruleset--comment-stripped file-sizes.txt
	paste -d ' ' $^ | awk '{print $$3, $$8}' > "$@"

# Average number of rules tried per log line
build/stats-average-number-of-rules-tried-per-log-line: results/results-full-run/timing
	awk '/num_lines_parsed:/ { lines_parsed = $$3 }; /num_rules_tried:/ { rules_tried = $$3; print rules_tried / lines_parsed; }' "$<" > "$@"

build/stats-average-number-of-rules-tried-per-program: results/results-full-run/timing
	perl mk-average-number-of-rules-tried-per-program "$<" > "$@"

# Optimal/shuffle/reverse ratios: stddev, mean, etc.
build/stats-optimal-vs-shuffle-stddev: build/stats-optimal-and-reverse-vs-shuffle
	awk '!/#/ {print $$1}' "$<" | perl mk-mean-stddev-for-three-groups-of-log-files "Optimal ordering" > "$@"

build/stats-reverse-vs-shuffle-stddev: build/stats-optimal-and-reverse-vs-shuffle
	awk '!/#/ {print $$2}' "$<" | perl mk-mean-stddev-for-three-groups-of-log-files "Reverse ordering" > "$@"

build/include-optimal-and-reverse-vs-shuffle.tex: 			\
		build/stats-optimal-vs-shuffle-stddev			\
		build/stats-reverse-vs-shuffle-stddev
	perl mk-stats-cached-discarded-include $^ > "$@"

# Perfect-best/optimal/shuffle/reverse/perfect-worst ratios: stddev, mean, etc.
# These partially depend on optimal/shuffle/reverse ratios generated above.
build/stats-perfect-best-vs-shuffle-stddev: build/stats-perfect-best-and-perfect-worst-vs-shuffle
	awk '!/#/ {print $$1}' "$<" | perl mk-mean-stddev-for-three-groups-of-log-files "The oracle" > "$@"

build/stats-perfect-worst-vs-shuffle-stddev: build/stats-perfect-best-and-perfect-worst-vs-shuffle
	awk '!/#/ {print $$2}' "$<" | perl mk-mean-stddev-for-three-groups-of-log-files "Oracle" > "$@"

build/include-perfect-best-and-optimal-and-reverse-and-perfect-worst-vs-shuffle.tex: 			\
		build/stats-perfect-best-vs-shuffle-stddev			\
		build/stats-optimal-vs-shuffle-stddev				\
		build/stats-reverse-vs-shuffle-stddev				\
		build/stats-perfect-worst-vs-shuffle-stddev
	perl mk-stats-cached-discarded-include $^ > "$@"

build/include-perfect-best-and-optimal-vs-shuffle.tex: 				\
		build/stats-perfect-best-vs-shuffle-stddev			\
		build/stats-optimal-vs-shuffle-stddev
	perl mk-stats-cached-discarded-include $^ > "$@"

# Summary of most effective restrictions
build/include-restriction-summary-table.tex: db.full-run.sq3
	perl mk-restriction-summary-table > "$@"

# Number of mails received per day
build/stats-mails-received-stddev: mails-received.txt
	awk '{print $$2}' "$<" | perl ../stats/stddev > "$@"
	echo "Row: All days" >> "$@"
	echo >> "$@"

build/stats-mails-received-weekends-stddev: mails-received.txt
	awk '((NR % 7) == 2) || ((NR % 7) == 3) { print $$2 }' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Weekend days" >> "$@"
	echo >> "$@"

build/stats-mails-received-weekdays-stddev: mails-received.txt
	awk '((NR % 7) != 2) && ((NR % 7) != 3) { print $$2 }' "$<" | perl ../stats/stddev > "$@"
	echo "Row: Week days" >> "$@"
	echo >> "$@"

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

build/stats-number-of-rules-per-program: db.full-run.sq3
	sqlite3 -separator ' & ' "$<" 'SELECT program, count(program) FROM rules GROUP BY program ORDER BY program;' > "$@"

build/include-number-of-rules-per-program.tex: build/stats-number-of-rules-per-program
	sed -e 's/$$/ \\\\/;' "$<" > "$@"

build/stats-number-of-rules-per-program-minimum-ruleset: ../sql/db.minimum-ruleset.sq3
	sqlite3 -separator ' & ' "$<" 'SELECT program, count(program) FROM rules GROUP BY program ORDER BY program;' > "$@"

build/include-number-of-rules-per-program-minimum-ruleset.tex: build/stats-number-of-rules-per-program build/stats-number-of-rules-per-program-minimum-ruleset
	paste -d ' ' $^ | awk 'BEGIN { OFS = " & " } { print $$1, $$3, $$6, $$3 - $$6 }' | sed -e 's/$$/ \\\\/;' > "$@"

# Minimum ruleset vs maximum ruleset.
build/include-full-ruleset-vs-minimum-ruleset-mean.tex: build/stats-optimal-full-ruleset-vs-minimum-ruleset-stddev
	awk 'BEGIN { mean = 0; } /Mean:/ && mean == 0 { mean = $$2; } END { printf "%.3f\\%%%%\n", mean }' "$<" > "$@"

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

build/stats-optimal-full-ruleset-vs-minimum-ruleset-stddev: build/stats-optimal-full-ruleset-vs-minimum-ruleset
	awk '{print $$2}' "$<" | perl mk-mean-stddev-for-three-groups-of-log-files "Optimal ordering" > "$@"

build/stats-reverse-full-ruleset-vs-minimum-ruleset-stddev: build/stats-reverse-full-ruleset-vs-minimum-ruleset
	awk '{print $$2}' "$<" | perl mk-mean-stddev-for-three-groups-of-log-files "Reverse ordering" > "$@"

build/stats-shuffle-full-ruleset-vs-minimum-ruleset-stddev: build/stats-shuffle-full-ruleset-vs-minimum-ruleset
	awk '{print $$2}' "$<" | perl mk-mean-stddev-for-three-groups-of-log-files "Shuffled ordering" > "$@"

build/include-full-ruleset-vs-minimum-ruleset.tex: build/stats-optimal-full-ruleset-vs-minimum-ruleset-stddev build/stats-shuffle-full-ruleset-vs-minimum-ruleset-stddev build/stats-reverse-full-ruleset-vs-minimum-ruleset-stddev
	perl mk-stats-cached-discarded-include $^ > "$@"

# Duration of the full run parsing all 93 log files.
build/include-%-duration.tex: results/results-%/timing
	awk -F': ' '/^Total time:/ { printf "%d hours, %d minutes, and %.3f seconds%\n", $$3 / (60 * 60), ($$3 / 60) % 60, $$3 % 60 }' "$<" > "$@"
build/include-%-throughput.tex: results/results-%/timing
	awk -F': ' '/^Total time:/ { printf "%.3f~MB (%'\''.3f log lines) parsed per minute%%\n", (10076909581 / (1024 * 1024)) / ($$3 / 60), 60721709 / ($$3 / 60)}' "$<" > "$@"
build/include-skip-inserting-as-percentage-of-inserting.tex: results/results-full-run/timing results/results-insert-results/timing
	perl -Mstrict -w -E 'our @times; while (<>) { if (m/^Total time: : (.*)$$/) { push @times, $$1; } } chomp @times; printf qq{%.3f\\%%%%\n}, 100 * $$times[0] / $$times[1];' $^ > "$@"
build/include-skip-inserting-with-50-percent-improvement--as-percentage-of-inserting.tex: build/include-skip-inserting-as-percentage-of-inserting.tex
	perl -Mstrict -w -E 'my $$percentage = <>; $$percentage =~ s/\\%%//; printf qq{%.3f\\%%%%\n}, $$percentage / 2;' "$<" > "$@"

build/include-median-throughput-MB.tex: build/results--optimal_ordering--maximum_ruleset--comment-stripped file-sizes.txt
	paste -d ' ' $^ | awk '{ printf "%.3f\n", ($$8 / (1024 * 1024) ) / ($$3 / 60); }' | perl ../stats/stddev | awk '/Median:/ { print $$2 "~MB%" }' > "$@"
build/include-median-throughput-log-lines.tex: build/results--optimal_ordering--maximum_ruleset--comment-stripped wc.txt
	paste -d ' ' $^ | awk '{ printf "%.3f\n", $$8 / ($$3 / 60); }' | perl ../stats/stddev | awk '/Median:/ { printf "%'\''.3f log lines%\n", $$2 }' > "$@"

build/include-optimal-ordering-parsing-time-reduction-other-logs.tex: build/stats-optimal-and-reverse-vs-shuffle 
	sed -e '/^#/d' "$<" | sed -e '22d; 62,68d;' | awk '{print $$1}' | ../stats/stddev | awk '/Mean:/ { printf "%.3f%%\n", 100 - $$2 }' > "$@"

build/include-optimal-ordering-parsing-time-reduction-logs-22-62-68.tex: build/stats-optimal-and-reverse-vs-shuffle 
	sed -e '/^#/d' "$<" | sed -e '1,21d; 23,61d; 69,$$d;' | awk '{print $$1}' | ../stats/stddev | awk '/Mean:/ { printf "%.3f%%\n", 100 - $$2 }' > "$@"

build/include-100-minus-optimal-ordering-reduction.tex: build/include-optimal-ordering-parsing-time-reduction-other-logs.tex
	awk '{ printf "%.3f%%\n", 100 - $$1}' "$<" > "$@"

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

# How much time is spent recognising log lines.
build/stats-percentage-time-spent-recognising-log-lines: build/results--optimal_ordering--maximum_ruleset build/results--optimal_ordering--parse_lines_only
	paste -d ' ' $^ | awk '!/#/ { print $$9 * 100 / $$3 }' > "$@"

build/stats-percentage-time-spent-recognising-log-lines-stddev: build/stats-percentage-time-spent-recognising-log-lines
	perl mk-mean-stddev-for-three-groups-of-log-files "Recognising log lines" "$<" > "$@"

build/include-percentage-time-spent-recognising-log-lines-table.tex: build/stats-percentage-time-spent-recognising-log-lines-stddev
	perl mk-stats-cached-discarded-include "$<" > "$@"

build/include-percentage-time-spent-recognising-log-lines-mean.tex: build/stats-percentage-time-spent-recognising-log-lines-stddev
	awk '/Mean:/ { mean = $$2 } END { printf "%.3f\\%%%%\n", mean }' "$<" > "$@"

build/include-percentage-time-spent-processing-log-lines-mean.tex: build/stats-percentage-time-spent-recognising-log-lines-stddev
	awk '/Mean:/ { mean = $$2 } END { printf "%.3f\\%%%%\n", 100 - mean }' "$<" > "$@"

# Sample output from an SQL query.
build/include-sample-sql-output.tex: db.full-run.sq3 generate-sample-sql-output.sql
	sqlite3.6.0 -separator ' & ' -bail "$<" < "generate-sample-sql-output.sql" > "$@"
	sed -i -e 's/, [^ ]\+ / /' -e 's/\(\.[0-9]\{3\}\)[0-9]*%$$/\1%/' -e 's/$$/ \\\\/' -e 's/_/\\_/g' -e 's/%/\\%/g' "$@"

# The sample SQL query itself.
build/include-sample-sql-query.tex: generate-sample-sql-output.sql
	( echo '\begin{verbatim}'; cat "$<"; echo '\end{verbatim}' ) > "$@"

# Number of rules tried by different orderings.
build/stats-number-of-rules-used-%: results/results--%_ordering--maximum_ruleset
	awk '/num_rules_tried:/ { print $$3 }' "$<"/timing.*.1 > "$@"

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
		build/plot-* build/logparser*.tex		\
		build/database-schema.*

.PHONY: check
check: lines-from-paragraphs
	# Edit the log file to remove underfull hbox warnings I can't fix.
	sed -i -e '/(.\/.*.bbl/,$$s/^Underfull.*//' *.log
	make --silent join-lines | grep -i -E 'underfull|overfull|LaTeX Warning' || true
	sed -n -e '/^Package .* Warning/,/^$$/p' *.log
	grep '!!' *.?lg || true;
	chktex -I0 -q *.tex *.bbl build/include-*.tex
	# Check for contractions.
	ack-grep -i 'it'\''s|\w'\''(?!s)\w' logparser*.tex
	ack-grep 'etc\.' logparser*.tex
	# Check for uncapitalised words in section headings, and then in bibliography entries.
	ack-grep '\\(chapter|(sub)*section)\{([[:lower:]]|.*? (?!(a|and|by|for|from|is|in|of|or|the|to))[[:lower:]])' logparser*.tex
	ack-grep '(address|author|publisher|title)\s+=\s+.*[ "](?!(a|and|by|for|from|is|in|of|or|the|to))[[:lower:]]' logparser-bibliography.tt2
	# Check for:
	# * using a bare \url{} command
	# * trailing spaces or lines containing only spaces
	# * repeated .
	# * . not followed by two spaces
	# * three or more spaces separating sentences
	ack-grep '\\url{|[ \t]+$$|\.{2,}|\. [^ ]|\. {3,}\w' logparser-*.tex
	ack-grep -i 'XX[X]' logparser.bbl
	# Check for repeated words
	ack-grep '\b(\w+)\b\s+\b\1\b' build/logparser*.tex
	# Check for using an instead of a before \daemon{foo}
	ack-grep ' an \\daemon{' build/logparser*.tex
	# Check for perfect best not followed by oracle.
	ack-grep -i 'perfect best (?!oracle)' build/logparser*.tex
	grep 'begin{table}' logparser-*.tex | grep -v -F 'begin{table}[thbp]' || true
	grep 'set output.*pdf' graphs/* || true
	grep 'XX[X]' logparser*.tex || true

check-contractions:
	ACK_PAGER=less ack-grep "(?!(Postfix|mail|client|server|rule|parser|regex|user|program|architecture|restriction|sender|connection|word|line|framework)'s)\b\w+'s" logparser*.tex

.PHONY: check-acronyms
# List all acronyms not followed by {}, for visual inspection.
check-acronyms:
	perl check-acronyms logparser-acronyms.tex -- logparser*.tex

todo:
	( grep    -n -E '[T]ODO|[X]XX|[x]xx' Makefile *.tex *.tt2 || true )
	( grep -c -n -E '[T]ODO|[X]XX|[x]xx' Makefile *.tex *.tt2 || true ) | ( grep -v ':0$$' || true )
	( grep    -n -E '[T]ODO|[X]XX|[x]xx' Makefile *.tex *.tt2 || true ) |  wc -l

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
	ACK_PAGER="$$PAGER" ack-grep -i '(?<!log[- ])(?<!CSV\} )\b(line|file)s?\b(?!\{)' build/logparser*.tex
	ACK_PAGER="$$PAGER" ack-grep -i '\blogs\b' build/logparser*.tex
	ACK_PAGER="$$PAGER" ack-grep -i '(?<!log[- ])(?<!CSV\} )(?<!with )\b(line|file)s?\b' graphs/plot-*

diction:
	# Is -a a good option for untex?
	for file in *.tex; do \
		untex -e "$$file" | diction --ignore-double-words --suggest --file diction-rules --no-default-file | less -M -w "-PM$$file %lt/%L"; \
	done

slides-xpdf: sgai-2008-slides.pdf
	xpdf "$<" &

slides: sgai-2008-slides.pdf

sgai-2008-slides.pdf: sgai-2008-slides.tex
	pdflatex "$<"
	pdflatex "$<"
	chktex -q "$<"
