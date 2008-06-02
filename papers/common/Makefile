# NOTE: you need to run 'make clean' between running 'make foo.dvi' and 'make
# foo.pdf', otherwise latex will only be run once and it will get very confused.
all: paper.pdf

run_latex:
	("${PROGRAM}" -interaction=nonstopmode "${SOURCE}" || rm -f "${DEST}") | tee "${DEST}.out";
	[ -f "${DEST}" ]
	# Run bibtex if necessary; latex will pick up the new information on the 
	# next run, and on the third run will properly resolve \cite commands.
	if grep -q "Warning: Citation .* on page .* undefined" "${DEST}.out"; then \
		bibtex $$( basename "${SOURCE}" .tex ) || rm -f "${DEST}"; \
	fi
	[ -f "${DEST}" ]

paper.dvi: paper.tex
	make build PROGRAM="latex" SOURCE="$<" DEST="$@"

paper.pdf: paper.tex
	make build PROGRAM="pdflatex" SOURCE="$<" DEST="$@"

paper.bbl: ../common/bibliography.bib
	bibtex $$( basename "$@" .bbl ) || (rm -f paper.pdf paper.ps "$@"; false)
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

# build is a directory so it needs to be marked as PHONY.
.PHONY: build
build:
	make build_loop PROGRAM="${PROGRAM}" SOURCE="${SOURCE}" DEST="${DEST}"
	cat "${DEST}.out"
	grep Overfull "${DEST}.out" || true
	grep -A 1 "LaTeX Warning: " "${DEST}.out" || true
	BASE=$$( basename "${SOURCE}" .tex ); \
	grep ^Warning "$$BASE.blg" || true; \
	#grep '!!' "$$BASE.glg" "$$BASE.alg" || true;
	grep 'Output written .* pages' "${DEST}.out";
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
	#make run_makeindex STYLE="$$BASE.ist" LOG="$$BASE.glg" OUTPUT="$$BASE.gls" INPUT="$$BASE.glo"; \
	#make run_makeindex STYLE="$$BASE.ist" LOG="$$BASE.alg" OUTPUT="$$BASE.acn" INPUT="$$BASE.acr"
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
	set -e; \
	for i in $$( seq 1 4 ); do \
		echo "iteration $$i starting"; \
		make paper.bbl; \
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
		if grep -q -f ../common/latex-warnings "${DEST}.out"; then \
			echo "warnings found, running latex again"; \
			make build_run PROGRAM="${PROGRAM}" SOURCE="${SOURCE}" DEST="${DEST}"; \
			echo; echo; echo; \
		fi; \
	done

# 'make logparser.deps' correctly builds all dependencies, without running
# latex, because latex is noisy and slow.
paper.pdf: paper.deps
paper.ps:  paper.deps
paper.deps:
	touch "$@"

build/plot-%.pdf: graphs/plot-%-pdf.gpi
	cd graphs && gnuplot "../$<" || (rm -f "../$@"; false)

# Cleanup.
clean:
	rm -f *.dvi *.ps *.aux *.toc *.log *.bbl *.blg *.pdf *.out *.ist *.glg 
	rm -f *.gls *.glo *.cbk *.cit *.lof *.idx *.acn *.acr *.alg *.deps *.lot
	rm -f *.old build/*.pdf build/*.ps

veryclean: clean

check:
	chktex -I0 -q paper.tex

.PHONY: todo
todo:
	grep -n -E 'TODO|XXX' *.tex *.bib || true

xpdf: paper.pdf
	xpdf "$<" &
