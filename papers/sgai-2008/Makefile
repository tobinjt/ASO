include ../common/Makefile

#paper.pdf: 
paper.deps: build/plot-action-distribution.pdf \
			build/plot-normal-filesize-numlines.pdf \
			build/plot-normal-filesize-numlines-factor.pdf \
			build/plot-hits.pdf \
			build/plot-normal-shuffle-reverse-factor.pdf \
			build/plot-normal-vs-smaller.pdf \
			build/normal-vs-smaller-percentage-increase.tex
paper.bbl: spmpsci.bst

build/plot-normal-vs-smaller.pdf: build/stats-normal-vs-smaller.txt \
									build/stats-reverse-vs-smaller.txt \
									build/stats-shuffle-vs-smaller.txt

build/normal-vs-smaller-percentage-increase.tex: build/stats-normal-vs-smaller.txt
	awk 'BEGIN { sum = 0; } { sum += $$2; } END { printf "%.3g\\%%%%\n", sum / NR }' "$<" > "$@" || (rm -f "$@"; false)
