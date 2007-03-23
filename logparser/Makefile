# $Id$

# Use bash so we get a nice time, rather than GNU time, which has horrible
# output.
SHELL=bash

all: test summary

diff:
	diff -u warnings.working warnings
	diff -u rejects.working rejects

test: test.1

test-all:
	((date; nice --adjustment=19 time -v ${SHELL} -c 'perl logparser $$( < log-list )  > rejects.all 2> warnings.all'; wc rejects.all warnings.all; date ) 2>&1 ) | tee -a results

test.%: ../../../../logs/mail.log.%
	((date; nice --adjustment=19 time -v ${SHELL} -c 'perl logparser "$<"              > rejects     2> warnings';     wc rejects     warnings;     date ) 2>&1 ) | tee -a results

db:
	( cd ../sql/; perl setup-database create-tables-sqlite3.sql populate-rules.sql )

db-clean:
	( cd ../sql/; perl setup-database cleanup.sql )

# A full profile run on one logfile takes upwards of an hour, blocking any
# development during that time.  Create a copy of the directories required and
# do the profiling there to allow work to continue.
PROFILE_TEMP=../../profile_temp
profile:
	rm -rf "${PROFILE_TEMP}"
	mkdir -p "${PROFILE_TEMP}"
	tar cf - .. | tar xf - -C "${PROFILE_TEMP}"
	make -C "${PROFILE_TEMP}/logparser" profile2

profile2:
	echo "profiling started"; date
	echo "This will take over an hour - 70 minutes or so last time."
	for profile in Profile DProf SmallProf Cover; do \
		make "profile.$$profile"; 				\
		mv "warnings" "warnings.$$profile";		\
		mv "rejects" "rejects.$$profile";		\
	done
	echo "profiling ended"; date

profile.Profile:
	# Devel::Profile; see prof.out and prof.out.startup
	# Running time is about 300% of normal.
	PERL5OPT=-d:Profile PERL_PROFILE_SAVETIME=15 make test

# We need this for Windows
DPROFPP=dprofpp.bat
profile.DProf.stats:
	# Process tmon.out in various ways
	# This has a running time of roughly 400% of make test
	time nice --adjustment=19 ${DPROFPP} -l > ${DPROF_OUT}.by-calls
	# This has a running time of roughly 200% of make test
	time nice --adjustment=19 ${DPROFPP}    > ${DPROF_OUT}.top-15
	# This has a running time of roughly 400% of make test
	time nice --adjustment=19 ${DPROFPP} -S > ${DPROF_OUT}.call-tree-merged
	# This has a running time of roughly 200% of make test
	time nice --adjustment=19 ${DPROFPP} -v > ${DPROF_OUT}.by-avg-time

profile.DProf:
	# Devel::DProf; use dprofpp to do something useful with tmon.out
	# Running time is about 150% of normal.
	PERL5OPT=-d:DProf make test
	DPROF_OUT=dprof make profile.DProf.stats

profile.DProfLB:
	# Devel::DProfLB; use dprofpp to do something useful with tmonlb.out
	# Running time is about 600% of normal.
	# dprofpp doesn't do anything useful with tmonlb.out, dunno why,
	PERL_DPROF_OUT_FILE_NAME=tmonlb.out PERL5OPT=-d:DProfLB make test
	DPROFPP_OPTS=tmonlb.out DPROF_OUT=dproflb make profile.DProf.stats

profile.SmallProf:
	# Devel::SmallProf; sort -k 2nr,2 smallprof.out | less
	# Running time is about 2000% of normal.
	PERL5OPT=-d:SmallProf make test

profile.Cover:
	# DeveL::Cover; generates coverage reports.
	PERL5OPT=-d:Cover make test
	perl cover

profile.CallStack:
	# DeveL::CallStack; do something with callstack.out
	# Running time is about 1% of normal.
	# This doesn't see to work, it clobbers @_.
	PERL5OPT=-d:CallStack make test

profile.GraphVizProf:
	# Devel::GraphVizProf; make a graphviz call graph.
	# Running time is about 2000% of normal.
	PERL5OPT=-d:GraphVizProf REDIRECT_STDOUT=profile.dot make test
	# See profile.png for the call graph.
	# This failed last time.
	dot -Tpng -o profile.png profile.dot

summary:
	( echo "warning summary: "; grep ^logparser warnings | cut -d ' ' -f 4-9 | sort | uniq -c | sort -n ) | tee -a results
	( echo -n "rejects: "; grep -c queueid: rejects ) | tee -a results

summary-all:
	( echo "warning.all summary: "; grep ^logparser warnings.all | cut -d ' ' -f 4-9 | sort | uniq -c | sort -n ) | tee -a results
	( echo -n "rejects.all: "; grep -c queueid: rejects.all ) | tee -a results
