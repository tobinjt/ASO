all: test summary

test: test.1

test-all:
	(date; time nice --adjustment=19 perl logparser $$( < log-list )  > rejects.all 2> warnings.all; wc rejects.all warnings.all; date ) >> results 2>&1; tail -n 9 results	

test.%: ../../../../logs/mail.log.%
	(date; time nice --adjustment=19 perl logparser "$<" > rejects 2> warnings; wc rejects warnings; date ) >> results 2>&1; tail -n 9 results

db:
	( cd ../sql/; perl setup-database create-tables-sqlite3.sql populate-rules.sql )

# A full profile run on one logfile takes upwards of an hour, blocking any
# development during that time.  Create a copy of the directories required and
# do the profiling there to allow work to continue.
PROFILE_TEMP=../../profile_temp
profile:
	rm -rf "${PROFILE_TEMP}"
	mkdir -p "${PROFILE_TEMP}"
	tar cf - .. | tar xf - -C "${PROFILE_TEMP}"
	make -C "${PROFILE_TEMP}" profile2

profile2:
	echo "profiling started"; date
	echo "This will take over an hour - 70 minutes or so last time."
	for profile in Profile DProf DProfLB SmallProf GraphVizProf; do \
		make "profile.$$profile"; \
	done
	echo "profiling ended"; date

profile.Profile:
	# Devel::Profile; see prof.out and prof.out.startup
	# Running time is about 400% of normal.
	PERL5OPT=-d:Profile PERL_PROFILE_SAVETIME=15 make test

profile.DProf:
	# Devel::DProf; use dprofpp to do something useful with tmon.out
	# Running time is about 200% of normal.
	# Can't figure out whether this works or not.
	PERL5OPT=-d:DProf make test

profile.DProfLB:
	# Devel::DProfLB; use dprofpp to do something useful with tmonlb.out
	# Running time is about 600% of normal.
	PERL_DPROF_OUT_FILE_NAME=tmonlb.out PERL5OPT=-d:DProfLB make test

profile.SmallProf:
	# Devel::SmallProf; sort -k 2nr,2 smallprof.out | less
	# Running time is about 2200% of normal.
	PERL5OPT=-d:SmallProf make test

profile.CallStack:
	# DeveL::CallStack; do something with callstack.out
	# Running time is about 1% of normal.
	# This doesn't see to work, it clobbers @_.
	PERL5OPT=-d:CallStack make test

profile.GraphVizProf:
	# Devel::GraphVizProf; make a graphviz call graph.
	# Running time is about 2200% of normal.
	PERL5OPT=-d:GraphVizProf REDIRECT_STDOUT=profile.dot make test
	# See profile.png for the call graph.
	# This failed last time.
	dot -Tpng -o profile.png profile.dot

summary:
	grep ^logparser warnings | cut -d ' ' -f 4-9 | sort | uniq -c | sort -n
