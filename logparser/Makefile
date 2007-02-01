test: test.1

test-all:
	(date; time nice --adjustment=19 perl logparser $$( < log-list )  > rejects.all 2> warnings.all; wc rejects.all warnings.all; date ) >> results 2>&1; tail -n 9 results	

test.%: ../../../../logs/mail.log.%
	(date; time nice --adjustment=19 perl logparser "$<" > rejects 2> warnings; wc rejects warnings; date ) >> results 2>&1; tail -n 9 results

db:
	( cd ../sql/; perl setup-database create-tables-sqlite3.sql populate-rules.sql )

profile:
	# Devel::Profile; see prof.out and prof.out.startup
	PERL5OPT=-d:Profile PERL_PROFILE_SAVETIME=15 make test
	# Devel::DProf; use dprofpp to do something useful with tmon.out
	PERL5OPT=-d:DProf make test
	# Devel::SmallProf; sort -k 2nr,2 smallprof.out | less
	PERL5OPT=-d:SmallProf make test
