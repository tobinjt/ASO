# $Id$

SHELL=bash

all: test

diff-some:
	diff -u warnings-some-working warnings-some; diff -I ^# -u state-some-working state-some

copy.working-some:
	cp -p warnings-some warnings-some-working
	cp -p state-some    state-some-working

diff:
	diff -u warnings-working warnings; diff -I ^# -u state-working state

copy.working:
	cp -p warnings warnings-working
	cp -p state    state-working

test: test.20070616.gz

test-list:
	# We need to double escape the $, otherwise the submake will clobber it.
	make INPUT='$$$$( < logs-list )'  STATE='"state-list"'    OUTPUT='"warnings-list"'    TIMING='"timing-list"'	test-real

test-some:
	# We need to double escape the $, otherwise the submake will clobber it.
	make INPUT='$$$$( < logs-some )'  STATE='"state-some"'    OUTPUT='"warnings-some"'    TIMING='"timing-some"'	test-real

test.%: ../../../../logs/mail.log-%
	make INPUT='"$<"'                 STATE='"state"'         OUTPUT='"warnings"'         TIMING='"timing"'			test-real

test-real:
	date; perl logparser --year 2007 --skip_inserting_results --out-statefile ${STATE} --individual-state-files --timing-data ${TIMING} ${INPUT} 2> ${OUTPUT}; date

../sql/create-tables-sqlite3-generated.sql: ../ASO/DB.pm ../ASO/DB/Connection.pm ../ASO/DB/Result.pm ../ASO/DB/Rule.pm ../ASO/DB/ClusterGroup.pm
	(cd ../sql && perl make_schema > "$@")

db: ../sql/create-tables-sqlite3-generated.sql
	(cd ../sql/ && rm -f db.sq3 && perl setup-database create-tables-sqlite3-generated.sql populate-cluster-groups.sql populate-rules.sql)
	sqlite3 ../sql/db.sq3 'select name, regex from rules where regex not like "^%$$"';

db-clean:
	(cd ../sql/ && perl setup-database cleanup.sql)

# A full profile run on one logfile takes upwards of an hour, blocking any
# development during that time.  Create a copy of the directories required and
# do the profiling there to allow work to continue.
PROFILE_TEMP=../../profile_temp
profile:
	rm -rf "${PROFILE_TEMP}"
	mkdir -p "${PROFILE_TEMP}"
	tar cf - ../logparser ../ASO ../sql | tar xf - -C "${PROFILE_TEMP}"
	make -C "${PROFILE_TEMP}/logparser" profile2

profile2:
	echo "profiling started"; date
	echo "This will take over half an hour"
	for profile in Profile DProf SmallProf Cover; do    \
		make db;										\
		make "profile.$$profile";                       \
		mv "warnings" "warnings.$$profile";             \
		mv "state" "state.$$profile";                   \
	done
	echo "profiling ended"; date

profile.Profile:
	# Devel::Profile; see prof.out and prof.out.startup
	# Running time is about 300% of normal.
	PERL5OPT=-d:Profile PERL_PROFILE_SAVETIME=15 make test

# We need this for Windows
DPROFPP=dprofpp
profile.DProf.stats:
	# Process tmon.out in various ways
	# This has a running time of roughly 400% of make test
	time ${DPROFPP} -l > ${DPROF_OUT}.by-calls
	# This has a running time of roughly 200% of make test
	time ${DPROFPP}    > ${DPROF_OUT}.top-15
	# This has a running time of roughly 400% of make test
	time ${DPROFPP} -S > ${DPROF_OUT}.call-tree-merged
	# This has a running time of roughly 200% of make test
	time ${DPROFPP} -v > ${DPROF_OUT}.by-avg-time

profile.DProf:
	# Devel::DProf; use dprofpp to do something useful with tmon.out
	# Running time is about 150% of normal.
	PERL5OPT=-d:DProf make test
	DPROF_OUT=dprof make profile.DProf.stats

profile.SmallProf:
	# Devel::SmallProf; sort -k 2nr,2 smallprof.out | less
	# Running time is about 2000% of normal.
	PERL5OPT=-d:SmallProf make test

cover: profile.Cover

profile.Cover:
	# DeveL::Cover; generates coverage reports.
	if [ -d cover_db ] ; then cover -delete; fi
	PERL5OPT=-d:Cover make test
	cover

# XXX: SUMMARY TARGETS DON'T WORK ANY MORE BECAUSE OF INDIVIDUAL STATE FILES
summary:
	make WARNINGS=warnings STATE=state summarize

summary-all:
	make WARNINGS=warnings-all STATE=state-all summarize

summary-list:
	make WARNINGS=warnings-list STATE=state-list summarize

summary-some:
	make WARNINGS=warnings-some STATE=state-some summarize

summarize:
	# Delete any lines not matching ^logparser; delete any lines not having 6
	# colons; substitute the first six colon-delimited fields with nothing.
	(echo "${WARNINGS} summary: "; sed -e '/^logparser/!d; /^\([^:]\+:\)\{6\}/!d; s/^\([^:]\+:\)\{6\} \?//' "${WARNINGS}" | sort | uniq -c | sort -n) | tee -a results
	(grep 'Starting dump of .* entries' "${STATE}") | tee -a results

unknown-summary:
	grep  '^# xxx' state-some | sort | uniq -c | sort  -n

pod-coverage:
	for package in $$( find .. -name \*.pm | sed -e 's,^../,,' -e 's,/,::,g' -e 's,.pm$$,,' ); do \
		perl -I .. -MPod::Coverage="$$package" -e 1; \
	done

todo:
	ack [X]XX . ../ASO

.PHONY: random-sample-logs-regex-check
random-sample-logs-regex-check:
	make db
	perl logparser --out-statefile /dev/null --print_matching_regex --year 2007 --parse_lines_only random-sample-logs-regex-check | diff -u random-sample-logs-regex-output -
	sqlite3 -separator ' ' ../sql/db.sq3 'select "Number of rules hit:", count(name) from rules where hits > 0;'

.PHONY: test-logs
test-logs:
	make db
	perl logparser --year 2007 --debug_results --dump_committed_connections --out-statefile test-logs.state test-logs 2> test-logs.warnings
	perl dump-database > test-logs.database-dump

all-logs:
	make db
	perl logparser --skip_inserting_results --year 2007 --debug_results --out-statefile state.all-logs-2007 --individual-state-files                                                       ../../../../logs/mail.log-2007* 2> warnings.all-logs-2007
	perl logparser --skip_inserting_results --year 2008 --debug_results --out-statefile state.all-logs-2008 --individual-state-files --in-statefile state.all-logs-2007-mail.log-20071231  ../../../../logs/mail.log-2008* 2> warnings.all-logs-2008

.PHONY: unparsed
unparsed:
	grep unparsed warnings > unparsed
	cut -f 7- -d ' ' unparsed > unparsed.stripped
	perl logs2regexs unparsed.stripped > new-regexes
	yes 'Jun 16 00:00:01 relay.cs.tcd.ie postfix/smtpd[16278]: [ID 197553 mail.info] ' | head -n $$( wc -l unparsed.stripped | awk '{print $$1}' ) | paste -d '' - unparsed.stripped > unparsed.input

test-auto-regex:
	perl logparser --year 2007 --skip_inserting_results "../../../../logs/mail.log-20070616.gz"
