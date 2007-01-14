test: test.1

test-all:
	(date; time nice --adjustment=19 perl logparser $$( < log-list )  > rejects 2> warnings; wc rejects warnings; date ) >> results 2>&1; tail -n 9 results	

test.%: ../../../../logs/mail.log.%
	(date; time nice --adjustment=19 perl logparser "$<" > rejects 2> warnings; wc rejects warnings; date ) >> results 2>&1; tail -n 9 results

db:
	( cd ../sql/; perl setup-database create-tables-sqlite3.sql populate-rules.sql )
