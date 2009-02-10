#!/usr/bin/env perl
# vim: set textwidth=10000 :

# $Id$

use strict;
use warnings;

use lib q{..};
use Data::Dumper;
use ASO::Parser;

my $parser = ASO::Parser->new({
    data_source => q{dbi:SQLite:dbname=../sql/db.sq3}
});

my $line = q{143C0F3E27: to=<arash@dcs.qmul.ac.uk>, relay=mail.dcs.qmul.ac.uk[138.37.95.139]:25, delay=4.4, delays=0.05/0.02/3.3/1.1, dsn=4.0.0, status=deferred (host mail.dcs.qmul.ac.uk[138.37.95.139] said: 451-response to "RCPT TO:<fg07participants-bounces+arash=dcs.qmul.ac.uk@cs.tcd.ie>" from smtp.cs.tcd.ie [134.226.32.56] was: 450 4.2.0 <fg07participants-bounces+arash=dcs.qmul.ac.uk@cs.tcd.ie>: Recipient address rejected: Greylisted, see http://postgrey.schweikert.ch/help/cs.tcd.ie.html 451-Could not complete sender verify callout for 451-<fg07participants-bounces+arash=dcs.qmul.ac.uk@cs.tcd.ie>. 451-The mail server(s) for the domain may be temporarily unreachable, or 451-they may be permanently unreachable from this server. In the latter case, 451-you need to change the address or create an MX record for its domain 451-if it is supposed to be generally accessible from the Internet. 451 Talk to your mail administrator for details. (in reply to RCP};
my $regex = q{^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<(__RECIPIENT__)>,)? relay=(__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__,\s)?status=deferred \(host (__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\] said: (__SMTP_CODE__)(__DATA__.*451.Could not complete sender verify callout for .*)$};
my $regex_filtered = ASO::Parser::filter_regex($parser, $regex);
warn $line, qq{\n};
warn $regex_filtered, qq{\n};
if ($line =~ m/$regex_filtered/) {
    warn qq{success\n};
    warn qq{\$`: -->>$`<<--\n};
    warn qq{\$&: -->>$&<<--\n};
    warn qq{\$': -->>$'<<--\n};
    warn q{%+: }, Dumper(\%+);
} else {
    warn qq{failure\n};
}
