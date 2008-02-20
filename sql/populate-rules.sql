-- vim: set foldmethod=marker textwidth=1000 :
-- $Id$

DELETE FROM rules;

-- SMTPD CONNECT RULES {{{1
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('client connection', 'A client has connected',
        'postfix/smtpd',
        '^connect from (__HOSTNAME__)\[(__IP__)\]$',
        '',
        'client_hostname = 1, client_ip = 2',
        'server_hostname = localhost, server_ip = 127.0.0.1',
        'CONNECT',
        0,
        'INFO'
);

-- }}}

-- SMTPD DISCONNECT RULES {{{1
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('client disconnection', 'The client has disconnected cleanly',
        'postfix/smtpd',
        '^disconnect from __HOSTNAME__\[__IP__\]$',
        '',
        '',
        'DISCONNECT',
        0,
        'INFO'
);

-- }}}

-- SMTPD ERROR RULES {{{1
-- These cause the mail to be discarded.
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, action, queueid, priority, postfix_action)
    VALUES('Timeout after DATA command from client', 'Timeout reading data from the client, mail will be discarded',
        'postfix/smtpd',
        '^timeout after DATA from (__HOSTNAME__)\[(__IP__)\]$',
        '',
        'client_hostname = 1, client_ip = 2',
        'sender = unknown, recipient = unknown, smtp_code = unknown',
        'TIMEOUT',
        0,
        5,
        'DISCARDED'
);

INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, action, queueid, priority, postfix_action)
    VALUES('Lost connection after DATA command from client', 'Lost connection reading data from the client, mail will be discarded',
        'postfix/smtpd',
        '^lost connection after DATA from (__HOSTNAME__)\[(__IP__)\]$',
        '',
        'client_hostname = 1, client_ip = 2',
        'sender = unknown, recipient = unknown, smtp_code = unknown',
        'TIMEOUT',
        0,
        5,
        'DISCARDED'
);

-- warning: 03F6E38CA: queue file size limit exceeded
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, action, queueid, priority, postfix_action)
    VALUES('Client exceeded the maximum mail size', 'Client exceeded the maximum mail size, mail will be discarded',
        'postfix/smtpd',
        '^warning: __QUEUEID__: queue file size limit exceeded$',
        '',
        '',
        'sender = unknown, recipient = unknown, smtp_code = unknown',
        'MAIL_TOO_LARGE',
        0,
        5,
        'DISCARDED'
);

-- }}}

-- SMTPD IGNORE RULES {{{1
-- These will always be followed by a disconnect line, as matched above
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('lost connection', 'Client disconnected uncleanly',
        'postfix/smtpd',
        '^lost connection after __SHORT_CMD__ from __HOSTNAME__\[__IP__\]$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Timeout reading reply', 'Timeout reading reply from client',
        'postfix/smtpd',
        '^timeout after __SHORT_CMD__ from __HOSTNAME__\[__IP__\]$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Too many errors', 'The client has made so many errors postfix has disconnected it',
        'postfix/smtpd',
        '^too many errors after (?:\w+|END-OF-MESSAGE) from __HOSTNAME__\[__IP__\]$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- gethostbyaddr: eta.routhost.com. != 66.98.227.100
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Mismatched DNS warning', 'A warning about mismatched DNS',
        'postfix/smtpd',
        '^gethostbyaddr: __HOSTNAME__ != __IP__$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- Other lines we want to ignore
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Warning', 'Warnings of some sort',
        'postfix/smtpd',
        '^warning: .*$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Table changed', 'A lookup table has changed, smtpd is quitting',
        'postfix/smtpd',
        '^table .* has changed -- restarting$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Fatal error', 'Fatal error of some sort',
        'postfix/smtpd',
        '^fatal: .*$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- }}}

-- SMTPD FATAL RULES {{{1

-- fatal: watchdog timeout
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, priority)
    VALUES('Watchdog timeout', 'Watchdog timed out; kill the active connection.',
        'postfix/smtpd',
        '^fatal: watchdog timeout$',
        '',
        '',
        'SMTPD_WATCHDOG',
        0,
        'IGNORED',
        5
);

-- }}}


-- SMTPD REJECT RULES {{{1
-- __RESTRICTION_START__ has four capturing parentheses, so *_cols and back 
-- references start at 5 not 1.

-- <munin@cs.tcd.ie>: Recipient address rejected: User unknown in local recipient table; from=<> to=<munin@cs.tcd.ie> proto=ESMTP helo=<lg12x22.cs.tcd.ie>
-- <hienes@cs.tcd.ie>: Recipient address rejected: User unknown in local recipient table; from=<BrooksPool@rowcmi.org> to=<hienes@cs.tcd.ie> proto=ESMTP helo=<PETTERH?DNEB?>
-- <rt@cs.tcd.ie>: Recipient address rejected: User unknown; from=<Leynard563@aikon-trading.com> to=<rt@cs.tcd.ie> proto=ESMTP helo=<imx1.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Unknown recipient', 'The recipient address is unknown on our system',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: User unknown(?: in \w+ \w+ table)?; from=<(__SENDER__)> to=<\5> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 5, sender = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'reject_unlisted_recipient'
);

-- <  sharyn.davies@cs.tcd.ie>: Recipient address rejected: User unknown in local recipient table; from=<newsletter@globalmediaserver.com> to=<??sharyn.davies@cs.tcd.ie> proto=ESMTP helo=<mail1.globalmediaserver.com>
-- <greedea@cs.tcd.ie>: Recipient address rejected: User unknown in local recipient table; from=<<>@inprima.locaweb.com.br> to=<greedea@cs.tcd.ie> proto=ESMTP helo=<hm22.locaweb.com.br>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, priority, postfix_action, restriction_name)
    VALUES('A weird address was rejected', 'A weird address was rejected by Postfix, and may have been escaped',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(.*?)>: Recipient address rejected: User unknown in \w+ \w+ table; from=<(.*?)> to=<.*?> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 5, sender = 6',
        'helo = 7',
        'REJECTION',
        1,
        -1,
        'REJECTED',
        'reject_unlisted_recipient'
);

-- <munin@cs.tcd.ie>: Sender address rejected: User unknown in local recipient table; from=<munin@cs.tcd.ie> to=<john.tobin@cs.tcd.ie> proto=ESMTP helo=<lg12x36.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Unknown sender', 'The sender address is unknown on our system',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: User unknown in \w+ \w+ table; from=<\5> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 6, sender = 5',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'reject_unlisted_sender'
);

-- <                      >: Sender address rejected: User unknown in local recipient table; from=<??????????????????????> to=<emcmanus@cs.tcd.ie> proto=SMTP helo=<mail.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, priority, postfix_action, restriction_name)
    VALUES('Unknown sender (escaped)', 'The sender address is unknown on our system (postfix escaped it)',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(.*)>: Sender address rejected: User unknown in \w+ \w+ table; from=<.*> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 6, sender = 5',
        'helo = 7',
        'REJECTION',
        1,
        -1,
        'REJECTED',
        'reject_unlisted_sender'
);

-- <ocalladw@toad.toad>: Sender address rejected: Domain not found; from=<ocalladw@toad.toad> to=<submit@bugs.gnome.org> proto=SMTP helo=<toad>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Unknown sender domain', 'We do not accept mail from unknown domains',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Domain not found; from=<\5> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 6, sender = 5',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'reject_unknown_sender_domain'
);

-- <                     @thai.co.th>: Sender address rejected: Domain not found; from=<?????????????????????@thai.co.th> to=<faircloc@cs.tcd.ie> proto=SMTP helo=<mail.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, priority, postfix_action, restriction_name)
    VALUES('Unknown sender domain (escaped)', 'We do not accept mail from unknown domains (postfix partially escaped it)',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(.*)>: Sender address rejected: Domain not found; from=<.*> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 6, sender = 5',
        'helo = 7',
        'REJECTION',
        1,
        -1,
        'REJECTED',
        'reject_unknown_sender_domain'
);

-- <stephen@tjbx.org>: Recipient address rejected: Domain not found; from=<4sdcsaz@nbsanjiang.com> to=<stephen@tjbx.org> proto=ESMTP helo=<nbsanjiang.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Unknown recipient domain', 'We do not accept mail for unknown domains',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Domain not found; from=<(__SENDER__)> to=<\5> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 5, sender = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'reject_unknown_recipient_domain'
);

-- Service unavailable; Client host [190.40.116.202] blocked using sbl-xbl.spamhaus.org; from=<taliaferraearl@blackburn-green.com> to=<amjudge@dsg.cs.tcd.ie> proto=SMTP helo=<blackburn-green.com>
-- Service unavailable; Client host [211.212.156.4] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/query/bl?ip=211.212.156.4; from=<lucia@abouttimemag.com> to=<amjudge@dsg.cs.tcd.ie> proto=SMTP helo=<abouttimemag.com>
-- Service unavailable; Client host [66.30.84.174] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/query/bl?ip=66.30.84.174; from=<DianaBoykin@movemail.com> to=<Paolo.Rosso@cs.tcd.ie> proto=SMTP helo=<b100mng10bce9ob.hsd1.ma.comcast.net.>
-- Service unavailable; Client host [210.236.32.153] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/SBL/sbl.lasso?query=SBL47877; from=<euyery@linuxmail.org> to=<vinny.cahill@cs.tcd.ie> proto=SMTP helo=<eworuetyberiyneortmweprmuete57197179680.com>
-- Service unavailable; Client host [204.14.1.123] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/SBL/sbl.lasso?query=SBL27197 / http://www.spamhaus.org/SBL/sbl.lasso?query=SBL47903; from=<tia@baraskaka.com> to=<vjcahill@dsg.cs.tcd.ie> proto=SMTP helo=<customer.optindirectmail.123.sls-hosting.com>
-- Service unavailable; Client host [82.119.202.142] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/query/bl?ip=82.119.202.142; from=<001topzine-hypertext@123point.net> to=<ecdlf@cs.tcd.ie.> proto=ESMTP helo=<cs.tcd.ie.>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Blacklisted by SpamHaus SBL-XBL', 'The client IP address is blacklisted by SpamHaus SBL-XBL',
        'postfix/smtpd',
        '^__RESTRICTION_START__ Service unavailable; Client host (?>\[(__IP__)\]) blocked using sbl-xbl.spamhaus.org;(?:((?:(?:(?: http://www.spamhaus.org/SBL/sbl.lasso\?query=\w+)|(?: http://www.spamhaus.org/query/bl\?ip=\5))(?: /)?)*);)? (?>from=<(__SENDER__)>) to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 8, data = 6, sender = 7',
        'helo = 9, client_ip = 5',
        'REJECTION',
        1,
        'REJECTED',
        'reject_rbl_client'
);

-- Service unavailable; Client host [220.104.147.28] blocked using zen.spamhaus.org; http://www.spamhaus.org/query/bl?ip=220.104.147.28; from=<sakuran_b0@yahoo.co.jp> to=<stephen.barrett@cs.tcd.ie> proto=SMTP helo=<eruirutkjshfk.com>
-- Service unavailable; Client host [201.231.83.38] blocked using zen.spamhaus.org; from=<contact@digitalav.com> to=<gerry@cs.tcd.ie> proto=SMTP helo=<38-83-231-201.fibertel.com.ar>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Blacklisted by SpamHaus Zen', 'The client IP address is blacklisted by SpamHaus Zen',
        'postfix/smtpd',
        '^__RESTRICTION_START__ Service unavailable; Client host (?>\[(__IP__)\]) blocked using zen.spamhaus.org; (?:(?>(http://www.spamhaus.org/query/bl\?ip=\5)); )?from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 8, data = 6, sender = 7',
        'helo = 9, client_ip = 5',
        'REJECTION',
        1,
        'REJECTED',
        'reject_rbl_client'
);

-- Service unavailable; Client host [80.236.27.105] blocked using list.dsbl.org; http://dsbl.org/listing?80.236.27.105; from=<mrnpftjx@pacbell.net> to=<tom.irwin@cs.tcd.ie> proto=SMTP helo=<ip-105.net-80-236-27.asnieres.rev.numericable.fr>
-- Service unavailable; Client host [82.159.196.151] blocked using list.dsbl.org; from=<vrespond@cima.com.my> to=<irwin@cs.tcd.ie> proto=SMTP helo=<pc.bcs>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Blacklisted by DSBL', 'The client IP address is blacklisted by DSBL',
        'postfix/smtpd',
        '^__RESTRICTION_START__ Service unavailable; Client host (?>\[(__IP__)\]) blocked using list.dsbl.org; (?:(?>(http://dsbl.org/listing\?\5);) )?from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 8, data = 6, sender = 7',
        'helo = 9, client_ip = 5',
        'REJECTION',
        1,
        'REJECTED',
        'reject_rbl_client'
);

-- Service unavailable; Client host [148.243.214.52] blocked using relays.ordb.org; This mail was handled by an open relay - please visit <http://ORDB.org/lookup/?host=148.243.214.52>; from=<cw-chai@umail.hinet.net> to=<webmaster@cs.tcd.ie> proto=ESMTP helo=<sicomnet.edu.mx>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Blacklisted by ordb.org', 'The client IP address is blacklisted by ordb.org',
        'postfix/smtpd',
        '^__RESTRICTION_START__ Service unavailable; Client host (?>\[(__IP__)\]) blocked using relays.ordb.org; (?>(This mail was handled by an open relay - please visit <http://ORDB.org/lookup/\?host=\5>);) from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 8, data = 6, sender = 7',
        'helo = 9, client_ip = 5',
        'REJECTION',
        1,
        'REJECTED',
        'reject_rbl_client'
);

-- Service unavailable; Client host [60.22.99.9] blocked using cbl.abuseat.org; Blocked - see http://cbl.abuseat.org/lookup.cgi?ip=60.22.99.9; from=<pegbxbsusiiao@cowboyart.net> to=<daokeeff@cs.tcd.ie> proto=SMTP helo=<cowboyart.net>
-- Service unavailable; Client host [90.194.116.50] blocked using cbl.abuseat.org; from=<lazauear@appleleasing.com> to=<noctor@cs.tcd.ie> proto=SMTP helo=<appleleasing.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Blacklisted by CBL', 'The client IP address is blacklisted by CBL',
        'postfix/smtpd',
        '^__RESTRICTION_START__ Service unavailable; Client host (?>\[(__IP__)\]) blocked using cbl.abuseat.org;(?>( Blocked - see http://cbl.abuseat.org/lookup.cgi\?ip=\5);)? from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 8, data = 6, sender = 7',
        'helo = 9, client_ip = 5',
        'REJECTION',
        1,
        'REJECTED',
        'reject_rbl_client'
);

-- <31.pool80-103-5.dynamic.uni2.es[80.103.5.31]>: Client host rejected: Greylisted, see http://isg.ee.ethz.ch/tools/postgrey/help/dsg.cs.tcd.ie.html; from=<iqxrgomtl@purinmail.com> to=<skenny@dsg.cs.tcd.ie> proto=SMTP helo=<31.pool80-103-5.dynamic.uni2.es>
-- <mail.saraholding.com.sa[212.12.166.254]>: Client host rejected: Greylisted, see http://isg.ee.ethz.ch/tools/postgrey/help/cs.tcd.ie.html; from=<lpty@[212.12.166.226]> to=<colin.little@cs.tcd.ie> proto=ESMTP helo=<mail.saraholding.com.sa>
-- <flow.helderhosting.nl[82.94.236.142]>: Client host rejected: Greylisted, see http://isg.ee.ethz.ch/tools/postgrey/help/cs.tcd.ie.html; from=<www-data@info+spam@helderhosting.nl> to=<siobhan.clarke@cs.tcd.ie> proto=SMTP helo=<flow.helderhosting.nl>
-- <host10-102.pool82104.interbusiness.it[82.104.102.10]>: Client host rejected: Greylisted, see http://postgrey.schweikert.ch/help/cs.tcd.ie.html; from=<Tania@nis-portal.de> to=<mite-00@cs.tcd.ie> proto=SMTP helo=<host10-102.pool82104.interbusiness.it>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Greylisted', 'Client greylisted; see http://www.greylisting.org/ for more details',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__HOSTNAME__)\[(__IP__)\]>: Client host rejected: Greylisted, see (http://postgrey.schweikert.ch/help/[^\s]+|http://isg.ee.ethz.ch/tools/postgrey/help/[^\s]+); from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 9, data = 7, sender = 8',
        'helo = 10, client_hostname = 5, client_ip= 6',
        'REJECTION',
        1,
        'REJECTED',
        'check_policy_service'
);

-- NOQUEUE: reject: RCPT from hm22.locaweb.com.br[200.234.196.44]: 450 4.7.1 <hm22.locaweb.com.br[200.234.196.44]>: Client host rejected: Greylisted, see http://isg.ee.ethz.ch/tools/postgrey/help/cs.tcd.ie.html; from=<<>@inprima.locaweb.com.br> to=<mary.sharp@cs.tcd.ie> proto=ESMTP helo=<hm22.locaweb.com.br>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, priority, restriction_name)
    VALUES('Greylisted (weird addresses)', 'Client greylisted; see http://www.greylisting.org/ for more details (weird addresses)',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__HOSTNAME__)\[(__IP__)\]>: Client host rejected: Greylisted, see (http://postgrey.schweikert.ch/help/[^\s]+|http://isg.ee.ethz.ch/tools/postgrey/help/[^\s]+); from=<(.*?)> to=<(.*?)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 9, data = 7, sender = 8',
        'helo = 10, client_hostname = 5, client_ip= 6',
        'REJECTION',
        1,
        'REJECTED',
        -1,
        'check_policy_service'
);

-- <nicholas@seaton.biz>: Sender address rejected: Address uses MX in loopback address space (127.0.0.0/8); from=<nicholas@seaton.biz> to=<gillian.long@cs.tcd.ie> proto=ESMTP helo=<friend>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Sender MX in loopback address space', 'The MX for sender domain is in loopback address space, so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in loopback address space \(127.0.0.0/8\); from=<\5> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 6, sender = 5',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_sender_mx_access'
);

-- <root@inet.microlins.com.br>: Sender address rejected: Address uses MX in private address space (172.16.0.0/12); from=<root@inet.microlins.com.br> to=<stephen.farrell@cs.tcd.ie> proto=ESMTP helo=<inet.microlins.com.br>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Sender MX in private address space (172.16.0.0/12)', 'The MX for sender domain is in private address space (172.16.0.0/12), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in private address space \(172.16.0.0/12\); from=<\5> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 6, sender = 5',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_sender_mx_access'
);

-- NOQUEUE: reject: RCPT from unknown[123.190.117.163]: 550 5.7.1 <cji1031@scourt.go.kr>: Recipient address rejected: Address uses MX in private address space (172.16.0.0/12); from=<qm73z1@paran.com> to=<cji1031@scourt.go.kr> proto=SMTP helo=<123.190.117.163>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Recipient MX in private address space (172.16.0.0/12)', 'The MX for recipient domain is in private address space (172.16.0.0/12), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Address uses MX in private address space \(172.16.0.0/12\); from=<(__SENDER__)> to=<\5> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 5, sender = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_recipient_mx_access'
);

-- <aaholi@web009.ahp01.lax.affinity.com>: Sender address rejected: Address uses MX in private address space (127.16.0.0/12); from=<aaholi@web009.ahp01.lax.affinity.com> to=<luzs@cs.tcd.ie> proto=ESMTP helo=<ams006.lax.affinity.com> 
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Sender MX in private address space (127.16.0.0/12)', 'The MX for sender domain is in private address space (127.16.0.0/12), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in private address space \(127.16.0.0/12\); from=<\5> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 6, sender = 5',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_sender_mx_access'
);

-- <hlhbs@china.org.cn>: Recipient address rejected: Address uses MX in private address space (127.16.0.0/12); from=<1221q5@chinachewang.com> to=<hlhbs@china.org.cn> proto=ESMTP helo=<chinachewang.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Recipient MX in private address space (127.16.0.0/12)', 'The MX for recipient domain is in private address space (127.16.0.0/12), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Address uses MX in private address space \(127.16.0.0/12\); from=<(__SENDER__)> to=<\5> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 5, sender = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_recipient_mx_access'
);

-- <aeneasdecathlon@rotnot.com>: Sender address rejected: Address uses MX in private address space (192.168.0.0/16); from=<aeneasdecathlon@rotnot.com> to=<MCCARTHY@CS.tcd.ie> proto=ESMTP helo=<vms1.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Sender MX in private address space (192.168.0.0/16)', 'The MX for sender domain is in private address space (192.168.0.0/16), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in private address space \(192.168.0.0/16\); from=<\5> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 6, sender = 5',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_sender_mx_access'
);

-- <showh@tdt3.com.tw>: Recipient address rejected: Address uses MX in private address space (192.168.0.0/16); from=<zsl.gzrza@yahoo.com.tw> to=<showh@tdt3.com.tw> proto=SMTP helo=<134.226.32.56>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Recipient MX in private address space (192.168.0.0/16)', 'The MX for Recipient domain is in private address space (192.168.0.0/16), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Address uses MX in private address space \(192.168.0.0/16\); from=<(__SENDER__)> to=<\5> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 5, sender = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_recipient_mx_access'
);

-- <acornascription@rot.wartesaal.darktech.org>: Sender address rejected: Address uses MX in private address space (10.0.0.0/8); from=<acornascription@rot.wartesaal.darktech.org> to=<gap@cs.tcd.ie> proto=ESMTP helo=<xmx1.tcd.ie>
-- <artlesslyLumi re's@wildsecretary.com>: Sender address rejected: Address uses MX in private address space (10.0.0.0/8); from=<artlesslyLumi?re's@wildsecretary.com> to=<carol.osullivan@cs.tcd.ie> proto=ESMTP helo=<home.tvscable.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Sender MX in private address space (10.0.0.0/8)', 'The MX for sender domain is in private address space (10.0.0.0/8), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in private address space \(10.0.0.0/8\); from=<.*?> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 6, sender = 5',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_sender_mx_access'
);

-- <mactusqdx@wartesaal.darktech.org>: Recipient address rejected: Address uses MX in private address space (10.0.0.0/8); from=<bartel@integramed.com> to=<mactusqdx@wartesaal.darktech.org> proto=SMTP helo=<integramed.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Recipient MX in private address space (10.0.0.0/8)', 'The MX for recipient domain is in private address space (10.0.0.0/8), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Address uses MX in private address space \(10.0.0.0/8\); from=<(__SENDER__)> to=<\5> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 5, sender = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_recipient_mx_access'
);

-- <banihashemian@modares.ac.ir>: Sender address rejected: Address uses MX in local address space (169.254.0.0/16); from=<banihashemian@modares.ac.ir> to=<Elisa.Baniassad@cs.tcd.ie> proto=ESMTP helo=<mail-relay1.cs.ubc.ca>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Sender MX in "local" address space (169.254.0.0/16)', 'The MX for sender domain is in "local" address space (169.254.0.0/16), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in local address space \(169.254.0.0/16\); from=<\5> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 6, sender = 5',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_sender_mx_access'
);

-- <sble@corn.kiev.ua>: Recipient address rejected: Address uses MX in "this" address space (0.0.0.0/8); from=<-sol@hinet.net> to=<sble@corn.kiev.ua> proto=SMTP helo=<125-225-33-196.dynamic.hinet.net>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Recipient MX in "this" address space (0.0.0.0/8)', 'The MX for recipient domain is in "this" address space (0.0.0.0/8), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Address uses MX in "this" address space \(0.0.0.0/8\); from=<(__SENDER__)> to=<\5> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 5, sender = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_sender_mx_access'
);

-- <lisa@telephonebooth.com>: Sender address rejected: Address uses MX in "this" address space (0.0.0.0/8); from=<lisa@telephonebooth.com> to=<francis.neelamkavil@cs.tcd.ie> proto=SMTP helo=<localhost>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Sender MX in "this" address space (0.0.0.0/8)', 'The MX for sender domain is in "this" address space (0.0.0.0/8), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in "this" address space \(0.0.0.0/8\); from=<\5> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 6, sender = 5',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_sender_mx_access'
);

-- <af53eec9@verpiss-dich.de>: Recipient address rejected: Address uses MX in loopback address space (127.0.0.0/8); from=<cbsrlkhaigye@allsaintsfan.com> to=<af53eec9@verpiss-dich.de> proto=SMTP helo=<127.0.0.1>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Recipient MX in loopback address space (127.0.0.0/8)', 'The MX for recipient domain is in loopback address space (127.0.0.0/8), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Address uses MX in loopback address space \(127.0.0.0/8\); from=<(__SENDER__)> to=<\5> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 5, sender = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_recipient_mx_access'
);

-- <ForestSimmspq@rpis.pl>: Sender address rejected: Address uses MX in reserved address space (240.0.0.0/4); from=<ForestSimmspq@rpis.pl> to=<dave.lewis@cs.tcd.ie> proto=ESMTP helo=<xmx1.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Sender MX in reserved address space (240.0.0.0/4)', 'The MX for sender domain is in reserved address space (240.0.0.0/4), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in reserved address space \(240.0.0.0/4\); from=<\5> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 6, sender = 5',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_sender_mx_access'
);

-- <cs.tcd.ie>: Helo command rejected: You are not in cs.tcd.ie; from=<van9219@yahoo.co.jp> to=<david.ocallaghan@cs.tcd.ie> proto=SMTP helo=<cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Faked CS HELO', 'The client used a CS address in HELO but is not within our network',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__HELO__)>: Helo command rejected: You are not in cs.tcd.ie; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\5>$',
        'recipient = 7, sender = 6',
        'helo = 5',
        'REJECTION',
        1,
        'REJECTED',
        'check_helo_access'
);

-- <a-tikx23d9jlacr>: Helo command rejected: need fully-qualified hostname; from=<aprenda06@walla.com> to=<michael.brady@cs.tcd.ie> proto=SMTP helo=<a-tikx23d9jlacr>
-- <203.162.3.152>: Helo command rejected: need fully-qualified hostname; from=<grid-ireland-ca@cs.tcd.ie> to=<grid-ireland-ca@cs.tcd.ie> proto=ESMTP helo=<203.162.3.152>
-- <qbic>: Helo command rejected: need fully-qualified hostname; from=<> to=<faircloc@cs.tcd.ie> proto=ESMTP helo=<qbic>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Non-FQDN HELO', 'The hostname given in the HELO command is not fully qualified, i.e. it lacks a domain',
        'postfix/smtpd',
        '^__RESTRICTION_START__ (?><(.*?)>:) Helo command rejected: need fully-qualified hostname; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\5>$',
        'recipient = 7, sender = 6',
        'helo = 5',
        'REJECTION',
        1,
        'REJECTED',
        'reject_non_fqdn_hostname, reject_non_fqdn_helo_hostname'
);

-- <among@ecosse.net>: Relay access denied; from=<uvqjnkhcwanbvk@walla.com> to=<among@ecosse.net> proto=SMTP helo=<88-134-149-72-dynip.superkabel.de>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Relaying denied', 'Client tried to use us as an open relay',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Relay access denied; from=<(__SENDER__)> to=<\5> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 5, sender = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'reject_unauth_destination'
);

-- Client host rejected: cannot find your hostname, [199.84.53.138]; from=<security@e-gold.com.> to=<melanie.bouroche@cs.tcd.ie> proto=ESMTP helo=<DynamicCorp.net>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Rejected client without PTR', 'Client IP address does not have associated PTR record',
        'postfix/smtpd',
        '^__RESTRICTION_START__ Client host rejected: cannot find your hostname, \[__IP__\]; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 6, sender = 5',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'reject_unknown_client'
);

-- We match anything here because the address is invalid.
-- <[]>: Helo command rejected: invalid ip address; from=<mrmmpwv@parfive.com> to=<hitesh.tewari@cs.tcd.ie> proto=ESMTP helo=<[]>
-- <24383590>: Helo command rejected: Invalid name; from=<CBKWPMIUF@hotmail.com> to=<byrne@cs.tcd.ie> proto=SMTP helo=<24383590>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Invalid HELO hostname/ip', 'The hostname/ip used in the HELO command is invalid',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(.*?)>: Helo command rejected: (invalid ip address|Invalid name); from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\5>$',
        'recipient = 8, sender = 7, data = 6',
        'helo = 5',
        'REJECTION',
        1,
        'REJECTED',
        'reject_invalid_helo_hostname'
);

-- <daemon@cs.tcd.ie>: Recipient address rejected: recipient address unknown; from=<> to=<daemon@cs.tcd.ie> proto=ESMTP helo=<lg12x21.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Unknown recipient (system user)', 'The recipient address is unknown on our system (system users should not receive mail)',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: recipient address unknown; from=<(__SENDER__)> to=<\5> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 5, sender = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_recipient_access'
);

-- <daemon@cs.tcd.ie>: Sender address rejected: sender address unknown; from=<daemon@cs.tcd.ie> to=<root@cs.tcd.ie> proto=ESMTP helo=<apex.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Unknown sender (system user)', 'The sender address is unknown on our system (system users should not send mail)',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: sender address unknown; from=<\5> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 6, sender = 5',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_sender_access'
);

-- <neville.harris@cs.tcd.ie>: Recipient address rejected: User no longer receiving mail at this address; from=<have@jewelprecision.com> to=<neville.harris@cs.tcd.ie> proto=SMTP helo=<jewelprecision.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Unknown recipient (user not receiving mail)', 'The recipient address is unknown on our system (user not receiving mail here any more)',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: User no longer receiving mail at this address; from=<(__SENDER__)> to=<\5> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 5, sender = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_recipient_access'
);

-- <godiva.cs.tcd.ie[134.226.35.142]>: Client host rejected: Alias root to something useful.; from=<root@godiva.cs.tcd.ie> to=<root@godiva.cs.tcd.ie> proto=SMTP helo=<godiva.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Unwanted mail to root', 'People keep sending us mail for root at their machine',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <__HOSTNAME__(?>\[__IP__\]>:) Client host rejected: Alias root to something useful.; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 6, sender = 5',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_client_access'
);

-- <root@pc910.cs.tcd.ie>: Recipient address rejected: alias root to some other user, damnit.; from=<root@pc910.cs.tcd.ie> to=<root@pc910.cs.tcd.ie> proto=ESMTP helo=<vangogh.cs.tcd.ie>
-- <root@pc910.cs.tcd.ie>: Recipient address rejected: alias root to some other user, damnit.; from=<> to=<root@pc910.cs.tcd.ie> proto=ESMTP helo=<vangogh.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Unwanted mail to root 2', 'People keep sending us mail for root at their machine (2)',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Recipient address rejected: alias root to some other user, damnit.; from=<(__RECIPIENT__)> to=<\5> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 5, sender = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_client_access'
);

-- <localhost.localhost>: Helo command rejected: You are not me; from=<qute1212000@yahoo.it> to=<mads.haahr@cs.tcd.ie> proto=SMTP helo=<localhost.localhost>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Fake localhost HELO', 'The client claimed to be localhost in the HELO command',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__HELO__)>: Helo command rejected: You are not me; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\5>$',
        'recipient = 7, sender = 6',
        'helo = 5',
        'REJECTION',
        1,
        'REJECTED',
        'check_helo_access'
);

-- <stephen.farrell>: Recipient address rejected: need fully-qualified address; from=<ykkxj.ukf@sfilc.com> to=<stephen.farrell> proto=SMTP helo=<www.BMS96.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Non-FQDN recipient', 'Recipient addresses must be in FQDN form, so replies can be sent',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: need fully-qualified address; from=<(__SENDER__)> to=<\5> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 5, sender = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'reject_non_fqdn_sender'
);

-- <apache>: Sender address rejected: need fully-qualified address; from=<apache> to=<Arthur.Hughes@cs.tcd.ie> proto=ESMTP helo=<najm.tendaweb.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Non-FQDN sender', 'Sender addresses must be in FQDN form, so replies can be sent',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: need fully-qualified address; from=<\5> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 6, sender = 5',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'reject_non_fqdn_sender'
);

-- <DATA>: Data command rejected: Multi-recipient bounce; from=<> proto=SMTP helo=<mail71.messagelabs.com>
-- <DATA>: Data command rejected: Multi-recipient bounce; from=<> proto=ESMTP helo=<euphrates.qatar.net.qa>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, action, queueid, postfix_action, restriction_name)
    VALUES('Multi-recipient bounce rejected', 'Any mail from <> should be a bounce, therefore if there is more than one recipient it can be rejected (supposedly it had more than one sender)',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <DATA>: Data command rejected: Multi-recipient bounce; from=<()> proto=E?SMTP helo=<(__HELO__)>$',
        'sender = 5',
        'helo = 6',
        'recipient = unknown',
        'REJECTION',
        1,
        'REJECTED',
        'reject_multi_recipient_bounce'
);

-- <DATA>: Data command rejected: Improper use of SMTP command pipelining; from=<bounce-523207-288@lists.tmforum.org> to=<vwade@cs.tcd.ie> proto=SMTP helo=<lists.tmforum.org>
-- <DATA>: Data command rejected: Improper use of SMTP command pipelining; from=<daffy982@livedoor.com> to=<tfernand@cs.tcd.ie> proto=ESMTP helo=<adler.ims.uni-stuttgart.de>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Bad pipelining', 'The client tried to use pipelining before Postfix allowed it',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <DATA>: Data command rejected: Improper use of SMTP command pipelining; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'sender = 5, recipient = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'reject_unauth_pipelining'
);

-- NOTE: this rejection doesn't start with __RESTRICTION_START__.
-- NOQUEUE: reject: MAIL from cagraidsvr06.cs.tcd.ie[134.226.53.22]: 552 Message size exceeds fixed limit; proto=ESMTP helo=<cagraidsvr06.cs.tcd.ie>
-- NOQUEUE: reject: MAIL from cagraidsvr06.cs.tcd.ie[134.226.53.22]: 552 5.3.4 Message size exceeds fixed limit; proto=ESMTP helo=<cagraidsvr06.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, action, queueid, postfix_action, restriction_name)
    VALUES('Rejected mail too large', 'The client tried to send a mail but it is too big to be accepted.',
        'postfix/smtpd',
        '^(NOQUEUE): reject: MAIL from (__HOSTNAME__)\[(__IP__)\]: (__SMTP_CODE__) (?:__DSN__ )?Message size exceeds fixed limit; proto=ESMTP helo=<(__HELO__)>$',
        'smtp_code = 4',
        'client_hostname = 2, client_ip = 3, helo = 5',
        'sender = unknown, recipient = unknown',
        'REJECTION',
        1,
        'REJECTED',
        'message_size_limit'
);

-- <info@tiecs.ie>: Sender address rejected: Stop flooding our users with mail.; from=<info@tiecs.ie> to=<tobinjt@cs.tcd.ie> proto=SMTP helo=<wilde.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Stop flooding users with mail', 'A client was flooding users with unwanted mail',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Stop flooding our users with mail.; from=<\5> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'sender = 5, recipient = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_sender_access'
);

-- NOTE: this rejection doesn't start with __RESTRICTION_START__.
-- NOQUEUE: reject: CONNECT from localhost[::1]: 554 5.7.1 <localhost[::1]>: Client host rejected: Access denied; proto=SMTP
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, action, queueid, postfix_action, restriction_name)
    VALUES('Client host rejected for some reason', 'The client was rejected but no reason was specified',
        'postfix/smtpd',
        '^(NOQUEUE): reject: CONNECT from (__HOSTNAME__)\[(__IP__)\]: (__SMTP_CODE__) (?:__DSN__ )?<\2\[\3\]>: Client host rejected: Access denied; proto=E?SMTP$',
        'smtp_code = 4',
        'client_hostname = 2, client_ip = 3',
        'sender = unknown, recipient = unknown',
        'REJECTION',
        1,
        'REJECTED',
        'check_client_access?'
);

-- <angbuchsbaum@yahoo.be>: Recipient address rejected: Malformed DNS server reply; from=<Alena.Moison@cs.tcd.ie> to=<angbuchsbaum@yahoo.be> proto=ESMTP helo=<SECPC2>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Malformed DNS reply (recipient)', 'The DNS reply was malformed when checking the recipient domain',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Malformed DNS server reply; from=<(__SENDER__)> to=<\5> proto=E?SMTP helo=<(__HELO__)>$',
        'sender = 6, recipient = 5',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'reject_unknown_sender_domain'
);

-- <Gunter_LetitiaV@bionorthernireland.com>: Sender address rejected: Malformed DNS server reply; from=<Gunter_LetitiaV@bionorthernireland.com> to=<donnelly@cs.tcd.ie> proto=SMTP helo=<2D87008>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Malformed DNS reply (sender)', 'The DNS reply was malformed when checking the sender domain',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Malformed DNS server reply; from=<\5> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'sender = 5, recipient = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'reject_unknown_sender_domain'
);

-- <relay.ubu.es[193.146.160.3]>: Client host rejected: Please stop sending us unwanted call for papers.; from=<escorchado@ubu.es> to=<kahmad@cs.tcd.ie> proto=ESMTP helo=<virtual310.curris.ubu.es>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Unwanted calls for papers', 'The client is spamming us with calls for papers',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__HOSTNAME__)\[(__IP__)\]>: Client host rejected: Please stop sending us unwanted call for papers.; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'sender = 7, recipient = 8',
        'client_hostname = 5, client_ip = 6, helo = 9',
        'REJECTION',
        1,
        'REJECTED',
        'check_client_access'
);

-- <postmaster@cs.tcd.ie>: Sender address rejected: This address is not in use.; from=<postmaster@cs.tcd.ie> to=<caramisgo@yahoo.co.kr> proto=SMTP helo=<dvnpahxwg.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Rejecting unused sender address', 'Rejecting an address we know is not used for sending mail',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: This address is not in use.; from=<\5> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'sender = 5, recipient = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_sender_access'
);

-- <bassire@venus.made2own.com>: Sender address rejected: We don't want your spam.; from=<bassire@venus.made2own.com> to=<liz.gray@cs.tcd.ie> proto=ESMTP helo=<venus.made2own.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Rejecting spammer sender address', 'Rejecting an address we know is used for sending spam',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: We don.t want your spam.; from=<\5> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'sender = 5, recipient = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_sender_access'
);

-- Client host rejected: Fix your mail system please, you've filling up our mail queue.; from=<> to=<root@pc910.cs.tcd.ie> proto=ESMTP helo=<pc910.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Rejecting client flooding us with mail', 'Rejecting a client which is flooding us with mail.',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(?:__HOSTNAME__)\[(?:__IP__)\]>: Client host rejected: Fix your mail system please, you.ve filling up our mail queue.; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'sender = 5, recipient = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_sender_access'
);


-- Client host rejected: Don't want this mail; from=<> to=<cricket@cs.tcd.ie> proto=ESMTP helo=<lg12x37.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action, restriction_name)
    VALUES('Rejecting we do not want', 'Rejecting mail which is unwanted for one reason or another',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <__HOSTNAME__\[__IP__\]>: Client host rejected: Don.t want this mail; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'sender = 5, recipient = 6',
        'helo = 7',
        'REJECTION',
        1,
        'REJECTED',
        'check_sender_access'
);

-- }}}

-- SMTPD ACCEPT RULES {{{1
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, action, queueid, postfix_action)
    VALUES('Mail accepted', 'Postfix accepted the mail; it is hardly obvious from the log message though',
        'postfix/smtpd',
        '^(__QUEUEID__): client=(__HOSTNAME__)\[(__IP__)\]$',
        '',
        'client_hostname = 2, client_ip = 3',
        'smtp_code = 250',
        'CLONE',
        1,
        'ACCEPTED'
);

-- }}}

-- SMTPD INFO RULES {{{

-- This has a high priority so that it supercedes the following rule, catching
-- uselessly logged HELOs.
-- NOQUEUE: warn: RCPT from unknown[200.42.252.162]: Logging HELO; from=<apple@cs.tcd.ie> to=<apple@cs.tcd.ie> proto=ESMTP helo=<200.42.252.162>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, priority, postfix_action)
    VALUES('Logging HELO (ignored)', 'HELO logged to provide additional data (ignored, an improved version is now in use)',
        'postfix/smtpd',
        '^NOQUEUE: warn: __SHORT_CMD__ from (?:__HOSTNAME__)\[(?:__IP__)\]: Logging HELO; from=<(?:__SENDER__)> to=<(?:__RECIPIENT__)> proto=E?SMTP helo=<(?:__HELO__)>$',
        '',
        '',
        'IGNORE',
        0,
        5,
        'IGNORED'
);

-- A3BB2363C: warn: DATA from localhost[127.0.0.1]: Logging HELO; from=<emailSenderApp+2VGO154B9WPQS-VA33Q45OY07B-2B82XZ9ZK7SCW@bounces.amazon.com> to=<eamonn.kenny@cs.tcd.ie> proto=ESMTP helo=<localhost>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Logging HELO', 'HELO logged to provide additional data',
        'postfix/smtpd',
        '^(__QUEUEID__): warn: (?:__SHORT_CMD__|DATA) from (__HOSTNAME__)\[(__IP__)\]: Logging HELO; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'sender = 4, recipient = 5',
        'client_hostname = 2, client_ip = 3, helo = 6',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- }}}


-- QMGR RULES {{{1
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Mail delivery accomplished', 'qmgr is finished with the mail; it has been delivered',
        'postfix/qmgr',
        '^(__QUEUEID__): removed$',
        '',
        '',
        'COMMIT',
        1,
        'INFO'
);

-- 6508A4317: from=<florenzaaluin@callisupply.com>, size=2656, nrcpt=1 (queue active)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('qmgr processing mail', 'qmgr is going to deliver this mail',
        'postfix/qmgr',
        '^(__QUEUEID__): from=<(__SENDER__)>, size=(\d+), nrcpt=(\d+) \(queue active\)$',
        'sender = 2, size = 3',
        '',
        'MAIL_PICKED_FOR_DELIVERY',
        1,
        'INFO'
);

-- A93F138A1: from=<<>@inprima.locaweb.com.br>, size=15535, nrcpt=1 (queue active)
-- 6508A4317: from=<florenzaaluin@callisupply.com>, size=2656, nrcpt=1 (queue active)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, priority, postfix_action)
    VALUES('qmgr processing mail (weird from address)', 'qmgr is going to deliver this mail (weird from address)',
        'postfix/qmgr',
        '^(__QUEUEID__): from=<(.*?)>, size=(\d+), nrcpt=\d+ \(queue active\)$',
        'sender = 2, size = 3',
        '',
        'MAIL_PICKED_FOR_DELIVERY',
        1,
        -1,
        'INFO'
);

-- B1508348E: from=<tcd-mzones-management-bounces+79talbert=jinan.gov.cn@cs.tcd.ie>, status=expired, returned to sender
-- 9C169364A: from=<>, status=expired, returned to sender
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, action, queueid, postfix_action)
    VALUES('mail has been queued for too long', 'mail has been sitting in the queue for too long, postifx is giving up on it',
        'postfix/qmgr',
        '^(__QUEUEID__): from=<(__SENDER__)>, (?:__DELAYS__)?(?:dsn=__DSN__, )?status=expired, returned to sender$',
        'sender = 1',
        '',
        'smtp_code = 554',
        'EXPIRY',
        1,
        'EXPIRED'
);

-- E8DE4438A: to=<root@godiva.cs.tcd.ie>, relay=none, delay=1, status=deferred (delivery temporarily suspended: connect to godiva.cs.tcd.ie[134.226.35.142]: Connection refused)
-- D24B44416: to=<G4254-list@tcd.ie>, orig_to=<allnightug-list@cs.tcd.ie>, relay=none, delay=64, status=deferred (delivery temporarily suspended: connect to imx2.tcd.ie[134.226.1.156]: Connection timed out)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('delivery suspended because the connection was refused/timed out', 'qmgr deferred delivery because the smtp connection was refused/timed out',
        'postfix/qmgr',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, __DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \(delivery temporarily suspended: connect to (__HOSTNAME__)\[(__IP__)\]: Connection (?:refused|timed out)\)$',
        'recipient = 2',
        'server_hostname = 3, server_ip = 4',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 0278038B0: to=<mary.davies@sihe.ac.uk>, relay=none, delay=0.09, delays=0.08/0.01/0/0, dsn=4.4.2, status=deferred (delivery temporarily suspended: lost connection with 127.0.0.1[127.0.0.1] while receiving the initial server greeting)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('delivery suspended because the connection was lost', 'qmgr deferred delivery because the smtp connection was lost',
        'postfix/qmgr',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, __DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \(delivery temporarily suspended: lost connection with (__HOSTNAME__)\[(__IP__)\] while receiving the initial server greeting\)$',
        'recipient = 2',
        'server_hostname = 3, server_ip = 4',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 27AB942D3: skipped, still being delivered
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Qmgr skipping a mail', 'I presume qmgr is rescanning the queue, sees this mail, but knows there is a process trying to deliver it?  How can it take so long?',
        'postfix/qmgr',
        '^__QUEUEID__: skipped, still being delivered$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- 0F5073725: to=<amulllly@cs.tcd.ie>, relay=none, delay=0, status=deferred (delivery temporarily suspended: lost connection with 127.0.0.1[127.0.0.1] while sending end of data -- message may be sent more than once)
-- 9326C365D: to=<welsh@cs.tcd.ie>, relay=none, delay=3, status=deferred (delivery temporarily suspended: lost connection with 127.0.0.1[127.0.0.1] while sending end of data -- message may be sent more than once)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, priority, postfix_action)
    VALUES('Conversation timed out with filter while sending <CR>.<CR>', 'The conversation timed out after Postfix had finished sending data to the filter; mail will be retried, but should not have been delivered by amavisd-new (we hope)',
        'postfix/qmgr',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, __DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \(delivery temporarily suspended: lost connection with (127.0.0.1)\[(127.0.0.1)\] while sending end of data -- message may be sent more than once\)$',
        'recipient = 2',
        'server_hostname = 3, server_ip = 4',
        'SAVE_BY_QUEUEID',
        1,
        10,
        'INFO'
);

-- warning: qmgr_active_corrupt: save corrupt file queue active id CF4E648F5: No such file or directory
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('QMGR logged a warning', 'QMGR logged a warning; we should probably try to do something with this is future',
        'postfix/qmgr',
        '^warning: .+$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- 1}}}


-- SMTP RULES {{{1

-- 058654401: to=<autosupport@netapp.com>, relay=mx1.netapp.com[216.240.18.38], delay=53, status=sent (250 ok:  Message 348102483 accepted)
-- 253234317: to=<shanneneables@granherne.com>, relay=houmail002.halliburton.com[34.254.16.14], delay=2, status=sent (250 2.0.0 kA50s0cL029158 Message accepted for delivery)
-- 0226B4317: to=<rajaverma@gmail.com>, relay=gmail-smtp-in.l.google.com[66.249.93.114], delay=1, status=sent (250 2.0.0 OK 1162706943 x33si2914313ugc)
-- DC1484406: to=<elisab@gmail.com>, orig_to=<elisa.baniassad@cs.tcd.ie>, relay=gmail-smtp-in.l.google.com[66.249.93.114], delay=1, status=sent (250 2.0.0 OK 1162686664 53si2666246ugd)
-- B7F9D4400: to=<dalyj1@tcd.ie>, orig_to=<dalyj1@cs.tcd.ie>, relay=imx1.tcd.ie[134.226.17.160], delay=0, status=sent (250 Ok: queued as BE7B04336)
-- 56D3838DB: to=<grid-ireland-alert@cs.tcd.ie>, relay=127.0.0.1[127.0.0.1]:10024, conn_use=2, delay=17, delays=2.1/8.8/0.01/5.7, dsn=2.6.0, status=sent (250 2.6.0 Ok, id=20909-22-2, from MTA([127.0.0.1]:11025): 250 2.0.0 Ok: queued as AB6AE3D6E)
-- 
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('mail delivered to outside world', 'a mail was delivered to an outside address',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__HOSTNAME__)\[(__IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=sent \(((__SMTP_CODE__).*)\)$',
        'recipient = 2, data = 5, smtp_code = 6',
        'server_hostname = 3, server_ip = 4',
        'client_ip = 127.0.0.1, client_hostname = localhost',
        'SAVE_BY_QUEUEID',
        1,
        'SENT'
);

-- 56EE54317: to=<creans@cs.tcd.ie>, relay=127.0.0.1[127.0.0.1], delay=3, status=sent (250 2.7.1 Ok, discarded, id=00218-04 - VIRUS: HTML.Phishing.Bank-753)
-- D93E84400: to=<diana.wilson@cs.tcd.ie>, relay=127.0.0.1[127.0.0.1], delay=1, status=sent (250 2.7.1 Ok, discarded, id=00218-03-2 - VIRUS: HTML.Phishing.Bank-753)
-- 1C8E84317: to=<dolan@cs.tcd.ie>, relay=127.0.0.1[127.0.0.1], delay=8, status=sent (250 2.6.0 Ok, id=00218-02, from MTA([127.0.0.1]:11025): 250 Ok: queued as 2677C43FD)
-- 730AC43FD: to=<grid-ireland-alert@cs.tcd.ie>, relay=127.0.0.1[127.0.0.1], delay=0, status=sent (250 2.6.0 Ok, id=15759-01-2, from MTA([127.0.0.1]:11025): 250 Ok: queued as A3B7C4403)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, priority, postfix_action)
    VALUES('mail being filtered', 'mail has been passed to a proxy  for filtering',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=127.0.0.1\[127.0.0.1\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=sent \(((250) .*)\)$',
        'recipient = 2, smtp_code = 4, data = 3',
        '',
        'SAVE_BY_QUEUEID',
        1,
        5,
        'SENT'
);

-- connect to wsatkins.co.uk[193.117.23.129]: Connection refused (port 25)
-- connect to 127.0.0.1[127.0.0.1]: Connection refused (port 10024)
-- connect to mail.3dns.tns-global.com[194.202.213.46]: Connection reset by peer (port 25)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('connect refused', 'postfix tried to connect to a remote smtp server, but the connection was refused',
        'postfix/smtp',
        '^connect to (__HOSTNAME__)\[(__IP__)\]: Connection (?:refused|reset by peer) \(port \d+\)$',
        '',
        'server_hostname = 1, server_ip = 2',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'IGNORE',
        0,
        'IGNORED'
);

-- 4CC8443C5: to=<abutbrittany@route66bikers.com>, relay=none, delay=222439, status=deferred (connect to route66bikers.com[69.25.142.6]: Connection timed out)
-- D004043FD: to=<bjung@uvic.ca>, orig_to=<jungb@cs.tcd.ie>, relay=none, delay=31, status=deferred (connect to smtpx.uvic.ca[142.104.5.91]: Connection timed out)
-- 790D438A6: to=<CFSworks@XeonNET.net>, relay=mail.XeonNET.net[70.57.16.248]:25, delay=78733, delays=78432/0.43/300/0, dsn=4.4.2, status=deferred (conversation with mail.XeonNET.net[70.57.16.248] timed out while receiving the initial server greeting)

INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('mail delayed', 'the connection timed out while trying to deliver mail',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(?:none|__HOSTNAME__\[__IP__\](?::\d+)?), (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \((?:conversation with|connect to) (__HOSTNAME__)\[(__IP__)\](?:: Connection timed out| timed out while receiving the initial server greeting)\)$',
        'recipient = 2',
        'server_hostname = 3, server_ip = 4',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 7A06F3489: to=<azo@www.instantweb.com>, relay=www.instantweb.com[206.185.24.12], delay=68210, status=deferred (host www.instantweb.com[206.185.24.12] said: 451 qq write error or disk full (#4.3.0) (in reply to end of DATA command))
-- B697043F0: to=<matthew@sammon.info>, orig_to=<matthew.sammon@cs.tcd.ie>, relay=mail.hosting365.ie[82.195.128.132], delay=1, status=deferred (host mail.hosting365.ie[82.195.128.132] said: 450 <matthew@sammon.info>: Recipient address rejected: Greylisted for 5 minutes (in reply to RCPT TO command))
-- DDF6A3489: to=<economie-recherche@region-bretagne.fr>, relay=rain-pdl.megalis.org[217.109.171.200], delay=1, status=deferred (host rain-pdl.megalis.org[217.109.171.200] said: 450 <economie-recherche@region-bretagne.fr>: Recipient address rejected: Greylisted for 180 seconds (see http://isg.ee.ethz.ch/tools/postgrey/help/region-bretagne.fr.html) (in reply to RCPT TO command))
-- EF2AE438D: to=<k.brown@cs.ucc.ie>, relay=mail6.ucc.ie[143.239.1.36], delay=11, status=deferred (host mail6.ucc.ie[143.239.1.36] said: 451 4.3.2 Please try again later (in reply to MAIL FROM command))
-- 0A6634382: to=<ala.biometry@rret.com>, relay=smtp.getontheweb.com[66.36.236.47], delay=57719, status=deferred (host smtp.getontheweb.com[66.36.236.47] said: 451 qqt failure (#4.3.0) (in reply to DATA command))
-- 2CD5C3D8F: to=<gordon.power@gmail.com>, relay=gmail-smtp-in.l.google.com[66.249.93.114]:25, conn_use=3, delay=0.58, delays=0.05/0/0.29/0.23, dsn=4.2.1, status=deferred (host gmail-smtp-in.l.google.com[66.249.93.114] said: 450-4.2.1 The Gmail user you are trying to contact is receiving 450-4.2.1 mail at a rate that prevents additional messages from 450-4.2.1 being delivered. Please resend your message at a later 450-4.2.1 time; if the user is able to receive mail at that time, 450 4.2.1 your message will be delivered. s1si6984646uge (in reply to RCPT TO command))
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('mail deferred because of a temporary remote failure', 'There is a temporary failure of some sort on the remote side, mail deferred',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__HOSTNAME__)\[(__IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \(host \3\[\4\] said: ((__SMTP_CODE__).*) \(in reply to __COMMAND__ command\)\)$',
        'recipient = 2, smtp_code = 6, data = 5',
        'server_hostname = 3, server_ip = 4',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 7ABDF43FD: to=<olderro@myccccd.net>, relay=none, delay=0, status=bounced (Host or domain name not found. Name service error for name=mailcruiser.campuscruiser.com type=A: Host not found)
-- 90F0E3E19: to=<matthew@sammon.info>, orig_to=<matthew.sammon@cs.tcd.ie>, relay=none, delay=0, status=bounced (Host or domain name not found. Name service error for name=mail.hosting365.ie type=A: Host not found)
-- C350F38DB: to=<sfee@tcd.cs.tcd.ie>, orig_to=<sfee@tcd>, relay=none, delay=0.39, delays=0.38/0/0/0, dsn=5.4.4, status=bounced (Host or domain name not found. Name service error for name=tcd.cs.tcd.ie type=AAAA: Host not found)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, connection_data, action, queueid, postfix_action)
    VALUES('Recipient MX not found', 'No MX server for the recipient was found',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=bounced \(Host or domain name not found. Name service error for name=(__HOSTNAME__) type=(?:MX|A|AAAA): Host not found\)$',
        'recipient = 2',
        'server_hostname = 3',
        'smtp_code = 554',
        'client_hostname = localhost, client_ip = 127.0.0.1, server_ip = unknown',
        'SAVE_BY_QUEUEID',
        1,
        'BOUNCED'
);

-- B028035EB: to=<Iain@fibernetix.com>, relay=none, delay=282964, status=deferred (Host or domain name not found. Name service error for name=fibernetix.com type=MX: Host not found, try again)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, connection_data, action, queueid, postfix_action)
    VALUES('Recipient MX not found (try again)', 'No MX server for the recipient was found (try again, temporary failure)',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \((?:Host or domain name not found. )?Name service error for name=(__HOSTNAME__) type=(?:A|AAAA|MX): Host not found, try again\)$',
        'recipient = 2',
        'server_hostname = 3',
        'smtp_code = 554',
        'client_hostname = localhost, client_ip = 127.0.0.1, server_ip = unknown',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- connect to lackey.cs.qub.ac.uk[143.117.5.165]: Connection timed out (port 25)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('connect timed out', 'time out while postfix was connecting to remote server',
        'postfix/smtp',
        '^connect to __HOSTNAME__\[__IP__\]: Connection timed out \(port 25\)$',
        '',
        '',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'IGNORE',
        0,
        'IGNORED'
);

-- D7B274401: to=<jaumaffup@cchlis.com>, relay=cchlis.com.s5a1.psmtp.com[64.18.4.10], delay=2, status=bounced (host cchlis.com.s5a1.psmtp.com[64.18.4.10] said: 550 5.1.1 User unknown (in reply to RCPT TO command))
-- A71B043FD: to=<dpdlbalgkcm@malaysia.net>, relay=malaysia-net.mr.outblaze.com[205.158.62.177], delay=31, status=bounced (host malaysia-net.mr.outblaze.com[205.158.62.177] said: 550 <>: No thank you rejected: Account Unavailable: Possible Forgery (in reply to RCPT TO command))
-- 224E243C3: to=<lamohtm@mail.ru>, orig_to=<sergey.tsvetkov@cs.tcd.ie>, relay=mxs.mail.ru[194.67.23.20], delay=5, status=bounced (host mxs.mail.ru[194.67.23.20] said: 550 spam message discarded. If you think that the system is mistaken, please report details to abuse@corp.mail.ru (in reply to end of DATA command))
-- 
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('mail to outside world rejected', 'mail to the outside world was rejected',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__HOSTNAME__)\[(__IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?>(?:__DELAYS__)?(?:dsn=__DSN__, )?status=bounced) \(host \3\[\4\] said: ((__SMTP_CODE__).*) \(in reply to __COMMAND__ command\)\)$',
        'recipient = 2, smtp_code = 6, data = 5',
        'server_hostname = 3, server_ip = 4',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'BOUNCED'
);

-- connect to mx1.mail.yahoo.com[4.79.181.14]: server refused to talk to me: 421 Message from (134.226.32.56) temporarily deferred - 4.16.50. Please refer to http://help.yahoo.com/help/us/mail/defer/defer-06.html   (port 25)
-- connect to mx1.mail.ukl.yahoo.com[195.50.106.7]: server refused to talk to me: 451 Message temporarily deferred - 4.16.50   (port 25)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('Server refused to talk', 'The remote server refused to talk for some reason',
        'postfix/smtp',
        '^connect to __HOSTNAME__\[__IP__\]: server refused to talk to me: __SMTP_CODE__(?:.*) \(port 25\)$',
        '',
        '',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'IGNORE',
        0,
        'IGNORED'
);

-- 31AE04400: to=<domurtag@yahoo.co.uk>, orig_to=<domurtag@cs.tcd.ie>, relay=none, delay=0, status=deferred (connect to mx2.mail.ukl.yahoo.com[217.12.11.64]: server refused to talk to me: 451 Message temporarily deferred - 4.16.50  )
-- A932037C8: to=<ayako70576@freewww.info>, relay=none, delay=30068, status=deferred (connect to vanitysmtp.changeip.com[143.215.15.51]: server refused to talk to me: 421 cannot send to name server  )
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('Server refused to talk (later stage?)', 'The remote server refused to talk for some reason - at a later stage?  We have a queueid anyway',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \(connect to (__HOSTNAME__)\[(__IP__)\]: server refused to talk to me: ((__SMTP_CODE__).*)\)$',
        'recipient = 2, smtp_code = 6, data = 5',
        'server_hostname = 3, server_ip = 4',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- warning: numeric domain name in resource data of MX record for phpcompiler.org: 80.68.89.7
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('Warning from smtp', 'Warning of some sort from smtp - rare',
        'postfix/smtp',
        '^warning: .*$',
        '',
        '',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'IGNORE',
        0,
        'IGNORED'
);

-- 18FCF43C3: host iona.com.s8a1.psmtp.com[64.18.7.10] said: 451 Can't connect to iona.ie - psmtp (in reply to RCPT TO command)
-- 3B91D4390: host mail6.ucc.ie[143.239.1.36] said: 451 4.3.2 Please try again later (in reply to MAIL FROM command)
-- 80C05439E: host ASPMX.L.GOOGLE.COM[66.249.93.27] said: 450-4.2.1 The Gmail user you are trying to contact is receiving 450-4.2.1 mail at a rate that prevents additional messages from 450-4.2.1 being delivered. Please resend your message at a later 450-4.2.1 time; if the user is able to receive mail at that time, 450 4.2.1 your message will be delivered. q40si1486066ugc (in reply to RCPT TO command)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, priority, postfix_action)
    VALUES('Generic smtp failure', 'A catchall for failures we do not have more specific tests for',
        'postfix/smtp',
        '^(__QUEUEID__): host (__HOSTNAME__)\[(__IP__)\] said: ((__SMTP_CODE__).*) \(in reply to __COMMAND__ command\)$',
        'data = 4, smtp_code = 5',
        'server_hostname = 2, server_ip = 3',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        -1,
        -- XXX is INFO right here?
        'INFO'
);

-- connect to smap-net-bk.mr.outblaze.com[205.158.62.181]: read timeout (port 25)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('read timeout', 'reading data from remote server timed out',
        'postfix/smtp',
        '^connect to __HOSTNAME__\[__IP__\]: read timeout \(port 25\)$',
        '',
        '',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'IGNORE',
        0,
        'IGNORED'
);

-- C770E4317: to=<nywzssbpk@smapxsmap.net>, relay=none, delay=944, status=deferred (connect to smap-net-bk.mr.outblaze.com[205.158.62.177]: read timeout)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('read timeout (with queueid)', 'read timeout during connect - with queueid',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \(connect to (__HOSTNAME__)\[(__IP__)\]: read timeout\)$',
        'recipient = 2',
        'server_hostname = 3, server_ip = 4',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 681A74425: lost connection with mx1.mail.yahoo.com[4.79.181.15] while sending RCPT TO
-- 719B44312: lost connection with mail.waypt.com[63.172.167.6] while sending DATA command
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('smtp client lost connection', 'smtp client lost connection for who knows what reason',
        'postfix/smtp',
        '^(__QUEUEID__): lost connection with (__HOSTNAME__)\[(__IP__)\] while sending (__COMMAND__)(?: command)?$',
        'data = 3',
        'server_hostname = 2, server_ip = 3',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- no queueid to save with
-- connect to mail.boilingpoint.com[66.240.186.41]: server dropped connection without sending the initial SMTP greeting (port 25)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('remote server rudely hung up', 'The remote server closed the connection without saying anything at all',
        'postfix/smtp',
        '^connect to __HOSTNAME__\[__IP__\]: server dropped connection without sending the initial SMTP greeting \(port \d+\)$',
        '',
        '',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'IGNORE',
        0,
        'IGNORED'
);

-- 198D4438F: to=<fj.azuaje@ieee.org>, orig_to=<francisco.azuaje@cs.tcd.ie>, relay=none, delay=0, status=deferred (connect to hormel.ieee.org[140.98.193.224]: server dropped connection without sending the initial SMTP greeting)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('remote server rudely hung up (with queueid)', 'The remote server closed the connection without saying anything at all (but we have a queueid this time)',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \(connect to (__HOSTNAME__)\[(__IP__)\]: server dropped connection without sending the initial SMTP greeting\)$',
        'recipient = 2',
        'server_hostname = 3, server_ip = 4',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 99C2243F0: to=<mounderek@bigfot.com>, relay=none, delay=385069, status=deferred (connect to mail.ehostinginc.com[66.172.49.6]: Connection refused)
-- 2F5C643E9: to=<fj.azuaje@ieee.org>, orig_to=<francisco.azuaje@cs.tcd.ie>, relay=none, delay=0, status=deferred (connect to hormel.ieee.org[140.98.193.224]: Connection refused)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('connection to remote host failed', 'smtp client could not connect to remote server',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \(connect to (__HOSTNAME__)\[(__IP__)\]: Connection refused\)$',
        'recipient = 2',
        'server_hostname = 3, server_ip = 4',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 2A2DB4496: conversation with mail.zust.it[213.213.93.228] timed out while sending RCPT TO
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('Conversation timed out (2)', 'There was an awkward pause in the conversation and eventually it died',
        'postfix/smtp',
        '^(__QUEUEID__): conversation with (__HOSTNAME__)\[(__IP__)\] timed out while sending __COMMAND__$',
        '',
        'server_hostname = 2, server_ip = 3',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 2A2DB4496: enabling PIX <CRLF>.<CRLF> workaround for mail.zust.it[213.213.93.228]
-- 5EAFB38C0: enabling PIX <CRLF>.<CRLF> workaround for mx.nsu.ru[212.192.164.5]:25
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('Working around broken PIX SMTP Fixup', 'The Cisco PIX has braindead SMTP Fixup, Postfix is working around it so that mail can be delivered',
        'postfix/smtp',
        '^(__QUEUEID__): enabling PIX <CRLF>.<CRLF> workaround for (__HOSTNAME__)\[(__IP__)\](?::\d+)?$',
        '',
        'server_hostname = 2, server_ip = 3',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 16B6A3F50: to=<skenny@relay.cs.tcd.ie>, relay=none, delay=0, status=bounced (mail for relay.cs.tcd.ie loops back to myself)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, connection_data, action, queueid, postfix_action)
    VALUES('Mail loop detected', 'This host is the MX for the addresses domain, but is not final destination for that domain',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=bounced \(mail for (__HOSTNAME__) loops back to myself\)$',
        'recipient = 2, data = 3',
        '',
        'smtp_code = 554',
        'client_hostname = localhost, client_ip = 127.0.0.1, server_hostname = localhost, server_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'BOUNCED'
);

-- 833CF438C: to=<essack@ion.co.za>, relay=spamfilter.ion.co.za[196.33.120.7], delay=603, status=deferred (conversation with spamfilter.ion.co.za[196.33.120.7] timed out while sending end of data -- message may be sent more than once)
-- 74AA93554: to=<kinshuk@athabascau.ca>, relay=smtp.athabascau.ca[131.232.10.21], delay=435, status=deferred (lost connection with smtp.athabascau.ca[131.232.10.21] while sending end of data -- message may be sent more than once)
-- 5B79E3850: to=<cathal.oconnor@cs.tcd.ie>, relay=127.0.0.1[127.0.0.1]:10024, conn_use=2, delay=9.5, delays=2.6/0/0/6.8, dsn=4.4.2, status=deferred (lost connection with 127.0.0.1[127.0.0.1] while sending end of data -- message may be sent more than once)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('Conversation timed out after sending <CR>.<CR>', 'The conversation timed out after Postfix had finished sending the data; mail will be retried, but may have already been delivered on the remote end',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__HOSTNAME__)\[(__IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \((?:lost connection with|conversation with) \3\[\4\] (?:timed out )?while sending end of data -- message may be sent more than once\)$',
        'recipient = 2',
        'server_hostname = 3, server_ip = 4',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 122E141CD: to=<Taught.Admissions@tcd.ie>, relay=imx1.tcd.ie[134.226.17.160], delay=2, status=bounced (message size 10694768 exceeds size limit 10240000 of server imx1.tcd.ie[134.226.17.160])
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, connection_data, action, queueid, postfix_action)
    VALUES('Mail too big for remote server', 'The remote server will not accept mails bigger than X, and this mail is bigger',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__HOSTNAME__)\[(__IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=bounced \((message size \d+ exceeds size limit \d+ of server) \3\[\4\]\)$',
        'recipient = 2, data = 5',
        'server_hostname = 3, server_ip = 4',
        'smtp_code = 552',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'BOUNCED'
);

-- 5499D44A3: conversation with drip.STJAMES.IE[194.106.141.85] timed out while performing the initial protocol handshake
-- 8103838B8: conversation with d.mx.mail.yahoo.com[216.39.53.2] timed out while receiving the initial server greeting
-- 04AE038CA: conversation with rose.man.poznan.pl[150.254.173.3] timed out while performing the EHLO handshake
-- 9769838B2: lost connection with spamtrap.netsource.ie[212.17.32.57] while performing the EHLO handshake
-- C8B0C437E: lost connection with mx3.mail.yahoo.com[67.28.113.10] while performing the initial protocol handshake
-- 5E67F38A1: lost connection with e33.co.us.ibm.com[32.97.110.151] while receiving the initial server greeting
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('Conversation timed out while handshaking', 'The initial handshake timed out',
        'postfix/smtp',
        '^(__QUEUEID__): (?:lost connection with|conversation with) (__HOSTNAME__)\[(__IP__)\] (?:timed out )?while (?:performing the (?:initial protocol|EHLO|HELO) handshake|receiving the initial server greeting)$',
        '',
        'server_hostname = 2, server_ip = 3',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 431844388: to=<matthew@sammon.info>, orig_to=<matthew.sammon@cs.tcd.ie>, relay=redir-mail-telehouse1.gandi.net[217.70.180.1], delay=390, status=deferred (host redir-mail-telehouse1.gandi.net[217.70.180.1] refused to talk to me: 450 Server configuration problem)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('Server refused to talk (politely)', 'The remote server politely declied to talk to our server',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__HOSTNAME__)\[(__IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \(host \3\[\4\] refused to talk to me: ((__SMTP_CODE__).*)\)$',
        'recipient = 2, data = 5, smtp_code = 6',
        'server_hostname = 3, server_ip = 4',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 47F5C438A: to=<matthew@sammon.info>, orig_to=<matthew.sammon@cs.tcd.ie>, relay=redir-mail-telehouse2.gandi.net[217.70.178.1], delay=4106, status=deferred (conversation with redir-mail-telehouse2.gandi.net[217.70.178.1] timed out while performing the initial protocol handshake)
-- 820A94385: to=<Romanu6jMassey@photoeye.com>, relay=relay1.edgewebhosting.net[69.63.128.201], delay=1132, status=deferred (lost connection with relay1.edgewebhosting.net[69.63.128.201] while performing the initial protocol handshake)
-- E49EC438A: to=<DanR@Burton.com>, relay=mail.Burton.com[204.52.244.205], delay=3, status=deferred (lost connection with mail.Burton.com[204.52.244.205] while performing the initial protocol handshake)
-- 1E64D38CB: to=<wewontpay@btconnect.com>, relay=ibmr.btconnect.com[213.123.20.92]:25, delay=1.5, delays=0.08/0/1.4/0, dsn=4.4.2, status=deferred (lost connection with ibmr.btconnect.com[213.123.20.92] while receiving the initial server greeting)
-- 172BD36E3: to=<bgiven@mason.gmu.edu>, relay=mx-h.gmu.edu[129.174.0.99]:25, delay=0.67, delays=0.27/0.07/0.33/0, dsn=4.4.2, status=deferred (lost connection with mx-h.gmu.edu[129.174.0.99] while performing the HELO handshake)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('Initial handshake timed out', 'The initial handshake did not complete within the timeout',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__HOSTNAME__)\[(__IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \((?:lost connection with|conversation with) \3\[\4\] (?:(?:timed out )?while performing the (?:initial protocol|HELO|EHLO) handshake|while receiving the initial server greeting)\)$',
        'recipient= 2',
        'server_hostname = 3, server_ip = 4',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 979054314: to=<lionel.dahyot@cegetel.net>, relay=av.mgp.neufgp.fr[84.96.92.100], delay=10, status=deferred (lost connection with av.mgp.neufgp.fr[84.96.92.100] while sending RCPT TO)
-- CD3EC41CC: to=<resume@athabascau.ca>, relay=smtp.athabascau.ca[131.232.10.21], delay=63, status=deferred (lost connection with smtp.athabascau.ca[131.232.10.21] while sending RCPT TO)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('Lost connection with server', 'Lost connection with remote host during transaction',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__HOSTNAME__)\[(__IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \(lost connection with \3\[\4\] while sending __COMMAND__\)$',
        'recipient = 2',
        'server_hostname = 3, server_ip = 4',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 1324443A2: to=<zenobig@virgilio.it>, orig_to=<gabriele.zenobi@cs.tcd.ie>, relay=mxrm.virgilio.it[62.211.72.33], delay=8248, status=deferred (conversation with mxrm.virgilio.it[62.211.72.33] timed out while sending MAIL FROM)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('Conversation timed out', 'The conversation timed out at some stage',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__HOSTNAME__)\[(__IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \(conversation with \3\[\4\] timed out while sending __COMMAND__\)$',
        'recipient = 2',
        'server_hostname = 3, server_ip = 4',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 8007B41CD: host redir-mail-telehouse2.gandi.net[217.70.178.1] refused to talk to me: 450 Server configuration problem
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('Server refused to talk (short)', 'Another server refusing to talk',
        'postfix/smtp',
        '^(__QUEUEID__): host (__HOSTNAME__)\[(__IP__)\] refused to talk to me: ((__SMTP_CODE__).*)$',
        'data = 4, smtp_code = 5',
        'server_hostname= 2, server_ip = 3',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 01061437E: lost connection with mx1.mail.yahoo.com[4.79.181.168] while sending end of data -- message may be sent more than once
-- BCF8638BC: conversation with mail.tesco.ie[195.7.43.146] timed out while sending end of data -- message may be sent more than once
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
VALUES('Lost connection after data', 'Lost connection after end-of-data - message may be sent more than once',
        'postfix/smtp',
        '^(__QUEUEID__): (?:lost connection with|conversation with) (__HOSTNAME__)\[(__IP__)\] (?:while sending end of data|timed out while sending end of data) -- message may be sent more than once$',
        '',
        'server_hostname = 2, server_ip = 3',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 5F505437C: to=<smcblvacprbio@ekholden.com>, relay=none, delay=241762, status=bounced (Host or domain name not found. Name service error for name=ekholden.com type=A: Host found but no data record of requested type)
-- 94C1643AB: to=<alicechateau@royahoo.com>, relay=none, delay=0, status=bounced (Name service error for name=royahoo.com type=MX: Malformed name server reply)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, connection_data, action, queueid, postfix_action)
    VALUES('Malformed DNS reply, or no data', 'The DNS reply was malformed, or the requested record was not found',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=bounced \(((?:Host or domain name not found. )?Name service error for name=__HOSTNAME__ type=(?:A|AAAA|MX): (?:Malformed name server reply|Host found but no data record of requested type))\)$',
        'recipient = 2, data = 3',
        '',
        'smtp_code = 554',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'BOUNCED'
);

-- }}}


-- LOCAL RULES {{{1


-- 3FF7C4317: to=<mcadoor@cs.tcd.ie>, relay=local, delay=0, status=sent (forwarded as 56F5B43FD)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, connection_data, action, queueid, postfix_action)
    VALUES('Mail reinjected for forwarding', 'The mail was sent to a local address, but is aliased to an external address',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=sent \(forwarded as (__QUEUEID__)\)$',
        'recipient = 2, child = 3',
        '',
        'smtp_code = 250',
        'client_hostname = localhost, client_ip = 127.0.0.1, server_hostname = localhost, server_ip = 127.0.0.1',
        'TRACK',
        1,
        'SENT'
);

-- This will be followed by a 'postfix/qmgr: 8025E43F0: removed' line, so don't commit yet.
-- 7FD1443FD: to=<tobinjt@cs.tcd.ie>, orig_to=<root>, relay=local, delay=0, status=sent (delivered to command: /mail/procmail/bin/procmail -p -t /mail/procmail/etc/procmailrc)
-- 8025E43F0: to=<tobinjt@cs.tcd.ie>, relay=local, delay=0, status=sent (delivered to command: /mail/procmail/bin/procmail -p -t /mail/procmail/etc/procmailrc)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, connection_data, action, queueid, postfix_action)
    VALUES('Mail has been delivered locally', 'Mail has been delivered to the LDA (typically procmail)',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=sent \((delivered to command: .*)\)$',
        'recipient = 2, data = 3',
        '',
        'smtp_code = 250',
        'server_hostname = localhost, server_ip = 127.0.0.1, client_ip = 127.0.0.1, client_hostname = localhost',
        'SAVE_BY_QUEUEID',
        1,
        'SENT'
);

-- table cdb:/mail/postfix/etc/aliases.out(0,34100) has changed -- restarting
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Postfix noticed a table changed', 'Postfix noticed that a lookup table has changed, so it is restarting',
        'postfix/local',
        '^table .* has changed -- restarting$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- D9FC14493: to=<osulldps@cs.tcd.ie>, orig_to=<declan.osullivan@cs.tcd.ie>, relay=local, delay=2, status=deferred (temporary failure. Command output: procmail: Quota exceeded while writing "/users/staff/osulldps/Maildir/tmp/1157969601.28098_0.relay.cs.tcd.ie" )
-- E7ED243DA: to=<muckleys@cs.tcd.ie>, relay=local, delay=223453, status=deferred (temporary failure. Command output: procmail: Couldn't chdir to "/users/pg/muckleys" procmail: Couldn't chdir to "/users/pg/muckleys" procmail: Couldn't chdir to "/users/pg/muckleys/Maildir" procmail: Unable to treat as directory "./new" procmail: Skipped "." )
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Local delivery failed temporarily', 'Something went wrong with local delivery, so it will be retried later',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \(temporary failure. Command output: (.*)\)$',
        'recipient = 2, data = 3',
        '',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- 609504400: to=<gap@cs.tcd.ie>, relay=local, delay=0, status=bounced (mail forwarding loop for gap@cs.tcd.ie)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, action, queueid, postfix_action)
    VALUES('Mail forwarding loop', 'Postfix bounced a mail due to a mail forwarding loop',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=bounced \(mail forwarding loop for \2\)$',
        'recipient = 2',
        '',
        'smtp_code = 554',
        'SAVE_BY_QUEUEID',
        1,
        'BOUNCED'
);

-- warning: required alias not found: mailer-daemon
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Postifx warning about something', 'Postfix has logged a warning; probably it should be investigated',
        'postfix/local',
        '^warning: required alias not found: .*$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- A15004400: to=<Jean-Marc.Seigneur@cs.tcd.ie>, relay=local, delay=0, status=bounced (unknown user: "jean-marc.seigneur")
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, connection_data, action, queueid, postfix_action)
    VALUES('Unknown user??  This should have been caught long ago!', 'We should never have an unknown user at this stage, it should have been caught by smtpd',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=bounced \((unknown user: ".*")\)$',
        'recipient = 2, data = 3',
        '',
        'smtp_code = 550',
        'client_ip = 127.0.0.1, client_hostname = localhost, server_ip = 127.0.0.1, server_hostname = localhost',
        'SAVE_BY_QUEUEID',
        1,
        'BOUNCED'
);

-- 165173E19: to=<pbyrne6@cs.tcd.ie>, relay=local, delay=0, status=sent (delivered to file: /dev/null)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, action, queueid, postfix_action)
    VALUES('Local delivery to a file was successful', 'Local delivery of an email succeeded; the final destination was a file',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=sent \(delivered to file: (.*)\)$',
        'recipient = 2, data = 3',
        '',
        'smtp_code = 250',
        'SAVE_BY_QUEUEID',
        1,
        'SENT'
);

-- 8344043FD: to=<MAILER-DAEMON@cs.tcd.ie>, relay=local, delay=0, status=sent (discarded)
-- 1522F4317: to=<MAILER-DAEMON@cs.tcd.ie>, orig_to=<MAILER-DAEMON>, relay=local, delay=0, status=sent (discarded)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, action, queueid, postfix_action)
    VALUES('local delivery - discarded??', 'Why was a locally delivered mail discarded??  Should be investigated I think',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=sent \(discarded\)$',
        'recipient = 2',
        '',
        'smtp_code = 250',
        'SAVE_BY_QUEUEID',
        1,
        'SENT'
);

-- E3B36450D: to=<eganjo@cs.tcd.ie>, relay=local, delay=36526, status=deferred (temporary failure)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Temporary failure in local delivery', 'Temporary unspecified failure in local delivery',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \(temporary failure\)$',
        'recipient = 2',
        '',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- warning: database /mail/postfix/etc/aliases.out.cdb is older than source file /mail/postfix/etc/aliases.out
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('The aliases file was not rebuilt', 'The aliases file is newer than the compiled database',
        'postfix/local',
        '^warning: database .* is older than source file .*$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- 5822E4444: to=<cogsci@cs.tcd.ie>, relay=local, delay=0, status=deferred (cannot find alias database owner)
-- 05CC64462: to=<cs-ugvisitors-list@cs.tcd.ie>, orig_to=<alldayug-list@cs.tcd.ie>, relay=local, delay=1, status=deferred (cannot find alias database owner)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Delivery delayed, owner unknown', 'Delivery was delayed because the owenr of the alias files is unknown',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=deferred \(cannot find alias database owner\)$',
        'recipient = 2',
        '',
        'SAVE_BY_QUEUEID',
        1,
        'INFO'
);

-- This sometimes results when a local delivery fails and this bounce is generated; in that case the {client,server}_{ip,hostname} will be empty, so we supply them.  If they're not required they'll be discarded.
-- D1E494386: to=<scss-staff-bounces+bcollin=cs.tcd.ie@cs.tcd.ie>, relay=local, delay=0, status=bounced (Command died with status 8: "/mail/mailman-2.1.6/mail/mailman bounces scss-staff". Command output: Failure to find group name mailman.  Try adding this group to your system, or re-run configure, providing an existing group name with the command line option --with-mail-gid. )
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, connection_data, action, queueid, postfix_action)
    VALUES('Local delivery (pipe to command) failed', 'The command that the mail was piped into failed for some reason',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__DSN__, )?status=bounced \((Command died with status \d+: .* Command output: .* )\)$',
        'recipient = 2, data = 3',
        '',
        'smtp_code = 550',
        'server_hostname = localhost, server_ip = 127.0.0.1, client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_BY_QUEUEID',
        1,
        'BOUNCED'
);

-- warning: cannot find alias database owner for cdb:/mail/mailman/data/aliases(0,34100)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Table owner cannot be determined', 'The owner of the table foo cannot be determined; probably becaise Solaris LDAP has gone for a nap',
        'postfix/local',
        '^warning: cannot find alias database owner for .*$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- warning: 781E44393: address with illegal extension: mailman-bounces+john_collins/hq/omron_europe.omron=eu.omron.com
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('warning from local', 'A warning message from the local delivery agent',
        'postfix/local',
        '^warning: (__QUEUEID__): address with illegal extension: .*$',
        '',
        '',
        'IGNORE',
        1,
        'IGNORED'
);

-- warning: file /users/pg/steicheb/.forward is not a regular file
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('warning about messed up .forward', 'A warning message from the local delivery agent about a mesed up .forward',
        'postfix/local',
        '^warning: file .*.forward is not a regular file$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- 1}}}

-- PICKUP RULES {{{1

-- 39DE44317: uid=8515 from=<kennyau>
-- 0109D38EC: uid=0 from=<vee08-pc-request@cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, connection_data, action, queueid, postfix_action)
    VALUES('Mail submitted with sendmail', 'Mail submitted locally on the machine via sendmail is being picked up',
        'postfix/pickup',
        '^(__QUEUEID__): uid=\d+ from=<__EMAIL__>$',
        '',
        '',
        'client_hostname = localhost, client_ip = 127.0.0.1, server_hostname = localhost, server_ip = 127.0.0.1',
        'PICKUP',
        1,
        'INFO'
);

-- }}}

-- POSTSUPER RULES {{{1

-- 5A01B444E: removed
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, action, queueid, postfix_action)
    VALUES('Mail deleted using postsuper', 'The mail administrator used postsuper to delete mail from the queue',
        'postfix/postsuper',
        '^(__QUEUEID__): removed$',
        '',
        '',
        'smtp_code = 554',
        'COMMIT',
        1,
        'DELETED'
);

-- Deleted: 1 message
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Postsuper logging how many messages were deleted', 'Postsuper logs how many messages were deleted by the administrator',
        'postfix/postsuper',
        '^Deleted: \d+ message(?:s)?$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- fatal: usage: postsuper [-c config_dir] [-d queue_id (delete)] [-h queue_id (hold)] [-H queue_id (un-hold)] [-p (purge temporary files)] [-r queue_id (requeue)] [-s (structure fix)] [-v (verbose)] [queue...]
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Postsuper usage message', 'Postsuper logging its usage message',
        'postfix/postsuper',
        '^fatal: usage: postsuper .*$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- fatal: invalid directory name: 2F03B38A4
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Postsuper invalid directory message', 'Postsuper complaining about an invalid directory name',
        'postfix/postsuper',
        '^fatal: invalid directory name: .*$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- }}}

-- CLEANUP RULES {{{1

-- 8D6A74406: message-id=<546891334.17703392316576@thebat.net>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Cleanup doing its thing', 'Cleanup doing whatever it does with mail',
        'postfix/cleanup',
        '^(__QUEUEID__): (?:resent-)?message-id=(__MESSAGE_ID__)$',
        'message_id = 2',
        '',
        'MAIL_PICKED_FOR_DELIVERY',
        '1',
        'PROCESSING'
);

-- warning: 9701438A4: read timeout on cleanup socket
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Something went wrong reading mail', 'Cleanup did not get the full mail',
        'postfix/cleanup',
        '^warning: __QUEUEID__: read timeout on cleanup socket$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- warning: stripping too many comments from address: Mail Administrator <Postmaster@charter.net> <Postmaster@charter.net> <Postmaster@charter.net> <Postm...
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Warning about messed-up addressing', 'Mail client fscked up the addressing',
        'postfix/cleanup',
        '^warning: stripping too many comments from address: .*$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- warning: cleanup socket: unexpected EOF in data, record type 78 length 76
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Warning about protocol error', 'Something messed up the protocol',
        'postfix/cleanup',
        '^warning: cleanup socket: unexpected EOF in data, record type \d+ length \d+$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- }}}

-- BOUNCE RULES {{{1

-- 382CD36E3: sender non-delivery notification: 4419C38A0
-- A81E338BB: sender delivery status notification: 4427638C1
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Postfix created a bounce or delivery status message', 'Postfix created a bounce or delivery status message',
        'postfix/bounce',
        '^(__QUEUEID__): sender (?:delivery status|non-delivery) notification: (__QUEUEID__)$',
        'child = 2',
        '',
        'BOUNCE',
        1,
        'BOUNCED'
);

-- }}}

-- -- MASTER RULES {{{1

-- daemon started -- version 2.2.10, configuration /mail/postfix-2.2.10/etc
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Postfix started', 'Postfix master daemon started',
        'postfix/master',
        '^daemon started -- version \d+\.\d+\.\d+, configuration .*$',
        '',
        '',
        'POSTFIX_RELOAD',
        0,
        'POSTFIX_RELOAD'
);

-- reload configuration /mail/postfix-2.2.10/etc
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Postfix reload', 'Postfix master daemon reloaded configuration',
        'postfix/master',
        '^reload configuration .*$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- terminating on signal 15
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Postfix stop', 'Postfix master daemon stopped',
        'postfix/master',
        '^terminating on signal 15$',
        '',
        '',
        'POSTFIX_RELOAD',
        0,
        'POSTFIX_RELOAD'
);

-- warning: /mail/postfix/libexec/smtpd: bad command startup -- throttling
-- warning: ignoring inet_protocols change
-- warning: to change inet_protocols, stop and start Postfix
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Warning of some sort', 'Master logging a warning about something',
        'postfix/master',
        '^warning: .*$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- warning: process /mail/postfix/libexec/smtpd pid 17850 killed by signal 15
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, action, queueid, postfix_action, priority)
    VALUES('Master daemon killed an smtpd', 'Master daemon had to kill an smtpd forcefully',
        'postfix/master',
        '^warning: process .*/libexec/smtpd pid \d+ killed by signal \d+$',
        '',
        '',
        'pid_regex = pid (\d+) killed by signal',
        'SMTPD_DIED',
        0,
        'IGNORED',
        5
);

-- warning: process /mail/postfix/libexec/smtpd pid 13510 exit status 1
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, result_data, action, queueid, postfix_action)
    VALUES('smtpd died', 'An smtpd died for some reason',
        'postfix/master',
        '^warning: process .*/libexec/smtpd pid \d+ exit status \d+$',
        '',
        '',
        'pid_regex = pid (\d+) exit status',
        'SMTPD_DIED',
        0,
        'IGNORED'
);

-- }}}

-- * RULES {{{
-- These rules are applied to all log lines, after the program specific rules.
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Bloody Solaris LDAP', 'Solaris LDAP is trying to load something or other',
        '*',
        '^libsldap: Status: 2  Mesg: Unable to load configuration ./var/ldap/ldap_client_file. \(..\).$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Bloody Solaris LDAP 2', 'Solaris LDAP cannot connect or something',
        '*',
        '^libsldap: Status: 7  Mesg: Session error no available conn.$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Bloody Solaris LDAP 3', 'Solaris LDAP cannot bind or connect or something',
        '*',
        '^libsldap: Status: 91  Mesg: openConnection: simple bind failed - Can.t connect to the LDAP server$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
    VALUES('Bloody Solaris LDAP 4', 'Solaris LDAP cannot contact server',
        '*',
        '^libsldap: Status: 81  Mesg: openConnection: simple bind failed - Can.t contact LDAP server$',
        '',
        '',
        'IGNORE',
        0,
        'IGNORED'
);

-- }}}

-- INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid, postfix_action)
--     VALUES('', '',
--         '',
--         '',
--         '',
--         '',
--         'SAVE',
--         
-- );

