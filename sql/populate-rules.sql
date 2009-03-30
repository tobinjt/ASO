-- vim: set foldmethod=marker textwidth=10000 :
-- $Id$

DELETE FROM rules;

-- SMTPD CONNECT RULES {{{1
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('client connection', 'A client has connected',
        'postfix/smtpd',
        '^connect from (__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\]$',
        'server_hostname = localhost, server_ip = 127.0.0.1',
        'CONNECT'
);

-- }}}

-- SMTPD DISCONNECT RULES {{{1
INSERT INTO rules(name, description, program, regex, action)
    VALUES('client disconnection', 'The client has disconnected cleanly',
        'postfix/smtpd',
        '^disconnect from __CLIENT_HOSTNAME__\[__CLIENT_IP__\]$',
        'DISCONNECT'
);

-- }}}

-- SMTPD ERROR RULES {{{1
-- These cause the mail to be discarded.
INSERT INTO rules(name, description, program, regex, result_data, action, priority)
    VALUES('Timeout after DATA command from client', 'Timeout reading data from the client, mail will be discarded',
        'postfix/smtpd',
        '^timeout after DATA (?:\(\d+ bytes\) )?from (__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\]$',
        'sender = unknown, recipient = unknown, smtp_code = unknown',
        'TIMEOUT',
        5
);

INSERT INTO rules(name, description, program, regex, result_data, action, priority)
    VALUES('Lost connection after DATA command from client', 'Lost connection reading data from the client, mail will be discarded',
        'postfix/smtpd',
        '^lost connection after DATA (?:\(\d+ bytes\) )?from (__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\]$',
        'sender = unknown, recipient = unknown, smtp_code = unknown',
        'TIMEOUT',
        5
);

-- warning: 03F6E38CA: queue file size limit exceeded
INSERT INTO rules(name, description, program, regex, result_data, action, priority)
    VALUES('Client exceeded the maximum mail size', 'Client exceeded the maximum mail size, mail will be discarded',
        'postfix/smtpd',
        '^warning: __QUEUEID__: queue file size limit exceeded$',
        'sender = unknown, recipient = unknown, smtp_code = unknown',
        'MAIL_TOO_LARGE',
        5
);

-- }}}

-- SMTPD IGNORE RULES {{{1
-- These will always be followed by a disconnect line, as matched above
INSERT INTO rules(name, description, program, regex, action)
    VALUES('lost connection', 'Client disconnected uncleanly',
        'postfix/smtpd',
        '^lost connection after __SHORT_CMD__ from __CLIENT_HOSTNAME__\[__CLIENT_IP__\]$',
        'UNINTERESTING'
);

INSERT INTO rules(name, description, program, regex, action)
    VALUES('Timeout reading reply', 'Timeout reading reply from client',
        'postfix/smtpd',
        '^timeout after __SHORT_CMD__ from __CLIENT_HOSTNAME__\[__CLIENT_IP__\]$',
        'UNINTERESTING'
);

INSERT INTO rules(name, description, program, regex, action)
    VALUES('Too many errors', 'The client has made so many errors postfix has disconnected it',
        'postfix/smtpd',
        '^too many errors after (?:\w+|END-OF-MESSAGE) (?:\(\d+ bytes\) )?from __CLIENT_HOSTNAME__\[__CLIENT_IP__\]$',
        'UNINTERESTING'
);

-- gethostbyaddr: eta.routhost.com. != 66.98.227.100
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Mismatched DNS warning', 'A warning about mismatched DNS',
        'postfix/smtpd',
        '^gethostbyaddr: __CLIENT_HOSTNAME__ != __CLIENT_IP__$',
        'UNINTERESTING'
);

-- Other lines we want to ignore
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Warning', 'Warnings of some sort',
        'postfix/smtpd',
        '^warning: .*$',
        'UNINTERESTING'
);

INSERT INTO rules(name, description, program, regex, action)
    VALUES('Table changed', 'A lookup table has changed, smtpd is quitting',
        'postfix/smtpd',
        '^table .* has changed -- restarting$',
        'UNINTERESTING'
);

INSERT INTO rules(name, description, program, regex, action)
    VALUES('Fatal error', 'Fatal error of some sort',
        'postfix/smtpd',
        '^fatal: .*$',
        'UNINTERESTING'
);

-- NOTE: SEE big-regex-rule ALSO.

-- }}}

-- SMTPD FATAL RULES {{{1

-- fatal: watchdog timeout
INSERT INTO rules(name, description, program, regex, action, priority)
    VALUES('Watchdog timeout', 'Watchdog timed out; kill the active connection.',
        'postfix/smtpd',
        '^fatal: watchdog timeout$',
        'SMTPD_WATCHDOG',
        5
);

-- }}}


-- SMTPD REJECT RULES {{{1
-- __RESTRICTION_START__ has four capturing parentheses, so *_cols and back 
-- references start at 5 not 1.

-- <munin@cs.tcd.ie>: Recipient address rejected: User unknown in local recipient table; from=<> to=<munin@cs.tcd.ie> proto=ESMTP helo=<lg12x22.cs.tcd.ie>
-- <hienes@cs.tcd.ie>: Recipient address rejected: User unknown in local recipient table; from=<BrooksPool@rowcmi.org> to=<hienes@cs.tcd.ie> proto=ESMTP helo=<PETTERH?DNEB?>
-- <rt@cs.tcd.ie>: Recipient address rejected: User unknown; from=<Leynard563@aikon-trading.com> to=<rt@cs.tcd.ie> proto=ESMTP helo=<imx1.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Unknown recipient', 'The recipient address is unknown on our system',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: User unknown(?: in \w+ \w+ table)?; from=<(__SENDER__)> to=<__RECIPIENT__> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_unlisted_recipient',
        4
);

-- <  sharyn.davies@cs.tcd.ie>: Recipient address rejected: User unknown in local recipient table; from=<newsletter@globalmediaserver.com> to=<??sharyn.davies@cs.tcd.ie> proto=ESMTP helo=<mail1.globalmediaserver.com>
-- <greedea@cs.tcd.ie>: Recipient address rejected: User unknown in local recipient table; from=<<>@inprima.locaweb.com.br> to=<greedea@cs.tcd.ie> proto=ESMTP helo=<hm22.locaweb.com.br>
INSERT INTO rules(name, description, program, regex, action, priority, restriction_name, cluster_group_id)
    VALUES('A weird address was rejected', 'A weird address was rejected by Postfix, and may have been escaped',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: User unknown in \w+ \w+ table; from=<(__SENDER__)> to=<__RECIPIENT__> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        -1,
        'reject_unlisted_recipient',
        4
);

-- <munin@cs.tcd.ie>: Sender address rejected: User unknown in local recipient table; from=<munin@cs.tcd.ie> to=<john.tobin@cs.tcd.ie> proto=ESMTP helo=<lg12x36.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Unknown sender', 'The sender address is unknown on our system',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: User unknown in \w+ \w+ table; from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_unlisted_sender',
        4
);

-- <                      >: Sender address rejected: User unknown in local recipient table; from=<??????????????????????> to=<emcmanus@cs.tcd.ie> proto=SMTP helo=<mail.com>
INSERT INTO rules(name, description, program, regex, action, priority, restriction_name, cluster_group_id)
    VALUES('Unknown sender (escaped)', 'The sender address is unknown on our system (postfix escaped it)',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: User unknown in \w+ \w+ table; from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        -1,
        'reject_unlisted_sender',
        4
);

-- <ocalladw@toad.toad>: Sender address rejected: Domain not found; from=<ocalladw@toad.toad> to=<submit@bugs.gnome.org> proto=SMTP helo=<toad>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Unknown sender domain', 'We do not accept mail from unknown domains',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Domain not found; from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_unknown_sender_domain',
        4
);

-- <                     @thai.co.th>: Sender address rejected: Domain not found; from=<?????????????????????@thai.co.th> to=<faircloc@cs.tcd.ie> proto=SMTP helo=<mail.com>
INSERT INTO rules(name, description, program, regex, action, priority, restriction_name, cluster_group_id)
    VALUES('Unknown sender domain (escaped)', 'We do not accept mail from unknown domains (postfix partially escaped it)',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Domain not found; from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        -1,
        'reject_unknown_sender_domain',
        4
);

-- <stephen@tjbx.org>: Recipient address rejected: Domain not found; from=<4sdcsaz@nbsanjiang.com> to=<stephen@tjbx.org> proto=ESMTP helo=<nbsanjiang.com>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Unknown recipient domain', 'We do not accept mail for unknown domains',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Domain not found; from=<(__SENDER__)> to=<__RECIPIENT__> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_unknown_recipient_domain',
        4
);

-- Service unavailable; Client host [190.40.116.202] blocked using sbl-xbl.spamhaus.org; from=<taliaferraearl@blackburn-green.com> to=<amjudge@dsg.cs.tcd.ie> proto=SMTP helo=<blackburn-green.com>
-- Service unavailable; Client host [211.212.156.4] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/query/bl?ip=211.212.156.4; from=<lucia@abouttimemag.com> to=<amjudge@dsg.cs.tcd.ie> proto=SMTP helo=<abouttimemag.com>
-- Service unavailable; Client host [66.30.84.174] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/query/bl?ip=66.30.84.174; from=<DianaBoykin@movemail.com> to=<Paolo.Rosso@cs.tcd.ie> proto=SMTP helo=<b100mng10bce9ob.hsd1.ma.comcast.net.>
-- Service unavailable; Client host [210.236.32.153] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/SBL/sbl.lasso?query=SBL47877; from=<euyery@linuxmail.org> to=<vinny.cahill@cs.tcd.ie> proto=SMTP helo=<eworuetyberiyneortmweprmuete57197179680.com>
-- Service unavailable; Client host [204.14.1.123] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/SBL/sbl.lasso?query=SBL27197 / http://www.spamhaus.org/SBL/sbl.lasso?query=SBL47903; from=<tia@baraskaka.com> to=<vjcahill@dsg.cs.tcd.ie> proto=SMTP helo=<customer.optindirectmail.123.sls-hosting.com>
-- Service unavailable; Client host [82.119.202.142] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/query/bl?ip=82.119.202.142; from=<001topzine-hypertext@123point.net> to=<ecdlf@cs.tcd.ie.> proto=ESMTP helo=<cs.tcd.ie.>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Blacklisted by SpamHaus SBL-XBL', 'The client IP address is blacklisted by SpamHaus SBL-XBL',
        'postfix/smtpd',
        '^__RESTRICTION_START__ Service unavailable; Client host (?>\[(__CLIENT_IP__)\]) blocked using sbl-xbl.spamhaus.org;(?:(__DATA__(?:(?:(?: http://www.spamhaus.org/SBL/sbl.lasso\?query=\w+)|(?: http://www.spamhaus.org/query/bl\?ip=\k<client_ip>))(?: /)?)*);)? (?>from=<(__SENDER__)>) to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_rbl_client',
        6
);

-- Service unavailable; Client host [220.104.147.28] blocked using zen.spamhaus.org; http://www.spamhaus.org/query/bl?ip=220.104.147.28; from=<sakuran_b0@yahoo.co.jp> to=<stephen.barrett@cs.tcd.ie> proto=SMTP helo=<eruirutkjshfk.com>
-- Service unavailable; Client host [201.231.83.38] blocked using zen.spamhaus.org; from=<contact@digitalav.com> to=<gerry@cs.tcd.ie> proto=SMTP helo=<38-83-231-201.fibertel.com.ar>
-- Service unavailable; Client host [141.146.5.10] blocked using zen.spamhaus.org; http://www.spamhaus.org/SBL/sbl.lasso?query=SBL56587; from=<replies@oracle-mail.com> to=<TOBINJT@CS.TCD.IE> proto=ESMTP helo=<acsebinet200.oracleeblast.com>
-- Service unavailable; Client host [72.5.205.6] blocked using zen.spamhaus.org; http://www.spamhaus.org/SBL/sbl.lasso?query=SBL45324; from=<info@BreakthroughExperts.com> to=<vjcahill@dsg.cs.tcd.ie> proto=ESMTP helo=<BreakthroughExperts.com>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Blacklisted by SpamHaus Zen', 'The client IP address is blacklisted by SpamHaus Zen',
        'postfix/smtpd',
        '^__RESTRICTION_START__ Service unavailable; Client host (?>\[(__CLIENT_IP__)\]) blocked using zen.spamhaus.org; (?:(__DATA__(?:http://www.spamhaus.org/(?:query/bl\?ip=\k<client_ip>|SBL/sbl.lasso\?query=[^\s]+))| / )+; )?from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_rbl_client',
        6
);

-- Service unavailable; Client host [80.236.27.105] blocked using list.dsbl.org; http://dsbl.org/listing?80.236.27.105; from=<mrnpftjx@pacbell.net> to=<tom.irwin@cs.tcd.ie> proto=SMTP helo=<ip-105.net-80-236-27.asnieres.rev.numericable.fr>
-- Service unavailable; Client host [82.159.196.151] blocked using list.dsbl.org; from=<vrespond@cima.com.my> to=<irwin@cs.tcd.ie> proto=SMTP helo=<pc.bcs>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Blacklisted by DSBL', 'The client IP address is blacklisted by DSBL',
        'postfix/smtpd',
        '^__RESTRICTION_START__ Service unavailable; Client host (?>\[(__CLIENT_IP__)\]) blocked using list.dsbl.org; (?:(?>(__DATA__http://dsbl.org/listing\?\k<client_ip>);) )?from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_rbl_client',
        6
);

-- Service unavailable; Client host [148.243.214.52] blocked using relays.ordb.org; This mail was handled by an open relay - please visit <http://ORDB.org/lookup/?host=148.243.214.52>; from=<cw-chai@umail.hinet.net> to=<webmaster@cs.tcd.ie> proto=ESMTP helo=<sicomnet.edu.mx>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Blacklisted by ordb.org', 'The client IP address is blacklisted by ordb.org',
        'postfix/smtpd',
        '^__RESTRICTION_START__ Service unavailable; Client host (?>\[(__CLIENT_IP__)\]) blocked using relays.ordb.org; (?>(__DATA__This mail was handled by an open relay - please visit <http://ORDB.org/lookup/\?host=\k<client_ip>>);) from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_rbl_client',
        6
);

-- Service unavailable; Client host [60.22.99.9] blocked using cbl.abuseat.org; Blocked - see http://cbl.abuseat.org/lookup.cgi?ip=60.22.99.9; from=<pegbxbsusiiao@cowboyart.net> to=<daokeeff@cs.tcd.ie> proto=SMTP helo=<cowboyart.net>
-- Service unavailable; Client host [90.194.116.50] blocked using cbl.abuseat.org; from=<lazauear@appleleasing.com> to=<noctor@cs.tcd.ie> proto=SMTP helo=<appleleasing.com>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Blacklisted by CBL', 'The client IP address is blacklisted by CBL',
        'postfix/smtpd',
        '^__RESTRICTION_START__ Service unavailable; Client host (?>\[(__CLIENT_IP__)\]) blocked using cbl.abuseat.org;(?>(__DATA__ Blocked - see http://cbl.abuseat.org/lookup.cgi\?ip=\k<client_ip>);)? from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_rbl_client',
        6
);

-- <31.pool80-103-5.dynamic.uni2.es[80.103.5.31]>: Client host rejected: Greylisted, see http://isg.ee.ethz.ch/tools/postgrey/help/dsg.cs.tcd.ie.html; from=<iqxrgomtl@purinmail.com> to=<skenny@dsg.cs.tcd.ie> proto=SMTP helo=<31.pool80-103-5.dynamic.uni2.es>
-- <mail.saraholding.com.sa[212.12.166.254]>: Client host rejected: Greylisted, see http://isg.ee.ethz.ch/tools/postgrey/help/cs.tcd.ie.html; from=<lpty@[212.12.166.226]> to=<colin.little@cs.tcd.ie> proto=ESMTP helo=<mail.saraholding.com.sa>
-- <flow.helderhosting.nl[82.94.236.142]>: Client host rejected: Greylisted, see http://isg.ee.ethz.ch/tools/postgrey/help/cs.tcd.ie.html; from=<www-data@info+spam@helderhosting.nl> to=<siobhan.clarke@cs.tcd.ie> proto=SMTP helo=<flow.helderhosting.nl>
-- <host10-102.pool82104.interbusiness.it[82.104.102.10]>: Client host rejected: Greylisted, see http://postgrey.schweikert.ch/help/cs.tcd.ie.html; from=<Tania@nis-portal.de> to=<mite-00@cs.tcd.ie> proto=SMTP helo=<host10-102.pool82104.interbusiness.it>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Greylisted', 'Client greylisted; see http://www.greylisting.org/ for more details',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\]>: Client host rejected: Greylisted, see (__DATA__http://postgrey.schweikert.ch/help/[^\s]+|http://isg.ee.ethz.ch/tools/postgrey/help/[^\s]+); from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_policy_service',
        6
);

-- <huggardm@cs.tcd.ie>: Recipient address rejected: Greylisted, see http://postgrey.schweikert.ch/help/cs.tcd.ie.html; from=<fool@foolmail.co.uk> to=<huggardm@cs.tcd.ie> proto=SMTP helo=<maccullagh.maths.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Greylisted recipient', 'Recipient greylisted; see http://www.greylisting.org/ for more details',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Greylisted, see (__DATA__http://postgrey.schweikert.ch/help/.*|http://isg.ee.ethz.ch/tools/postgrey/help/.*); from=<(__SENDER__)> to=<__RECIPIENT__> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_policy_service',
        6
);

-- <nicholas@seaton.biz>: Sender address rejected: Address uses MX in loopback address space (127.0.0.0/8); from=<nicholas@seaton.biz> to=<gillian.long@cs.tcd.ie> proto=ESMTP helo=<friend>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Sender MX in loopback address space', 'The MX for sender domain is in loopback address space, so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in loopback address space \(127.0.0.0/8\); from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_mx_access',
        4
);

-- <root@inet.microlins.com.br>: Sender address rejected: Address uses MX in private address space (172.16.0.0/12); from=<root@inet.microlins.com.br> to=<stephen.farrell@cs.tcd.ie> proto=ESMTP helo=<inet.microlins.com.br>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Sender MX in private address space (172.16.0.0/12)', 'The MX for sender domain is in private address space (172.16.0.0/12), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in private address space \(172.16.0.0/12\); from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_mx_access',
        4
);

-- NOQUEUE: reject: RCPT from unknown[123.190.117.163]: 550 5.7.1 <cji1031@scourt.go.kr>: Recipient address rejected: Address uses MX in private address space (172.16.0.0/12); from=<qm73z1@paran.com> to=<cji1031@scourt.go.kr> proto=SMTP helo=<123.190.117.163>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Recipient MX in private address space (172.16.0.0/12)', 'The MX for recipient domain is in private address space (172.16.0.0/12), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Address uses MX in private address space \(172.16.0.0/12\); from=<(__SENDER__)> to=<__RECIPIENT__> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_recipient_mx_access',
        4
);

-- <aaholi@web009.ahp01.lax.affinity.com>: Sender address rejected: Address uses MX in private address space (127.16.0.0/12); from=<aaholi@web009.ahp01.lax.affinity.com> to=<luzs@cs.tcd.ie> proto=ESMTP helo=<ams006.lax.affinity.com> 
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Sender MX in private address space (127.16.0.0/12)', 'The MX for sender domain is in private address space (127.16.0.0/12), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in private address space \(127.16.0.0/12\); from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_mx_access',
        4
);

-- <hlhbs@china.org.cn>: Recipient address rejected: Address uses MX in private address space (127.16.0.0/12); from=<1221q5@chinachewang.com> to=<hlhbs@china.org.cn> proto=ESMTP helo=<chinachewang.com>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Recipient MX in private address space (127.16.0.0/12)', 'The MX for recipient domain is in private address space (127.16.0.0/12), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Address uses MX in private address space \(127.16.0.0/12\); from=<(__SENDER__)> to=<__RECIPIENT__> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_recipient_mx_access',
        4
);

-- <aeneasdecathlon@rotnot.com>: Sender address rejected: Address uses MX in private address space (192.168.0.0/16); from=<aeneasdecathlon@rotnot.com> to=<MCCARTHY@CS.tcd.ie> proto=ESMTP helo=<vms1.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Sender MX in private address space (192.168.0.0/16)', 'The MX for sender domain is in private address space (192.168.0.0/16), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in private address space \(192.168.0.0/16\); from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_mx_access',
        4
);

-- <showh@tdt3.com.tw>: Recipient address rejected: Address uses MX in private address space (192.168.0.0/16); from=<zsl.gzrza@yahoo.com.tw> to=<showh@tdt3.com.tw> proto=SMTP helo=<134.226.32.56>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Recipient MX in private address space (192.168.0.0/16)', 'The MX for Recipient domain is in private address space (192.168.0.0/16), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Address uses MX in private address space \(192.168.0.0/16\); from=<(__SENDER__)> to=<__RECIPIENT__> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_recipient_mx_access',
        4
);

-- <acornascription@rot.wartesaal.darktech.org>: Sender address rejected: Address uses MX in private address space (10.0.0.0/8); from=<acornascription@rot.wartesaal.darktech.org> to=<gap@cs.tcd.ie> proto=ESMTP helo=<xmx1.tcd.ie>
-- <artlesslyLumi re's@wildsecretary.com>: Sender address rejected: Address uses MX in private address space (10.0.0.0/8); from=<artlesslyLumi?re's@wildsecretary.com> to=<carol.osullivan@cs.tcd.ie> proto=ESMTP helo=<home.tvscable.com>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Sender MX in private address space (10.0.0.0/8)', 'The MX for sender domain is in private address space (10.0.0.0/8), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in private address space \(10.0.0.0/8\); from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_mx_access',
        4
);

-- <mactusqdx@wartesaal.darktech.org>: Recipient address rejected: Address uses MX in private address space (10.0.0.0/8); from=<bartel@integramed.com> to=<mactusqdx@wartesaal.darktech.org> proto=SMTP helo=<integramed.com>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Recipient MX in private address space (10.0.0.0/8)', 'The MX for recipient domain is in private address space (10.0.0.0/8), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Address uses MX in private address space \(10.0.0.0/8\); from=<(__SENDER__)> to=<__RECIPIENT__> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_recipient_mx_access',
        4
);

-- <banihashemian@modares.ac.ir>: Sender address rejected: Address uses MX in local address space (169.254.0.0/16); from=<banihashemian@modares.ac.ir> to=<Elisa.Baniassad@cs.tcd.ie> proto=ESMTP helo=<mail-relay1.cs.ubc.ca>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Sender MX in "local" address space (169.254.0.0/16)', 'The MX for sender domain is in "local" address space (169.254.0.0/16), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in local address space \(169.254.0.0/16\); from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_mx_access',
        4
);

-- <sble@corn.kiev.ua>: Recipient address rejected: Address uses MX in "this" address space (0.0.0.0/8); from=<-sol@hinet.net> to=<sble@corn.kiev.ua> proto=SMTP helo=<125-225-33-196.dynamic.hinet.net>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Recipient MX in "this" address space (0.0.0.0/8)', 'The MX for recipient domain is in "this" address space (0.0.0.0/8), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Address uses MX in "this" address space \(0.0.0.0/8\); from=<(__SENDER__)> to=<__RECIPIENT__> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_mx_access',
        4
);

-- <lisa@telephonebooth.com>: Sender address rejected: Address uses MX in "this" address space (0.0.0.0/8); from=<lisa@telephonebooth.com> to=<francis.neelamkavil@cs.tcd.ie> proto=SMTP helo=<localhost>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Sender MX in "this" address space (0.0.0.0/8)', 'The MX for sender domain is in "this" address space (0.0.0.0/8), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in "this" address space \(0.0.0.0/8\); from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_mx_access',
        4
);

-- <af53eec9@verpiss-dich.de>: Recipient address rejected: Address uses MX in loopback address space (127.0.0.0/8); from=<cbsrlkhaigye@allsaintsfan.com> to=<af53eec9@verpiss-dich.de> proto=SMTP helo=<127.0.0.1>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Recipient MX in loopback address space (127.0.0.0/8)', 'The MX for recipient domain is in loopback address space (127.0.0.0/8), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Address uses MX in loopback address space \(127.0.0.0/8\); from=<(__SENDER__)> to=<__SENDER__> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_recipient_mx_access',
        4
);

-- <rmurphywgra@itm-inst.com>: Sender address rejected: Address uses MX in test address space (192.0.2.0/24); from=<rmurphywgra@itm-inst.com> to=<noctor@cs.tcd.ie> proto=SMTP helo=<itm-inst.com>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Sender MX in test address space (192.0.2.0/24)', 'The MX for sender domain is in test address space (192.0.2.0/24), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in test address space \(192.0.2.0/24\); from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_mx_access',
        4
);

-- <ForestSimmspq@rpis.pl>: Sender address rejected: Address uses MX in reserved address space (240.0.0.0/4); from=<ForestSimmspq@rpis.pl> to=<dave.lewis@cs.tcd.ie> proto=ESMTP helo=<xmx1.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Sender MX in reserved address space (240.0.0.0/4)', 'The MX for sender domain is in reserved address space (240.0.0.0/4), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Address uses MX in reserved address space \(240.0.0.0/4\); from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_mx_access',
        4
);

-- <selby.dalzell@uldgalleriet.dk>: Sender address rejected: Address uses MX in multicast address space (224.0.0.0/4); from=<selby.dalzell@uldgalleriet.dk> to=<stephen.mcsweeney@cs.tcd.ie> proto=ESMTP helo=<host81-154-224-236.range81-154.btcentralplus.com>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Sender MX in multicast address space (224.0.0.0/4)', 'The MX for sender domain is in multicast address space (224.0.0.0/4), so cannot be contacted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <__SENDER__>: Sender address rejected: Address uses MX in multicast address space \(224.0.0.0/4\); from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_mx_access',
        4
);

-- Server configuration problem; from=<Trav-Buys@easytriprep.com> to=<mary.sharp@cs.tcd.ie> proto=ESMTP helo=<mail.easytriprep.com>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Local server configuration program', 'There is a problem with the configuration of the local mail server, so mail is not being accepted',
        'postfix/smtpd',
        '^__RESTRICTION_START__ Server configuration (?:problem|error); from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'Server misconfiguration',
        1
);

-- <cs.tcd.ie>: Helo command rejected: You are not in cs.tcd.ie; from=<van9219@yahoo.co.jp> to=<david.ocallaghan@cs.tcd.ie> proto=SMTP helo=<cs.tcd.ie>
-- NOQUEUE: reject_warning: RCPT from unknown[fe80::a800:86ff:fee2:21a1%bge0]: 550 5.7.1 <co001023.condor.cs.tcd.ie>: Helo command rejected: You are not in cs.tcd.ie; from=<root@co001023.condor.cs.tcd.ie> to=<grid-ireland-alert@cs.tcd.ie> proto=ESMTP helo=<co001023.condor.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Faked CS HELO', 'The client used a CS address in HELO but is not within our network',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <__HELO__>: Helo command rejected: You are not in cs.tcd.ie; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_helo_access',
        6
);

-- NOQUEUE: reject_warning: RCPT from scan14.cs.tcd.ie[134.226.54.40]: 550 5.7.1 <134.226.54.40>: Helo command rejected: You are not in my network.  Go away.; from=<Conor> to=<cgaffne@cs.tcd.ie> proto=SMTP helo=<134.226.54.40>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Faked HELO', 'The client used a local address in HELO but is not within our network',
        'postfix/smtpd',
	    '^__RESTRICTION_START__ <__HELO__>: Helo command rejected: You are not in my network. +Go away.; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_helo_access',
        6
);

-- NOQUEUE: reject: RCPT from pc792.cs.tcd.ie[134.226.40.104]: 550 5.7.1 <Igorb@infogateonline.com>: Recipient address rejected: Mail to this address bounces; from=<www-data@yossarian.cs.tcd.ie> to=<Igorb@infogateonline.com> proto=ESMTP helo=<pc792.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Misc recipient blocks', 'Misc recipient blocks used when necessary',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: (__DATA__Mail to this address bounces); from=<(__SENDER__)> to=<__RECIPIENT__> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_recipient_access',
        4
);

INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Misc emergency blocks', 'Misc blocks used when necessary',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <__CLIENT_HOSTNAME__\[__CLIENT_IP__\]>: Client host rejected: (__DATA__Do something sensible with mail to root.|Please contact John Tobin at 1534|Stop sending phishing scams); from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_client_access',
        4
);

-- <a-tikx23d9jlacr>: Helo command rejected: need fully-qualified hostname; from=<aprenda06@walla.com> to=<michael.brady@cs.tcd.ie> proto=SMTP helo=<a-tikx23d9jlacr>
-- <203.162.3.152>: Helo command rejected: need fully-qualified hostname; from=<grid-ireland-ca@cs.tcd.ie> to=<grid-ireland-ca@cs.tcd.ie> proto=ESMTP helo=<203.162.3.152>
-- <qbic>: Helo command rejected: need fully-qualified hostname; from=<> to=<faircloc@cs.tcd.ie> proto=ESMTP helo=<qbic>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Non-FQDN HELO', 'The hostname given in the HELO command is not fully qualified, i.e. it lacks a domain',
        'postfix/smtpd',
        '^__RESTRICTION_START__ (?><(__HELO__)>:) Helo command rejected: need fully-qualified hostname; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\k<helo>>$',
        'DELIVERY_REJECTED',
        'reject_non_fqdn_hostname, reject_non_fqdn_helo_hostname',
        6
);

-- <among@ecosse.net>: Relay access denied; from=<uvqjnkhcwanbvk@walla.com> to=<among@ecosse.net> proto=SMTP helo=<88-134-149-72-dynip.superkabel.de>
-- NOQUEUE: reject: RCPT from unknown[222.47.60.114]: 554 5.7.1 < lfelga@visir.is>: Relay access denied; from=<MarKetingsupport@hexun.com> to=<?lfelga@visir.is> proto=SMTP helo=<222.47.60.114>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Relaying denied', 'Client tried to use us as an open relay',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Relay access denied; from=<(__SENDER__)> to=<__RECIPIENT__> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'permit_mynetworks, reject_unauth_destination',
        5
);

-- Client host rejected: cannot find your hostname, [199.84.53.138]; from=<security@e-gold.com.> to=<melanie.bouroche@cs.tcd.ie> proto=ESMTP helo=<DynamicCorp.net>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Rejected client without PTR', 'Client IP address does not have associated PTR record',
        'postfix/smtpd',
        '^__RESTRICTION_START__ Client host rejected: cannot find your hostname, \[__CLIENT_IP__\]; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_unknown_client',
        4
);

-- We match anything here because the address is invalid.
-- <[]>: Helo command rejected: invalid ip address; from=<mrmmpwv@parfive.com> to=<hitesh.tewari@cs.tcd.ie> proto=ESMTP helo=<[]>
-- <24383590>: Helo command rejected: Invalid name; from=<CBKWPMIUF@hotmail.com> to=<byrne@cs.tcd.ie> proto=SMTP helo=<24383590>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Invalid HELO hostname/ip', 'The hostname/ip used in the HELO command is invalid',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__HELO__)>: Helo command rejected: (__DATA__invalid ip address|Invalid name); from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\k<helo>>$',
        'DELIVERY_REJECTED',
        'reject_invalid_helo_hostname',
        6
);

-- <daemon@cs.tcd.ie>: Recipient address rejected: recipient address unknown; from=<> to=<daemon@cs.tcd.ie> proto=ESMTP helo=<lg12x21.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Unknown recipient (system user)', 'The recipient address is unknown on our system (system users should not receive mail)',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: recipient address unknown; from=<(__SENDER__)> to=<__RECIPIENT__> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_recipient_access',
        4
);

-- <daemon@cs.tcd.ie>: Sender address rejected: sender address unknown; from=<daemon@cs.tcd.ie> to=<root@cs.tcd.ie> proto=ESMTP helo=<apex.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Unknown sender (system user)', 'The sender address is unknown on our system (system users should not send mail)',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: sender address unknown; from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_access',
        4
);

-- <neville.harris@cs.tcd.ie>: Recipient address rejected: User no longer receiving mail at this address; from=<have@jewelprecision.com> to=<neville.harris@cs.tcd.ie> proto=SMTP helo=<jewelprecision.com>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Unknown recipient (user not receiving mail)', 'The recipient address is unknown on our system (user not receiving mail here any more)',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: User no longer receiving mail at this address; from=<(__SENDER__)> to=<__RECIPIENT__> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_recipient_access',
        4
);

-- <godiva.cs.tcd.ie[134.226.35.142]>: Client host rejected: Alias root to something useful.; from=<root@godiva.cs.tcd.ie> to=<root@godiva.cs.tcd.ie> proto=SMTP helo=<godiva.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Unwanted mail to root', 'People keep sending us mail for root at their machine',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <__CLIENT_HOSTNAME__(?>\[__CLIENT_IP__\]>:) Client host rejected: Alias root to something useful.; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_client_access',
        4
);

-- <root@pc910.cs.tcd.ie>: Recipient address rejected: alias root to some other user, damnit.; from=<root@pc910.cs.tcd.ie> to=<root@pc910.cs.tcd.ie> proto=ESMTP helo=<vangogh.cs.tcd.ie>
-- <root@pc910.cs.tcd.ie>: Recipient address rejected: alias root to some other user, damnit.; from=<> to=<root@pc910.cs.tcd.ie> proto=ESMTP helo=<vangogh.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Unwanted mail to root 2', 'People keep sending us mail for root at their machine (2)',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <__RECIPIENT__>: Recipient address rejected: (?:alias root to some other user, damnit.|Please do something with root.s mail.); from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_recipient_access',
        4
);

-- <localhost.localhost>: Helo command rejected: You are not me; from=<qute1212000@yahoo.it> to=<mads.haahr@cs.tcd.ie> proto=SMTP helo=<localhost.localhost>
-- <134.226.32.56>: Helo command rejected: You are not me.; from=<lsfeisg.xrseusc@yahoo.com.tw> to=<stephen.farrell@cs.tcd.ie> proto=SMTP helo=<134.226.32.56>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Fake localhost HELO', 'The client claimed to be localhost in the HELO command',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__HELO__)>: Helo command rejected: You are not me\.?; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\k<helo>>$',
        'DELIVERY_REJECTED',
        'check_helo_access',
        6
);

-- <stephen.farrell>: Recipient address rejected: need fully-qualified address; from=<ykkxj.ukf@sfilc.com> to=<stephen.farrell> proto=SMTP helo=<www.BMS96.com>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Non-FQDN recipient', 'Recipient addresses must be in FQDN form, so replies can be sent',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: need fully-qualified address; from=<(__SENDER__)> to=<__RECIPIENT__> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_non_fqdn_sender',
        6
);

-- <apache>: Sender address rejected: need fully-qualified address; from=<apache> to=<Arthur.Hughes@cs.tcd.ie> proto=ESMTP helo=<najm.tendaweb.com>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Non-FQDN sender', 'Sender addresses must be in FQDN form, so replies can be sent',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: need fully-qualified address; from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_non_fqdn_sender',
        6
);

-- <DATA>: Data command rejected: Multi-recipient bounce; from=<> proto=SMTP helo=<mail71.messagelabs.com>
-- <DATA>: Data command rejected: Multi-recipient bounce; from=<> proto=ESMTP helo=<euphrates.qatar.net.qa>
INSERT INTO rules(name, description, program, regex, result_data, action, restriction_name, cluster_group_id)
    VALUES('Multi-recipient bounce rejected', 'Any mail from <> should be a bounce, therefore if there is more than one recipient it can be rejected (supposedly it had more than one sender)',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <DATA>: Data command rejected: Multi-recipient bounce; from=<(__SENDER__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = unknown',
        'DELIVERY_REJECTED',
        'reject_multi_recipient_bounce',
        7
);

-- <DATA>: Data command rejected: Improper use of SMTP command pipelining; from=<bounce-523207-288@lists.tmforum.org> to=<vwade@cs.tcd.ie> proto=SMTP helo=<lists.tmforum.org>
-- <DATA>: Data command rejected: Improper use of SMTP command pipelining; from=<daffy982@livedoor.com> to=<tfernand@cs.tcd.ie> proto=ESMTP helo=<adler.ims.uni-stuttgart.de>
-- <DATA>: Data command rejected: Improper use of SMTP command pipelining; from=<vwade@cs.tcd.ie> proto=ESMTP helo=<webmail.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Bad pipelining', 'The client tried to use pipelining before Postfix allowed it',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <DATA>: Data command rejected: Improper use of SMTP command pipelining; from=<(__SENDER__)> (?:to=<(__RECIPIENT__)> )?proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_unauth_pipelining',
        7
);

-- NOTE: this rejection doesn't start with __RESTRICTION_START__.
-- NOQUEUE: reject: MAIL from cagraidsvr06.cs.tcd.ie[134.226.53.22]: 552 Message size exceeds fixed limit; proto=ESMTP helo=<cagraidsvr06.cs.tcd.ie>
-- NOQUEUE: reject: MAIL from cagraidsvr06.cs.tcd.ie[134.226.53.22]: 552 5.3.4 Message size exceeds fixed limit; proto=ESMTP helo=<cagraidsvr06.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_data, action, restriction_name, cluster_group_id)
    VALUES('Rejected mail too large', 'The client tried to send a mail but it is too big to be accepted.',
        'postfix/smtpd',
        '^(__QUEUEID__): reject: MAIL from (__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\]: (__SMTP_CODE__) (?:__ENHANCED_STATUS_CODE__ )?Message size exceeds fixed limit; proto=ESMTP helo=<(__HELO__)>$',
        'sender = unknown, recipient = unknown',
        'DELIVERY_REJECTED',
        'message_size_limit',
        1
);

-- <info@tiecs.ie>: Sender address rejected: Stop flooding our users with mail.; from=<info@tiecs.ie> to=<tobinjt@cs.tcd.ie> proto=SMTP helo=<wilde.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Stop flooding users with mail', 'A client was flooding users with unwanted mail',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Stop flooding our users with mail.; from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_access',
        6
);

-- NOTE: this rejection doesn't start with __RESTRICTION_START__.
-- NOQUEUE: reject: CONNECT from localhost[::1]: 554 5.7.1 <localhost[::1]>: Client host rejected: Access denied; proto=SMTP
INSERT INTO rules(name, description, program, regex, result_data, action, restriction_name, cluster_group_id)
    VALUES('Client host rejected for some reason', 'The client was rejected but no reason was specified',
        'postfix/smtpd',
        '^(__QUEUEID__): reject: CONNECT from (__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\]: (__SMTP_CODE__) (?:__ENHANCED_STATUS_CODE__ )?<\k<client_hostname>\[\k<client_ip>\]>: Client host rejected: Access denied; proto=E?SMTP$',
        'sender = unknown, recipient = unknown',
        'DELIVERY_REJECTED',
        'check_client_access',
        1
);

-- <angbuchsbaum@yahoo.be>: Recipient address rejected: Malformed DNS server reply; from=<Alena.Moison@cs.tcd.ie> to=<angbuchsbaum@yahoo.be> proto=ESMTP helo=<SECPC2>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Malformed DNS reply (recipient)', 'The DNS reply was malformed when checking the recipient domain',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__RECIPIENT__)>: Recipient address rejected: Malformed DNS server reply; from=<(__SENDER__)> to=<__RECIPIENT__> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_unknown_sender_domain',
        4
);

-- <Gunter_LetitiaV@bionorthernireland.com>: Sender address rejected: Malformed DNS server reply; from=<Gunter_LetitiaV@bionorthernireland.com> to=<donnelly@cs.tcd.ie> proto=SMTP helo=<2D87008>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Malformed DNS reply (sender)', 'The DNS reply was malformed when checking the sender domain',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: Malformed DNS server reply; from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_unknown_sender_domain',
        4
);

-- <relay.ubu.es[193.146.160.3]>: Client host rejected: Please stop sending us unwanted call for papers.; from=<escorchado@ubu.es> to=<kahmad@cs.tcd.ie> proto=ESMTP helo=<virtual310.curris.ubu.es>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Unwanted calls for papers', 'The client is spamming us with calls for papers',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\]>: Client host rejected: Please stop sending us unwanted call for papers.; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_client_access',
        1
);

-- <postmaster@cs.tcd.ie>: Sender address rejected: This address is not in use.; from=<postmaster@cs.tcd.ie> to=<caramisgo@yahoo.co.kr> proto=SMTP helo=<dvnpahxwg.com>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Rejecting unused sender address', 'Rejecting an address we know is not used for sending mail',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: This address is not in use.; from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_access',
        4
);

-- <bassire@venus.made2own.com>: Sender address rejected: We don't want your spam.; from=<bassire@venus.made2own.com> to=<liz.gray@cs.tcd.ie> proto=ESMTP helo=<venus.made2own.com>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Rejecting spammer sender address', 'Rejecting an address we know is used for sending spam',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(__SENDER__)>: Sender address rejected: We don.t want your spam.; from=<__SENDER__> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_access',
        4
);

-- Client host rejected: Fix your mail system please, you've filling up our mail queue.; from=<> to=<root@pc910.cs.tcd.ie> proto=ESMTP helo=<pc910.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Rejecting client flooding us with mail', 'Rejecting a client which is flooding us with mail.',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <(?:__CLIENT_HOSTNAME__)\[(?:__CLIENT_IP__)\]>: Client host rejected: Fix your mail system please, you.ve filling up our mail queue.; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_access',
        1
);


-- Client host rejected: Don't want this mail; from=<> to=<cricket@cs.tcd.ie> proto=ESMTP helo=<lg12x37.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Rejecting we do not want', 'Rejecting mail which is unwanted for one reason or another',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <__CLIENT_HOSTNAME__\[__CLIENT_IP__\]>: Client host rejected: Don.t want this mail; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'check_sender_access',
        4
);

-- <unknown[87.192.55.104]>: Client host rejected: TOO MANY CONNECTIONS; proto=SMTP
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Rejecting client which connects too many times', 'Rejecting client which connects too many times',
        'postfix/smtpd',
        '^(__QUEUEID__): reject: CONNECT from (__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\]: 554 5.7.1 <__CLIENT_HOSTNAME__\[__CLIENT_IP__\]>: Client host rejected: TOO MANY CONNECTIONS; proto=E?SMTP$',
        'DELIVERY_REJECTED',
        'check_client_access',
        1
);

-- Recipient address rejected: undeliverable address: mail for gforgeisg.cs.tcd.ie loops back to myself; from=<noreply@gforgeisg.cs.tcd.ie> to=<noreply@gforgeisg.cs.tcd.ie> proto=ESMTP helo=<pc910.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Mail loop detected (2)', 'This host is the MX for the addresses domain, but is not final destination for that domain (2)',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <__RECIPIENT__>: Recipient address rejected: undeliverable address: mail for (__DATA__(?:)__SERVER_HOSTNAME__) loops back to myself; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'Mail loop detection',
        10
);

-- <root@lehane.cs.tcd.ie>: Recipient address rejected: unverified address: connect to lehane.cs.tcd.ie[134.226.35.142]:25: Connection refused; from=<root@lehane.cs.tcd.ie> to=<root@lehane.cs.tcd.ie> proto=SMTP helo=<lehane.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Mail addressed to a local server that would not accept it', 'This mail was sent to a local server that rejected the address',
        'postfix/smtpd',
        '^__RESTRICTION_START__ <__RECIPIENT__>: Recipient address rejected: unverified address: connect to (__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\]:25: Connection (refused|timed out); from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_unverified_recipient',
        4
);

-- NOQUEUE: reject: RCPT from cagnode21.cs.tcd.ie[134.226.53.85]: 450 4.1.1 <root@cagnode21.cs.tcd.ie>: Recipient address rejected: unverified address: Address verification in progress; from=<root@cagnode21.cs.tcd.ie> to=<root@cagnode21.cs.tcd.ie> proto=ESMTP helo=<gridgate.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, action, restriction_name, cluster_group_id)
    VALUES('Address verification not finished', 'Address verification is in progress',
        'postfix/smtpd',
	    '^__RESTRICTION_START__ <__RECIPIENT__>: Recipient address rejected: unverified address: Address verification in progress; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'DELIVERY_REJECTED',
        'reject_unverified_recipient',
        4
);

-- }}}

-- SMTPD ACCEPT RULES {{{1
INSERT INTO rules(name, description, program, regex, result_data, action)
    VALUES('Mail accepted', 'Postfix accepted the mail; it is hardly obvious from the log message though',
        'postfix/smtpd',
        '^(__QUEUEID__): client=(__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\](?::unknown)?$',
        'smtp_code = 250',
        'CLONE'
);

-- }}}

-- SMTPD INFO RULES {{{

-- This has a high priority so that it supercedes the following rule, catching
-- uselessly logged HELOs.
-- NOQUEUE: warn: RCPT from unknown[200.42.252.162]: Logging HELO; from=<apple@cs.tcd.ie> to=<apple@cs.tcd.ie> proto=ESMTP helo=<200.42.252.162>
-- NOQUEUE: warn: RCPT from apollo.niss.gov.ua[194.93.188.130]: Logging HELO; from=<<>@apollo.niss.gov.ua> to=<tithed7@cs.tcd.ie> proto=ESMTP helo=<apollo.niss.gov.ua>
INSERT INTO rules(name, description, program, regex, action, priority)
    VALUES('Logging HELO (ignored)', 'HELO logged to provide additional data (ignored, an improved version is now in use)',
        'postfix/smtpd',
        '^__QUEUEID__: warn: __SHORT_CMD__ from (?:__CLIENT_HOSTNAME__)\[(?:__CLIENT_IP__)\]: Logging HELO; from=<(?:__SENDER__)> to=<(?:__RECIPIENT__)> proto=E?SMTP helo=<(?:__HELO__)>$',
        'UNINTERESTING',
        5
);

-- A3BB2363C: warn: DATA from localhost[127.0.0.1]: Logging HELO; from=<emailSenderApp+2VGO154B9WPQS-VA33Q45OY07B-2B82XZ9ZK7SCW@bounces.amazon.com> to=<eamonn.kenny@cs.tcd.ie> proto=ESMTP helo=<localhost>
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Logging HELO', 'HELO logged to provide additional data',
        'postfix/smtpd',
        '^(__QUEUEID__): warn: (?:__SHORT_CMD__|DATA) from (__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\]: Logging HELO; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'SAVE_DATA'
);

-- D54C63203: warn: DATA from lists-outbound.sourceforge.net[66.35.250.225]: Logging HELO; from=<gumstix-users-bounces@lists.sourceforge.net> proto=ESMTP helo=<lists-outbound.sourceforge.net>
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Logging HELO (no recipien address)', 'HELO logged to provide additional data (no recipient address)',
        'postfix/smtpd',
        '^(__QUEUEID__): warn: (?:__SHORT_CMD__|DATA) from (__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\]: Logging HELO; from=<(__SENDER__)> proto=E?SMTP helo=<(__HELO__)>$',
        'SAVE_DATA'
);

-- 5A40338B2: hold: DATA from bkanemac3.cs.tcd.ie[134.226.40.156]: <help@cs.tcd.ie>: Recipient address triggers HOLD action; from=<kanebt@cs.tcd.ie> to=<help@cs.tcd.ie> proto=ESMTP helo=<[134.226.40.156]>
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Recipient addresses triggers HOLD action', 'The recipient addresses causes the mail to be moved to the hold queue',
        'postfix/smtpd',
        '^(__QUEUEID__): hold: DATA from (__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\]: <(__RECIPIENT__)>: Recipient address triggers HOLD action; from=<(__SENDER__)> to=<(\k<recipient>)> proto=E?SMTP helo=<(__HELO__)>$',
        'SAVE_DATA'
);

-- }}}



-- QMGR RULES {{{1
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Mail delivery accomplished', 'qmgr is finished with the mail; it has been delivered',
        'postfix/qmgr',
        '^(__QUEUEID__): removed$',
        'COMMIT'
);

-- 6508A4317: from=<florenzaaluin@callisupply.com>, size=2656, nrcpt=1 (queue active)
INSERT INTO rules(name, description, program, regex, action)
    VALUES('qmgr processing mail', 'qmgr is going to deliver this mail',
        'postfix/qmgr',
        '^(__QUEUEID__): from=<(__SENDER__)>, size=(__SIZE__), nrcpt=(\d+) \(queue active\)$',
        'MAIL_QUEUED'
);

-- B1508348E: from=<tcd-mzones-management-bounces+79talbert=jinan.gov.cn@cs.tcd.ie>, status=expired, returned to sender
-- 9C169364A: from=<>, status=expired, returned to sender
INSERT INTO rules(name, description, program, regex, result_data, action)
    VALUES('mail has been queued for too long', 'mail has been sitting in the queue for too long, postifx is giving up on it',
        'postfix/qmgr',
        '^(__QUEUEID__): from=<(__SENDER__)>, (?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=expired, returned to sender$',
        'smtp_code = 554',
        'EXPIRY'
);

-- E8DE4438A: to=<root@godiva.cs.tcd.ie>, relay=none, delay=1, status=deferred (delivery temporarily suspended: connect to godiva.cs.tcd.ie[134.226.35.142]: Connection refused)
-- D24B44416: to=<G4254-list@tcd.ie>, orig_to=<allnightug-list@cs.tcd.ie>, relay=none, delay=64, status=deferred (delivery temporarily suspended: connect to imx2.tcd.ie[134.226.1.156]: Connection timed out)
INSERT INTO rules(name, description, program, regex, action)
    VALUES('delivery suspended because the connection was refused/timed out', 'qmgr deferred delivery because the smtp connection was refused/timed out',
        'postfix/qmgr',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \(delivery temporarily suspended: connect to (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\]: Connection (?:refused|timed out)\)$',
        'SAVE_DATA'
);

-- 0278038B0: to=<mary.davies@sihe.ac.uk>, relay=none, delay=0.09, delays=0.08/0.01/0/0, dsn=4.4.2, status=deferred (delivery temporarily suspended: lost connection with 127.0.0.1[127.0.0.1] while receiving the initial server greeting)
INSERT INTO rules(name, description, program, regex, action)
    VALUES('delivery suspended because the connection was lost', 'qmgr deferred delivery because the smtp connection was lost',
        'postfix/qmgr',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, __DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \(delivery temporarily suspended: lost connection with (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\] while receiving the initial server greeting\)$',
        'SAVE_DATA'
);

-- 27AB942D3: skipped, still being delivered
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Qmgr skipping a mail', 'I presume qmgr is rescanning the queue, sees this mail, but knows there is a process trying to deliver it?  How can it take so long?',
        'postfix/qmgr',
        '^__QUEUEID__: skipped, still being delivered$',
        'UNINTERESTING'
);

-- 0F5073725: to=<amulllly@cs.tcd.ie>, relay=none, delay=0, status=deferred (delivery temporarily suspended: lost connection with 127.0.0.1[127.0.0.1] while sending end of data -- message may be sent more than once)
-- 9326C365D: to=<welsh@cs.tcd.ie>, relay=none, delay=3, status=deferred (delivery temporarily suspended: lost connection with 127.0.0.1[127.0.0.1] while sending end of data -- message may be sent more than once)
INSERT INTO rules(name, description, program, regex, action, priority)
    VALUES('Conversation timed out with filter while sending <CR>.<CR>', 'The conversation timed out after Postfix had finished sending data to the filter; mail will be retried, but should not have been delivered by amavisd-new (we hope)',
        'postfix/qmgr',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, __DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \(delivery temporarily suspended: lost connection with (?<server_hostname>127.0.0.1)\[(?<server_ip>127.0.0.1)\] while sending end of data -- message may be sent more than once\)$',
        'SAVE_DATA',
        10
);

-- warning: qmgr_active_corrupt: save corrupt file queue active id CF4E648F5: No such file or directory
INSERT INTO rules(name, description, program, regex, action)
    VALUES('QMGR logged a warning', 'QMGR logged a warning; we should probably try to do something with this is future',
        'postfix/qmgr',
        '^warning: .+$',
        'UNINTERESTING'
);

-- 7E7CB38EB: to=<vee08-pc-owner@>, relay=none, delay=0.57, delays=0.45/0.12/0/0, dsn=5.1.3, status=bounced (bad address syntax)
INSERT INTO rules(name, description, program, regex, action)
    VALUES('QMGR bounced a mail due to bad address syntax', 'QMGR bounced a mail due to bad address syntax',
        'postfix/qmgr',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__,\s)?status=bounced \(bad address syntax\)$',
        'SAVE_DATA'
);

-- E3F5149BB: to=<lricker@mta.ca>, relay=none, delay=0.2, delays=0.03/0.17/0/0, dsn=4.4.3, status=deferred (delivery temporarily suspended: Host or domain name not found. Name service error for name=mta.ca type=MX: Host not found, try again)
INSERT INTO rules(name, description, program, regex, result_data, connection_data, action)
    VALUES('Recipient MX not found by qmgr (try again)', 'No MX server for the recipient was found by qmgr (try again, temporary failure)',
        'postfix/qmgr',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \((?:delivery temporarily suspended: )?(?:Host or domain name not found. )?Name service error for name=(__SERVER_HOSTNAME__) type=(?:A|AAAA|MX): Host not found, try again\)$',
        'smtp_code = 554',
        'client_hostname = localhost, client_ip = 127.0.0.1, server_ip = unknown',
        'SAVE_DATA'
);

-- fatal: AF2B13D8C: timeout receiving delivery status from transport: local
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Timeout recieving delivery status from transport', 'Timeout recieving delivery status from transport',
        'postfix/qmgr',
        '^fatal: (__QUEUEID__): timeout receiving delivery status from transport: \w+$',
        'SAVE_DATA'
);

-- 2C372447F: to=<melanie.bouroche@cs.tcd.ie>, relay=none, delay=4.5, delays=1.4/3.1/0/0, dsn=4.3.0, status=deferred (unknown mail transport error)
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Delivery deferred because of a problem with the delivery agent', 'Delivery deferred because of a problem with the delivery agent',
        'postfix/qmgr',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__,\s)?status=deferred \(unknown mail transport error\)$',
        'SAVE_DATA'
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
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('mail delivered to outside world', 'a mail was delivered to an outside address',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__SERVER_HOSTNAME__)\[(__SERVER_IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=sent \((__SMTP_CODE__)(__DATA__.*)\)$',
        'client_ip = 127.0.0.1, client_hostname = localhost',
        'MAIL_SENT'
);

-- 56EE54317: to=<creans@cs.tcd.ie>, relay=127.0.0.1[127.0.0.1], delay=3, status=sent (250 2.7.1 Ok, discarded, id=00218-04 - VIRUS: HTML.Phishing.Bank-753)
-- D93E84400: to=<diana.wilson@cs.tcd.ie>, relay=127.0.0.1[127.0.0.1], delay=1, status=sent (250 2.7.1 Ok, discarded, id=00218-03-2 - VIRUS: HTML.Phishing.Bank-753)
-- 1C8E84317: to=<dolan@cs.tcd.ie>, relay=127.0.0.1[127.0.0.1], delay=8, status=sent (250 2.6.0 Ok, id=00218-02, from MTA([127.0.0.1]:11025): 250 Ok: queued as 2677C43FD)
-- 730AC43FD: to=<grid-ireland-alert@cs.tcd.ie>, relay=127.0.0.1[127.0.0.1], delay=0, status=sent (250 2.6.0 Ok, id=15759-01-2, from MTA([127.0.0.1]:11025): 250 Ok: queued as A3B7C4403)
INSERT INTO rules(name, description, program, regex, result_data, action, priority)
    VALUES('mail being filtered', 'mail has been passed to a proxy for filtering',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=127.0.0.1\[127.0.0.1\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=sent \((__DATA__.*)\)$',
        'smtp_code = 250',
        'MAIL_SENT',
        5
);

-- connect to wsatkins.co.uk[193.117.23.129]: Connection refused (port 25)
-- connect to 127.0.0.1[127.0.0.1]: Connection refused (port 10024)
-- connect to mail.3dns.tns-global.com[194.202.213.46]: Connection reset by peer (port 25)
-- connect to mailgate2.brunel.ac.uk[193.62.141.2]:25: Connection refused
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('connect refused', 'postfix tried to connect to a remote smtp server, but the connection was refused',
        'postfix/smtp',
        '^connect to (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\](?::\d+)?: Connection (?:refused|reset by peer)(?: \(port \d+\))?$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'UNINTERESTING'
);

-- F06883D9B: to=<mail@esben.com>, relay=none, delay=187365, delays=187364/0.42/0.09/0, dsn=4.4.1, status=deferred (connect to mail.esben.com[80.164.191.18]: Connection reset by peer)
-- 4CC8443C5: to=<abutbrittany@route66bikers.com>, relay=none, delay=222439, status=deferred (connect to route66bikers.com[69.25.142.6]: Connection timed out)
-- D004043FD: to=<bjung@uvic.ca>, orig_to=<jungb@cs.tcd.ie>, relay=none, delay=31, status=deferred (connect to smtpx.uvic.ca[142.104.5.91]: Connection timed out)
-- 790D438A6: to=<CFSworks@XeonNET.net>, relay=mail.XeonNET.net[70.57.16.248]:25, delay=78733, delays=78432/0.43/300/0, dsn=4.4.2, status=deferred (conversation with mail.XeonNET.net[70.57.16.248] timed out while receiving the initial server greeting)
-- 7FC073FA6F: to=<Chris.Evans@brunel.ac.uk>, relay=none, delay=40, delays=0.02/0/40/0, dsn=4.4.1, status=deferred (connect to mailgate1.brunel.ac.uk[193.62.141.1]:25: Connection timed out)
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('mail delayed', 'the connection timed out while trying to deliver mail',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(?:none|__SERVER_HOSTNAME__\[__SERVER_IP__\](?::\d+)?), (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \((?:conversation with|connect to) (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\](?::\d+)?(?::)? (?:Connection timed out|timed out while receiving the initial server greeting|Connection reset by peer)\)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- 7A06F3489: to=<azo@www.instantweb.com>, relay=www.instantweb.com[206.185.24.12], delay=68210, status=deferred (host www.instantweb.com[206.185.24.12] said: 451 qq write error or disk full (#4.3.0) (in reply to end of DATA command))
-- B697043F0: to=<matthew@sammon.info>, orig_to=<matthew.sammon@cs.tcd.ie>, relay=mail.hosting365.ie[82.195.128.132], delay=1, status=deferred (host mail.hosting365.ie[82.195.128.132] said: 450 <matthew@sammon.info>: Recipient address rejected: Greylisted for 5 minutes (in reply to RCPT TO command))
-- DDF6A3489: to=<economie-recherche@region-bretagne.fr>, relay=rain-pdl.megalis.org[217.109.171.200], delay=1, status=deferred (host rain-pdl.megalis.org[217.109.171.200] said: 450 <economie-recherche@region-bretagne.fr>: Recipient address rejected: Greylisted for 180 seconds (see http://isg.ee.ethz.ch/tools/postgrey/help/region-bretagne.fr.html) (in reply to RCPT TO command))
-- EF2AE438D: to=<k.brown@cs.ucc.ie>, relay=mail6.ucc.ie[143.239.1.36], delay=11, status=deferred (host mail6.ucc.ie[143.239.1.36] said: 451 4.3.2 Please try again later (in reply to MAIL FROM command))
-- 0A6634382: to=<ala.biometry@rret.com>, relay=smtp.getontheweb.com[66.36.236.47], delay=57719, status=deferred (host smtp.getontheweb.com[66.36.236.47] said: 451 qqt failure (#4.3.0) (in reply to DATA command))
-- 2CD5C3D8F: to=<gordon.power@gmail.com>, relay=gmail-smtp-in.l.google.com[66.249.93.114]:25, conn_use=3, delay=0.58, delays=0.05/0/0.29/0.23, dsn=4.2.1, status=deferred (host gmail-smtp-in.l.google.com[66.249.93.114] said: 450-4.2.1 The Gmail user you are trying to contact is receiving 450-4.2.1 mail at a rate that prevents additional messages from 450-4.2.1 being delivered. Please resend your message at a later 450-4.2.1 time; if the user is able to receive mail at that time, 450 4.2.1 your message will be delivered. s1si6984646uge (in reply to RCPT TO command))
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('mail deferred because of a temporary remote failure', 'There is a temporary failure of some sort on the remote side, mail deferred',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__SERVER_HOSTNAME__)\[(__SERVER_IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \(host \k<server_hostname>\[\k<server_ip>\] said: (__SMTP_CODE__)(__DATA__.*) \(in reply to __COMMAND__ command\)\)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- 7ABDF43FD: to=<olderro@myccccd.net>, relay=none, delay=0, status=bounced (Host or domain name not found. Name service error for name=mailcruiser.campuscruiser.com type=A: Host not found)
-- 90F0E3E19: to=<matthew@sammon.info>, orig_to=<matthew.sammon@cs.tcd.ie>, relay=none, delay=0, status=bounced (Host or domain name not found. Name service error for name=mail.hosting365.ie type=A: Host not found)
-- C350F38DB: to=<sfee@tcd.cs.tcd.ie>, orig_to=<sfee@tcd>, relay=none, delay=0.39, delays=0.38/0/0/0, dsn=5.4.4, status=bounced (Host or domain name not found. Name service error for name=tcd.cs.tcd.ie type=AAAA: Host not found)
INSERT INTO rules(name, description, program, regex, result_data, connection_data, action)
    VALUES('Recipient MX not found', 'No MX server for the recipient was found',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=bounced \(Host or domain name not found. Name service error for name=(__SERVER_HOSTNAME__) type=(?:MX|A|AAAA): Host not found\)$',
        'smtp_code = 554',
        'client_hostname = localhost, client_ip = 127.0.0.1, server_ip = unknown',
        'MAIL_BOUNCED'
);

-- B028035EB: to=<Iain@fibernetix.com>, relay=none, delay=282964, status=deferred (Host or domain name not found. Name service error for name=fibernetix.com type=MX: Host not found, try again)
INSERT INTO rules(name, description, program, regex, result_data, connection_data, action)
    VALUES('Recipient MX not found (try again)', 'No MX server for the recipient was found (try again, temporary failure)',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \((?:delivery temporarily suspended: )?(?:Host or domain name not found. )?Name service error for name=(__SERVER_HOSTNAME__) type=(?:A|AAAA|MX): Host not found, try again\)$',
        'smtp_code = 554',
        'client_hostname = localhost, client_ip = 127.0.0.1, server_ip = unknown',
        'SAVE_DATA'
);

-- connect to lackey.cs.qub.ac.uk[143.117.5.165]: Connection timed out (port 25)
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('connect timed out', 'time out while postfix was connecting to remote server',
        'postfix/smtp',
        '^connect to __SERVER_HOSTNAME__\[__SERVER_IP__\](?::\d+)?: Connection timed out(?: \(port 25\))?$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'UNINTERESTING'
);

-- D7B274401: to=<jaumaffup@cchlis.com>, relay=cchlis.com.s5a1.psmtp.com[64.18.4.10], delay=2, status=bounced (host cchlis.com.s5a1.psmtp.com[64.18.4.10] said: 550 5.1.1 User unknown (in reply to RCPT TO command))
-- A71B043FD: to=<dpdlbalgkcm@malaysia.net>, relay=malaysia-net.mr.outblaze.com[205.158.62.177], delay=31, status=bounced (host malaysia-net.mr.outblaze.com[205.158.62.177] said: 550 <>: No thank you rejected: Account Unavailable: Possible Forgery (in reply to RCPT TO command))
-- 224E243C3: to=<lamohtm@mail.ru>, orig_to=<sergey.tsvetkov@cs.tcd.ie>, relay=mxs.mail.ru[194.67.23.20], delay=5, status=bounced (host mxs.mail.ru[194.67.23.20] said: 550 spam message discarded. If you think that the system is mistaken, please report details to abuse@corp.mail.ru (in reply to end of DATA command))
-- 
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('mail to outside world rejected', 'mail to the outside world was rejected',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__SERVER_HOSTNAME__)\[(__SERVER_IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?>(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=bounced) \(host \k<server_hostname>\[\k<server_ip>\] said: (__SMTP_CODE__)(__DATA__.*) \(in reply to __COMMAND__ command\)\)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'MAIL_BOUNCED'
);

-- connect to mx1.mail.yahoo.com[4.79.181.14]: server refused to talk to me: 421 Message from (134.226.32.56) temporarily deferred - 4.16.50. Please refer to http://help.yahoo.com/help/us/mail/defer/defer-06.html   (port 25)
-- connect to mx1.mail.ukl.yahoo.com[195.50.106.7]: server refused to talk to me: 451 Message temporarily deferred - 4.16.50   (port 25)
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('Server refused to talk', 'The remote server refused to talk for some reason',
        'postfix/smtp',
        '^connect to __SERVER_HOSTNAME__\[__SERVER_IP__\]: server refused to talk to me: __SMTP_CODE__(?:.*) \(port 25\)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'UNINTERESTING'
);

-- 31AE04400: to=<domurtag@yahoo.co.uk>, orig_to=<domurtag@cs.tcd.ie>, relay=none, delay=0, status=deferred (connect to mx2.mail.ukl.yahoo.com[217.12.11.64]: server refused to talk to me: 451 Message temporarily deferred - 4.16.50  )
-- A932037C8: to=<ayako70576@freewww.info>, relay=none, delay=30068, status=deferred (connect to vanitysmtp.changeip.com[143.215.15.51]: server refused to talk to me: 421 cannot send to name server  )
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('Server refused to talk (later stage?)', 'The remote server refused to talk for some reason - at a later stage?  We have a queueid anyway',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \(connect to (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\]: server refused to talk to me: (__SMTP_CODE__)(__DATA__.*)\)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- warning: numeric domain name in resource data of MX record for phpcompiler.org: 80.68.89.7
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('Warning from smtp', 'Warning of some sort from smtp - rare',
        'postfix/smtp',
        '^warning: .*$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'UNINTERESTING'
);

-- 18FCF43C3: host iona.com.s8a1.psmtp.com[64.18.7.10] said: 451 Can't connect to iona.ie - psmtp (in reply to RCPT TO command)
-- 3B91D4390: host mail6.ucc.ie[143.239.1.36] said: 451 4.3.2 Please try again later (in reply to MAIL FROM command)
-- 80C05439E: host ASPMX.L.GOOGLE.COM[66.249.93.27] said: 450-4.2.1 The Gmail user you are trying to contact is receiving 450-4.2.1 mail at a rate that prevents additional messages from 450-4.2.1 being delivered. Please resend your message at a later 450-4.2.1 time; if the user is able to receive mail at that time, 450 4.2.1 your message will be delivered. q40si1486066ugc (in reply to RCPT TO command)
INSERT INTO rules(name, description, program, regex, connection_data, action, priority)
    VALUES('Generic smtp failure', 'A catchall for failures we do not have more specific tests for',
        'postfix/smtp',
        '^(__QUEUEID__): host (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\] said: (__SMTP_CODE__)(__DATA__.*) \(in reply to __COMMAND__ command\)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA',
        -1
);

-- connect to smap-net-bk.mr.outblaze.com[205.158.62.181]: read timeout (port 25)
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('read timeout', 'reading data from remote server timed out',
        'postfix/smtp',
        '^connect to __SERVER_HOSTNAME__\[__SERVER_IP__\]: read timeout \(port 25\)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'UNINTERESTING'
);

-- C770E4317: to=<nywzssbpk@smapxsmap.net>, relay=none, delay=944, status=deferred (connect to smap-net-bk.mr.outblaze.com[205.158.62.177]: read timeout)
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('read timeout (with queueid)', 'read timeout during connect - with queueid',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \(connect to (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\]: read timeout\)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- 681A74425: lost connection with mx1.mail.yahoo.com[4.79.181.15] while sending RCPT TO
-- 719B44312: lost connection with mail.waypt.com[63.172.167.6] while sending DATA command
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('smtp client lost connection', 'smtp client lost connection for who knows what reason',
        'postfix/smtp',
        '^(__QUEUEID__): lost connection with (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\] while sending __COMMAND__(?: command)?$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- no queueid to save with
-- connect to mail.boilingpoint.com[66.240.186.41]: server dropped connection without sending the initial SMTP greeting (port 25)
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('remote server rudely hung up', 'The remote server closed the connection without saying anything at all',
        'postfix/smtp',
        '^connect to __SERVER_HOSTNAME__\[__SERVER_IP__\]: server dropped connection without sending the initial SMTP greeting \(port \d+\)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'UNINTERESTING'
);

-- 198D4438F: to=<fj.azuaje@ieee.org>, orig_to=<francisco.azuaje@cs.tcd.ie>, relay=none, delay=0, status=deferred (connect to hormel.ieee.org[140.98.193.224]: server dropped connection without sending the initial SMTP greeting)
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('remote server rudely hung up (with queueid)', 'The remote server closed the connection without saying anything at all (but we have a queueid this time)',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \(connect to (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\]: server dropped connection without sending the initial SMTP greeting\)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- 99C2243F0: to=<mounderek@bigfot.com>, relay=none, delay=385069, status=deferred (connect to mail.ehostinginc.com[66.172.49.6]: Connection refused)
-- 2F5C643E9: to=<fj.azuaje@ieee.org>, orig_to=<francisco.azuaje@cs.tcd.ie>, relay=none, delay=0, status=deferred (connect to hormel.ieee.org[140.98.193.224]: Connection refused)
-- 52214F36FE: to=<www-data@planxty.dsg.cs.tcd.ie>, relay=none, delay=55166, delays=55166/0.06/0.01/0, dsn=4.4.1, status=deferred (connect to planxty.dsg.cs.tcd.ie[134.226.36.87]:25: Connection refused)
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('connection to remote host failed', 'smtp client could not connect to remote server',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \(connect to (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\](?::\d+)?: Connection refused\)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- 2A2DB4496: conversation with mail.zust.it[213.213.93.228] timed out while sending RCPT TO
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('Conversation timed out (2)', 'There was an awkward pause in the conversation and eventually it died',
        'postfix/smtp',
        '^(__QUEUEID__): conversation with (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\] timed out while sending __COMMAND__$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- 2A2DB4496: enabling PIX <CRLF>.<CRLF> workaround for mail.zust.it[213.213.93.228]
-- 5EAFB38C0: enabling PIX <CRLF>.<CRLF> workaround for mx.nsu.ru[212.192.164.5]:25
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('Working around broken PIX SMTP Fixup', 'The Cisco PIX has braindead SMTP Fixup, Postfix is working around it so that mail can be delivered',
        'postfix/smtp',
        '^(__QUEUEID__): enabling PIX <CRLF>.<CRLF> workaround for (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\](?::\d+)?$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- 16B6A3F50: to=<skenny@relay.cs.tcd.ie>, relay=none, delay=0, status=bounced (mail for relay.cs.tcd.ie loops back to myself)
INSERT INTO rules(name, description, program, regex, result_data, connection_data, action)
    VALUES('Mail loop detected', 'This host is the MX for the addresses domain, but is not final destination for that domain',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=bounced \(mail for __SERVER_HOSTNAME__ loops back to myself\)$',
        'smtp_code = 554',
        'client_hostname = localhost, client_ip = 127.0.0.1, server_hostname = localhost, server_ip = 127.0.0.1',
        'MAIL_BOUNCED'
);

-- 833CF438C: to=<essack@ion.co.za>, relay=spamfilter.ion.co.za[196.33.120.7], delay=603, status=deferred (conversation with spamfilter.ion.co.za[196.33.120.7] timed out while sending end of data -- message may be sent more than once)
-- 74AA93554: to=<kinshuk@athabascau.ca>, relay=smtp.athabascau.ca[131.232.10.21], delay=435, status=deferred (lost connection with smtp.athabascau.ca[131.232.10.21] while sending end of data -- message may be sent more than once)
-- 5B79E3850: to=<cathal.oconnor@cs.tcd.ie>, relay=127.0.0.1[127.0.0.1]:10024, conn_use=2, delay=9.5, delays=2.6/0/0/6.8, dsn=4.4.2, status=deferred (lost connection with 127.0.0.1[127.0.0.1] while sending end of data -- message may be sent more than once)
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('Conversation timed out after sending <CR>.<CR>', 'The conversation timed out after Postfix had finished sending the data; mail will be retried, but may have already been delivered on the remote end',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__SERVER_HOSTNAME__)\[(__SERVER_IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \((?:lost connection with|conversation with) \k<server_hostname>\[\k<server_ip>\] (?:timed out )?while sending end of data -- message may be sent more than once\)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- 122E141CD: to=<Taught.Admissions@tcd.ie>, relay=imx1.tcd.ie[134.226.17.160], delay=2, status=bounced (message size 10694768 exceeds size limit 10240000 of server imx1.tcd.ie[134.226.17.160])
INSERT INTO rules(name, description, program, regex, result_data, connection_data, action)
    VALUES('Mail too big for remote server', 'The remote server will not accept mails bigger than X, and this mail is bigger',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__SERVER_HOSTNAME__)\[(__SERVER_IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=bounced \((__DATA__message size \d+ exceeds size limit \d+ of server) \k<server_hostname>\[\k<server_ip>\]\)$',
        'smtp_code = 552',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'MAIL_BOUNCED'
);

-- 5499D44A3: conversation with drip.STJAMES.IE[194.106.141.85] timed out while performing the initial protocol handshake
-- 8103838B8: conversation with d.mx.mail.yahoo.com[216.39.53.2] timed out while receiving the initial server greeting
-- 04AE038CA: conversation with rose.man.poznan.pl[150.254.173.3] timed out while performing the EHLO handshake
-- 9769838B2: lost connection with spamtrap.netsource.ie[212.17.32.57] while performing the EHLO handshake
-- C8B0C437E: lost connection with mx3.mail.yahoo.com[67.28.113.10] while performing the initial protocol handshake
-- 5E67F38A1: lost connection with e33.co.us.ibm.com[32.97.110.151] while receiving the initial server greeting
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('Conversation timed out while handshaking', 'The initial handshake timed out',
        'postfix/smtp',
        '^(__QUEUEID__): (?:lost connection with|conversation with) (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\] (?:timed out )?while (?:performing the (?:initial protocol|EHLO|HELO) handshake|receiving the initial server greeting)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- 431844388: to=<matthew@sammon.info>, orig_to=<matthew.sammon@cs.tcd.ie>, relay=redir-mail-telehouse1.gandi.net[217.70.180.1], delay=390, status=deferred (host redir-mail-telehouse1.gandi.net[217.70.180.1] refused to talk to me: 450 Server configuration problem)
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('Server refused to talk (politely)', 'The remote server politely declied to talk to our server',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__SERVER_HOSTNAME__)\[(__SERVER_IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \(host \k<server_hostname>\[\k<server_ip>\] refused to talk to me: (__SMTP_CODE__)(__DATA__.*)\)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- 47F5C438A: to=<matthew@sammon.info>, orig_to=<matthew.sammon@cs.tcd.ie>, relay=redir-mail-telehouse2.gandi.net[217.70.178.1], delay=4106, status=deferred (conversation with redir-mail-telehouse2.gandi.net[217.70.178.1] timed out while performing the initial protocol handshake)
-- 820A94385: to=<Romanu6jMassey@photoeye.com>, relay=relay1.edgewebhosting.net[69.63.128.201], delay=1132, status=deferred (lost connection with relay1.edgewebhosting.net[69.63.128.201] while performing the initial protocol handshake)
-- E49EC438A: to=<DanR@Burton.com>, relay=mail.Burton.com[204.52.244.205], delay=3, status=deferred (lost connection with mail.Burton.com[204.52.244.205] while performing the initial protocol handshake)
-- 1E64D38CB: to=<wewontpay@btconnect.com>, relay=ibmr.btconnect.com[213.123.20.92]:25, delay=1.5, delays=0.08/0/1.4/0, dsn=4.4.2, status=deferred (lost connection with ibmr.btconnect.com[213.123.20.92] while receiving the initial server greeting)
-- 172BD36E3: to=<bgiven@mason.gmu.edu>, relay=mx-h.gmu.edu[129.174.0.99]:25, delay=0.67, delays=0.27/0.07/0.33/0, dsn=4.4.2, status=deferred (lost connection with mx-h.gmu.edu[129.174.0.99] while performing the HELO handshake)
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('Initial handshake timed out', 'The initial handshake did not complete within the timeout',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__SERVER_HOSTNAME__)\[(__SERVER_IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \((?:lost connection with|conversation with) \k<server_hostname>\[\k<server_ip>\] (?:(?:timed out )?while performing the (?:initial protocol|HELO|EHLO) handshake|while receiving the initial server greeting)\)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- 979054314: to=<lionel.dahyot@cegetel.net>, relay=av.mgp.neufgp.fr[84.96.92.100], delay=10, status=deferred (lost connection with av.mgp.neufgp.fr[84.96.92.100] while sending RCPT TO)
-- CD3EC41CC: to=<resume@athabascau.ca>, relay=smtp.athabascau.ca[131.232.10.21], delay=63, status=deferred (lost connection with smtp.athabascau.ca[131.232.10.21] while sending RCPT TO)
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('Lost connection with server', 'Lost connection with remote host during transaction',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__SERVER_HOSTNAME__)\[(__SERVER_IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \(lost connection with \k<server_hostname>\[\k<server_ip>\] while sending __COMMAND__\)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- 1324443A2: to=<zenobig@virgilio.it>, orig_to=<gabriele.zenobi@cs.tcd.ie>, relay=mxrm.virgilio.it[62.211.72.33], delay=8248, status=deferred (conversation with mxrm.virgilio.it[62.211.72.33] timed out while sending MAIL FROM)
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('Conversation timed out', 'The conversation timed out at some stage',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__SERVER_HOSTNAME__)\[(__SERVER_IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \(conversation with \k<server_hostname>\[\k<server_ip>\] timed out while sending __COMMAND__\)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- 8007B41CD: host redir-mail-telehouse2.gandi.net[217.70.178.1] refused to talk to me: 450 Server configuration problem
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('Server refused to talk (short)', 'Another server refusing to talk',
        'postfix/smtp',
        '^(__QUEUEID__): host (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\] refused to talk to me: (__SMTP_CODE__)(__DATA__.*)$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- 01061437E: lost connection with mx1.mail.yahoo.com[4.79.181.168] while sending end of data -- message may be sent more than once
-- BCF8638BC: conversation with mail.tesco.ie[195.7.43.146] timed out while sending end of data -- message may be sent more than once
INSERT INTO rules(name, description, program, regex, connection_data, action)
VALUES('Lost connection after data', 'Lost connection after end-of-data - message may be sent more than once',
        'postfix/smtp',
        '^(__QUEUEID__): (?:lost connection with|conversation with) (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\] (?:while sending end of data|timed out while sending end of data) -- message may be sent more than once$',
        'client_hostname = localhost, client_ip = 127.0.0.1',
        'SAVE_DATA'
);

-- 5F505437C: to=<smcblvacprbio@ekholden.com>, relay=none, delay=241762, status=bounced (Host or domain name not found. Name service error for name=ekholden.com type=A: Host found but no data record of requested type)
-- 94C1643AB: to=<alicechateau@royahoo.com>, relay=none, delay=0, status=bounced (Name service error for name=royahoo.com type=MX: Malformed name server reply)
INSERT INTO rules(name, description, program, regex, result_data, connection_data, action)
    VALUES('Malformed DNS reply, or no data', 'The DNS reply was malformed, or the requested record was not found',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=bounced \((__DATA__(?:Host or domain name not found. )?Name service error for name=(__SERVER_HOSTNAME__) type=(?:A|AAAA|MX): (?:Malformed name server reply|Host found but no data record of requested type))\)$',
        'smtp_code = 554',
        'client_hostname = localhost, client_ip = 127.0.0.1, server_ip = unknown',
        'MAIL_BOUNCED'
);

-- 4377E544AA: to=<bounce-2280-17395@go.globaltravelmarket.co.uk>, relay=none, delay=106454, delays=106364/0.02/90/0, dsn=4.4.3, status=deferred (Host or domain name not found. Name service error for name=mail.go.globaltravelmarket.co.uk type=AAAA: Host found but no data record of requested type)
INSERT INTO rules(name, description, program, regex, result_data, connection_data, action)
    VALUES('Malformed DNS reply, or no data (mail deferred)', 'The DNS reply was malformed, or the requested record was not found (mail delivery was deferred)',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \((__DATA__(?:Host or domain name not found. )?Name service error for name=(__SERVER_HOSTNAME__) type=(?:A|AAAA|MX): (?:Malformed name server reply|Host found but no data record of requested type))\)$',
        'smtp_code = 554',
        'client_hostname = localhost, client_ip = 127.0.0.1, server_ip = unknown',
        'MAIL_BOUNCED'
);

-- 380133F45: enabling PIX workarounds: disable_esmtp delay_dotcrlf for mx1.nuigalway.ie[140.203.201.100]:25
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Enabling workarounds to deal with Cisco PIX', 'Cisco PIX firewalls mangle SMTP, and Postfix needs to enable workarounds to successfully deliver mail',
        'postfix/smtp',
        '^(__QUEUEID__): enabling PIX workarounds: disable_esmtp delay_dotcrlf for (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\]:25$',
        'SAVE_DATA'
);

-- connect to alamut.cs.tcd.ie[2001:770:10:200:210:22ff:fefe:57c1]: Network is unreachable (port 25)
-- connect to ogma.cp.dias.ie[2001:770:60:18:215:c5ff:fee5:5c86]:25: Network is unreachable
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Network unreachable', 'The remote network is unreachable',
        'postfix/smtp',
        '^connect to __SERVER_HOSTNAME__\[__SERVER_IP__\]:(?:\d+:)? Network is unreachable(?: \(port \d+\))?$',
        'UNINTERESTING'
);

-- 6F118F3A4B: to=<pmcsween@revenue.ie>, orig_to=<macsweep@CS.TCD.IE>, relay=none, delay=31656, delays=31160/0.32/496/0, dsn=4.4.1, status=deferred (connect to prim-smtp.revenue.ie[137.191.227.38]:25: Network is unreachable)
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Network unreachable (more detailed)', 'The remote network is unreachable - more details given about the mail',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<(__RECIPIENT__)>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__,\s)?status=deferred \(connect to (__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\](?::\d+)?: Network is unreachable\)$',
        'SAVE_DATA'
);

-- 6F50FF34BC: to=<maa10887@relay.cs.tcd.ie>, relay=none, delay=0.03, delays=0.01/0.02/0/0, dsn=5.4.6, status=undeliverable (mail for relay.cs.tcd.ie loops back to myself)
INSERT INTO rules(name, description, program, regex, result_data, action, restriction_name, cluster_group_id)
    VALUES('Mail loop detected (3)', 'This host is the MX for the addresses domain, but is not final destination for that domain (3)',
        'postfix/smtp',
    	 '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<(__RECIPIENT__)>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__,\s)?status=undeliverable \(mail for __SERVER_HOSTNAME__ loops back to myself\)$',
        'smtp_code = 550',
        'MAIL_BOUNCED',
        'Mail loop detection',
        10
);

-- F2295F3894: to=<root@cagnode21.cs.tcd.ie>, relay=none, delay=30, delays=0.02/0/30/0, dsn=4.4.1, status=undeliverable (connect to cagnode21.cs.tcd.ie[134.226.53.85]:25: Connection timed out)
INSERT INTO rules(name, description, program, regex, result_data, action)
    VALUES('Mail bounced because the connection was refused/timed out', 'Mail bounced because the smtp connection was refused/timed out',
        'postfix/smtp',
	    '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__,\s)?status=undeliverable \(connect to (__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\]:25: Connection (?:refused|timed out)\)$',
        'smtp_code = 550',
        'MAIL_BOUNCED'
);

-- C1D4AF3B36: to=<promotion@the-bingo.co.uk>, relay=none, delay=0.04, delays=0.02/0/0.01/0, dsn=5.4.4, status=bounced (Name server loop for mx.the-bingo.co.uk)
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Mail bounced because of a DNS loop', 'Mail bounced because there was a loop when looking up MX/A/AAAA records for the recipient domain',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<(__RECIPIENT__)>,)? relay=none, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__,\s)?status=bounced \(Name server loop for (__SERVER_HOSTNAME__)\)$',
        'MAIL_BOUNCED'
);

-- 2C1DEF38F9: to=<hansjanek@t-online.de>, relay=mx01.t-online.de[194.25.134.72]:25, delay=0.3, delays=0.02/0/0.11/0.17, dsn=5.7.0, status=bounced (host mx01.t-online.de[194.25.134.72] said: 550-5.7.0 Message considered as spam or virus, rejected 550-5.7.0 Message rejected because it was considered as spam. If you feel this 550-5.7.0 to be an error, please forward the wrong classified e-mail to our 550-5.7.0 abuse department at FPR@RX.T-ONLINE.DE with all the header lines! 550-5.7.0 We will analyse the problem and solve it. We are sorry for any 550-5.7.0 inconvenience and thank you very much in advance for your support! 550-5.7.0   550-5.7.0 Die Annahme Ihrer Nachricht wurde abgelehnt, da sie als Spam 550-5.7.0 eingestuft wurde. Sollten Sie dies als Fehler ansehen, bitten wir 550-5.7.0 Sie darum, die E-Mail mit allen Kopfzeilen an FPR@RX.T-ONLINE.DE 550-5.7.0 weiterzuleiten. Das Problem wird dann untersucht und geloest. 550-5.7.0 Wir bedauer
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Mail rejected by T-ONLINE.DE', 'Mail rejected by T-ONLINE.DE with an enormous error message in English and German.',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<(__RECIPIENT__)>,)? relay=(__SERVER_HOSTNAME__)\[(__SERVER_IP__)\]:25, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__,\s)?status=bounced \(host (__SERVER_HOSTNAME__)\[(__SERVER_IP__)\] said: 550-5.7.0 Message considered as spam or virus, rejected 550-5.7.0 Message rejected because it was considered as spam. If you feel this 550-5.7.0 to be an error, please forward the wrong classified e-mail to our 550-5.7.0 abuse department at FPR@RX.T-ONLINE.DE with all the header lines! 550-5.7.0 We will analyse the problem and solve it. We are sorry for any 550-5.7.0 inconvenience and thank you very much in advance for your support!.*$',
        'MAIL_BOUNCED'
);

-- 32CBB3FA53: to=<obries10@hiteshpc.cs.tcd.ie>, relay=hiteshpc.cs.tcd.ie[2001:770:10:200:201:3ff:fe49:b00d]:25, delay=0.16, delays=0.01/0/0.09/0.05, dsn=2.1.5, status=deliverable (250 2.1.5 Ok)
INSERT INTO rules(name, description, program, regex, result_data, action)
    VALUES('Postfix logging how it will deliver some mail via SMTP', 'XXX FIGURE OUT WHY THIS HAPPENS 2',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<(__RECIPIENT__)>,)? relay=(__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__,\s)?status=deliverable \((__DATA__.*)\)$',
        'smtp_code = 250',
        'SAVE_DATA'
);

-- 143C0F3E27: to=<arash@dcs.qmul.ac.uk>, relay=mail.dcs.qmul.ac.uk[138.37.95.139]:25, delay=4.4, delays=0.05/0.02/3.3/1.1, dsn=4.0.0, status=deferred (host mail.dcs.qmul.ac.uk[138.37.95.139] said: 451-response to "RCPT TO:<fg07participants-bounces+arash=dcs.qmul.ac.uk@cs.tcd.ie>" from smtp.cs.tcd.ie [134.226.32.56] was: 450 4.2.0 <fg07participants-bounces+arash=dcs.qmul.ac.uk@cs.tcd.ie>: Recipient address rejected: Greylisted, see http://postgrey.schweikert.ch/help/cs.tcd.ie.html 451-Could not complete sender verify callout for 451-<fg07participants-bounces+arash=dcs.qmul.ac.uk@cs.tcd.ie>. 451-The mail server(s) for the domain may be temporarily unreachable, or 451-they may be permanently unreachable from this server. In the latter case, 451-you need to change the address or create an MX record for its domain 451-if it is supposed to be generally accessible from the Internet. 451 Talk to your mail administrator for details. (in reply to RCP
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Delivery attempt failed sender validation', 'Delivery attempt failed sender validation',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<(__RECIPIENT__)>,)? relay=(__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\](?::\d+)?, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__,\s)?status=deferred \(host (__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\] said: (__SMTP_CODE__)(__DATA__.*451.Could not complete sender verify callout for .*)$',
        'SAVE_DATA'
);

-- }}}


-- LOCAL RULES {{{1


-- 3FF7C4317: to=<mcadoor@cs.tcd.ie>, relay=local, delay=0, status=sent (forwarded as 56F5B43FD)
INSERT INTO rules(name, description, program, regex, result_data, connection_data, action)
    VALUES('Mail reinjected for forwarding', 'The mail was sent to a local address, but is aliased to an external address',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=sent \(forwarded as (__CHILD__)\)$',
        'smtp_code = 250',
        'client_hostname = localhost, client_ip = 127.0.0.1, server_hostname = localhost, server_ip = 127.0.0.1',
        'TRACK'
);

-- This will be followed by a 'postfix/qmgr: 8025E43F0: removed' line, so don't commit yet.
-- 7FD1443FD: to=<tobinjt@cs.tcd.ie>, orig_to=<root>, relay=local, delay=0, status=sent (delivered to command: /mail/procmail/bin/procmail -p -t /mail/procmail/etc/procmailrc)
-- 8025E43F0: to=<tobinjt@cs.tcd.ie>, relay=local, delay=0, status=sent (delivered to command: /mail/procmail/bin/procmail -p -t /mail/procmail/etc/procmailrc)
INSERT INTO rules(name, description, program, regex, result_data, connection_data, action)
    VALUES('Mail has been delivered locally', 'Mail has been delivered to the LDA (typically procmail)',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=sent \((__DATA__delivered to command: .*)\)$',
        'smtp_code = 250',
        'server_hostname = localhost, server_ip = 127.0.0.1, client_ip = 127.0.0.1, client_hostname = localhost',
        'MAIL_SENT'
);

-- table cdb:/mail/postfix/etc/aliases.out(0,34100) has changed -- restarting
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Postfix noticed a table changed', 'Postfix noticed that a lookup table has changed, so it is restarting',
        'postfix/local',
        '^table .* has changed -- restarting$',
        'UNINTERESTING'
);

-- D9FC14493: to=<osulldps@cs.tcd.ie>, orig_to=<declan.osullivan@cs.tcd.ie>, relay=local, delay=2, status=deferred (temporary failure. Command output: procmail: Quota exceeded while writing "/users/staff/osulldps/Maildir/tmp/1157969601.28098_0.relay.cs.tcd.ie" )
-- E7ED243DA: to=<muckleys@cs.tcd.ie>, relay=local, delay=223453, status=deferred (temporary failure. Command output: procmail: Couldn't chdir to "/users/pg/muckleys" procmail: Couldn't chdir to "/users/pg/muckleys" procmail: Couldn't chdir to "/users/pg/muckleys/Maildir" procmail: Unable to treat as directory "./new" procmail: Skipped "." )
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Local delivery failed temporarily', 'Something went wrong with local delivery, so it will be retried later',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \(temporary failure. Command output: (__DATA__.*)\)$',
        'SAVE_DATA'
);

-- BEAA25406B: to=<mcbridej@cs.tcd.ie>, relay=local, delay=0.09, delays=0.03/0/0/0.06, dsn=4.3.0, status=deferred (error reading forwarding file: Permission denied)
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Local delivery agent could not open user .forward file', 'Local delivery agent could not open user .forward file',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<(?:__RECIPIENT__)>,)? relay=local, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__,\s)?status=deferred \(error reading forwarding file: Permission denied\)$',
        'SAVE_DATA'
);

-- 609504400: to=<gap@cs.tcd.ie>, relay=local, delay=0, status=bounced (mail forwarding loop for gap@cs.tcd.ie)
INSERT INTO rules(name, description, program, regex, result_data, action)
    VALUES('Mail forwarding loop', 'Postfix bounced a mail due to a mail forwarding loop',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=bounced \(mail forwarding loop for \k<recipient>\)$',
        'smtp_code = 554',
        'MAIL_BOUNCED'
);

-- warning: required alias not found: mailer-daemon
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Postfix warning about something', 'Postfix has logged a warning; probably it should be investigated',
        'postfix/local',
        '^warning: (?:required alias not found: .*|pipe_command_read: read time limit exceeded|premature end-of-input on .* socket while reading input attribute name|__QUEUEID__: defer service failure|close file .*.forward: Permission denied)$',
        'UNINTERESTING'
);

-- Ideally we'd do something with these, but we don't have anything to tie them too.
-- We'd need to add another table to save details in.
-- fatal: main.cf configuration error: mailbox_size_limit is smaller than message_size_limit
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Postfix fatal configuration error', 'Postfix has detected a fatal error in main.cf, and cannot run',
        'postfix/local',
        '^fatal: main.cf configuration error: (?:mailbox_size_limit is smaller than message_size_limit)$',
        'UNINTERESTING'
);

-- A15004400: to=<Jean-Marc.Seigneur@cs.tcd.ie>, relay=local, delay=0, status=bounced (unknown user: "jean-marc.seigneur")
INSERT INTO rules(name, description, program, regex, result_data, connection_data, action)
    VALUES('Unknown user??  This should have been caught long ago!', 'We should never have an unknown user at this stage, it should have been caught by smtpd',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=bounced \((__DATA__unknown user: ".*")\)$',
        'smtp_code = 550',
        'client_ip = 127.0.0.1, client_hostname = localhost, server_ip = 127.0.0.1, server_hostname = localhost',
        'MAIL_BOUNCED'
);

-- 165173E19: to=<pbyrne6@cs.tcd.ie>, relay=local, delay=0, status=sent (delivered to file: /dev/null)
INSERT INTO rules(name, description, program, regex, result_data, action)
    VALUES('Local delivery to a file was successful', 'Local delivery of an email succeeded; the final destination was a file',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=sent \(delivered to file: (__DATA__.*)\)$',
        'smtp_code = 250',
        'MAIL_SENT'
);

-- 8344043FD: to=<MAILER-DAEMON@cs.tcd.ie>, relay=local, delay=0, status=sent (discarded)
-- 1522F4317: to=<MAILER-DAEMON@cs.tcd.ie>, orig_to=<MAILER-DAEMON>, relay=local, delay=0, status=sent (discarded)
INSERT INTO rules(name, description, program, regex, result_data, action)
    VALUES('local delivery - discarded??', 'Why was a locally delivered mail discarded??  Should be investigated I think',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=sent \(discarded\)$',
        'smtp_code = 250',
        'MAIL_SENT'
);

-- E3B36450D: to=<eganjo@cs.tcd.ie>, relay=local, delay=36526, status=deferred (temporary failure)
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Temporary failure in local delivery', 'Temporary unspecified failure in local delivery',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \(temporary failure\)$',
        'SAVE_DATA'
);

-- warning: database /mail/postfix/etc/aliases.out.cdb is older than source file /mail/postfix/etc/aliases.out
INSERT INTO rules(name, description, program, regex, action)
    VALUES('The aliases file was not rebuilt', 'The aliases file is newer than the compiled database',
        'postfix/local',
        '^warning: database .* is older than source file .*$',
        'UNINTERESTING'
);

-- 5822E4444: to=<cogsci@cs.tcd.ie>, relay=local, delay=0, status=deferred (cannot find alias database owner)
-- 05CC64462: to=<cs-ugvisitors-list@cs.tcd.ie>, orig_to=<alldayug-list@cs.tcd.ie>, relay=local, delay=1, status=deferred (cannot find alias database owner)
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Delivery delayed, owner unknown', 'Delivery was delayed because the owenr of the alias files is unknown',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=deferred \(cannot find alias database owner\)$',
        'SAVE_DATA'
);

-- This sometimes results when a local delivery fails and this bounce is generated; in that case the {client,server}_{ip,hostname} will be empty, so we supply them.  If they're not required they'll be discarded.
-- D1E494386: to=<scss-staff-bounces+bcollin=cs.tcd.ie@cs.tcd.ie>, relay=local, delay=0, status=bounced (Command died with status 8: "/mail/mailman-2.1.6/mail/mailman bounces scss-staff". Command output: Failure to find group name mailman.  Try adding this group to your system, or re-run configure, providing an existing group name with the command line option --with-mail-gid. )
INSERT INTO rules(name, description, program, regex, result_data, connection_data, action)
    VALUES('Local delivery (pipe to command) failed', 'The command that the mail was piped into failed for some reason',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=local, __DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__, )?status=bounced \((__DATA__Command died with status \d+: .* Command output: .* )\)$',
        'smtp_code = 550',
        'server_hostname = localhost, server_ip = 127.0.0.1, client_hostname = localhost, client_ip = 127.0.0.1',
        'MAIL_BOUNCED'
);

-- warning: cannot find alias database owner for cdb:/mail/mailman/data/aliases(0,34100)
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Table owner cannot be determined', 'The owner of the table foo cannot be determined; probably becaise Solaris LDAP has gone for a nap',
        'postfix/local',
        '^warning: cannot find alias database owner for .*$',
        'UNINTERESTING'
);

-- warning: 781E44393: address with illegal extension: mailman-bounces+john_collins/hq/omron_europe.omron=eu.omron.com
INSERT INTO rules(name, description, program, regex, action)
    VALUES('warning from local', 'A warning message from the local delivery agent',
        'postfix/local',
        '^warning: (__QUEUEID__): address with illegal extension: .*$',
        'UNINTERESTING'
);

-- warning: file /users/pg/steicheb/.forward is not a regular file
INSERT INTO rules(name, description, program, regex, action)
    VALUES('warning about messed up .forward', 'A warning message from the local delivery agent about a mesed up .forward',
        'postfix/local',
        '^warning: file .*.forward is not a regular file$',
        'UNINTERESTING'
);

-- 1DC1F93CF: to=<sfarrel6@cs.tcd.ie>, orig_to=<stephen.farrell@cs.tcd.ie>, relay=local, delay=4651, delays=1729/906/0/2016, dsn=5.3.0, status=bounced (Command time limit exceeded: "/mail/procmail/bin/procmail -p -t /mail/procmail/etc/procmailrc". Command output: procmail: Couldn't chdir to "/users/staff/sfarrel6" procmail: Couldn't chdir to "/users/staff/sfarrel6" procmail: Couldn't chdir to "/users/staff/sfarrel6/Maildir" procmail: Lock failure on "./.Spam/.lock" procmail: Unable to treat as directory "./.Spam" procmail: Error while writing to "./.Spam" procmail: Timeout, terminating "test" )
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Local delivery agent took too long', 'Local delivery agent took too long, so Postfix killed it',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<(?:__RECIPIENT__)>,)? relay=local, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__,\s)?status=bounced \((__DATA__Command time limit exceeded: .+)\)$',
        'MAIL_BOUNCED'
);

-- 6C7D1F3894: to=<james.murphy@cs.tcd.ie>, relay=local, delay=0.04, delays=0.02/0.02/0/0, dsn=2.0.0, status=deliverable (aliased to jfmurphy)
INSERT INTO rules(name, description, program, regex, result_data, action)
    VALUES('Postfix logging how it will deliver some mail via local delivery', 'XXX FIGURE OUT WHY THIS HAPPENS',
        'postfix/local',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<(__RECIPIENT__)>,)? relay=local, (?:__CONN_USE__)?__DELAY__(?:__DELAYS__)?(?:dsn=__ENHANCED_STATUS_CODE__,\s)?status=deliverable \((__DATA__.*)\)$',
        'smtp_code = 250',
        'SAVE_DATA'
);

-- 1}}}

-- PICKUP RULES {{{1

-- 39DE44317: uid=8515 from=<kennyau>
-- 0109D38EC: uid=0 from=<vee08-pc-request@cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, connection_data, action)
    VALUES('Mail submitted with sendmail', 'Mail submitted locally on the machine via sendmail is being picked up',
        'postfix/pickup',
        '^(__QUEUEID__): uid=\d+ from=<__EMAIL__>$',
        'client_hostname = localhost, client_ip = 127.0.0.1, server_hostname = localhost, server_ip = 127.0.0.1',
        'PICKUP'
);

-- }}}

-- POSTSUPER RULES {{{1

-- 5A01B444E: removed
INSERT INTO rules(name, description, program, regex, result_data, action)
    VALUES('Mail deleted using postsuper', 'The mail administrator used postsuper to delete mail from the queue',
        'postfix/postsuper',
        '^(__QUEUEID__): removed$',
        'smtp_code = 554',
        'DELETE'
);

-- Deleted: 1 message
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Postsuper logging how many messages were deleted', 'Postsuper logs how many messages were deleted by the administrator',
        'postfix/postsuper',
        '^Deleted: \d+ message(?:s)?$',
        'UNINTERESTING'
);

-- fatal: usage: postsuper [-c config_dir] [-d queue_id (delete)] [-h queue_id (hold)] [-H queue_id (un-hold)] [-p (purge temporary files)] [-r queue_id (requeue)] [-s (structure fix)] [-v (verbose)] [queue...]
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Postsuper usage message', 'Postsuper logging its usage message',
        'postfix/postsuper',
        '^fatal: usage: postsuper .*$',
        'UNINTERESTING'
);

-- fatal: invalid directory name: 2F03B38A4
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Postsuper invalid directory message', 'Postsuper complaining about an invalid directory name',
        'postfix/postsuper',
        '^fatal: invalid directory name: .*$',
        'UNINTERESTING'
);

-- Released from hold: 3 messages
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Messages released from the hold queue', 'Postsuper released messages from the hold queue',
        'postfix/postsuper',
        '^Released from hold: 3 messages$',
        'UNINTERESTING'
);

-- Renamed to match inode number: 19 messages
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Postfix renamed messages in queue to match inodes', 'Postfix renamed some mails in the queue to match their inode numbers; this generally happens after the queue is backed up and restored',
        'postfix/postsuper',
        '^(?:Renamed to match inode number: \d+ messages|warning: QUEUE FILE NAMES WERE CHANGED TO MATCH INODE NUMBERS)$',
        'UNINTERESTING'
);

-- }}}

-- CLEANUP RULES {{{1

-- 8D6A74406: message-id=<546891334.17703392316576@thebat.net>
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Cleanup doing its thing', 'Cleanup doing whatever it does with mail',
        'postfix/cleanup',
        '^(__QUEUEID__): (?:resent-)?message-id=(__MESSAGE_ID__)$',
        'CLEANUP_PROCESSING'
);

-- warning: 9701438A4: read timeout on cleanup socket
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Something went wrong reading mail', 'Cleanup did not get the full mail',
        'postfix/cleanup',
        '^warning: __QUEUEID__: read timeout on cleanup socket$',
        'UNINTERESTING'
);

-- warning: stripping too many comments from address: Mail Administrator <Postmaster@charter.net> <Postmaster@charter.net> <Postmaster@charter.net> <Postm...
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Warning about messed-up addressing', 'Mail client fscked up the addressing',
        'postfix/cleanup',
        '^warning: stripping too many comments from address: .*$',
        'UNINTERESTING'
);

-- warning: cleanup socket: unexpected EOF in data, record type 78 length 76
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Warning about protocol error', 'Something messed up the protocol',
        'postfix/cleanup',
        '^warning: cleanup socket: unexpected EOF in data, record type \d+ length \d+$',
        'UNINTERESTING'
);

-- warning: pipe_command_read: read time limit exceeded
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Cleanup timed out waiting for data from a pipe', 'Cleanup timed out waiting for data from a pipe',
        'postfix/cleanup',
        '^warning: pipe_command_read: read time limit exceeded$',
        'UNINTERESTING'
);

-- fatal: watchdog timeout
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Cleanup interrupted by watchdog timer', 'Cleanup interrupted by watchdog timer, it must have gotten hung up on a system call',
        'postfix/cleanup',
        '^fatal: watchdog timeout$',
        'UNINTERESTING'
);

-- table cdb:/mail/postfix/etc/grid.ie-aliases(0,lock|fold_fix) has changed -- restarting
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Postfix/cleanup noticed a table changed', 'Postfix/cleanup noticed that a lookup table has changed, so it is restarting',
        'postfix/cleanup',
        '^table .* has changed -- restarting$',
        'UNINTERESTING'
);

-- warning: 03F6E38CA: queue file size limit exceeded
INSERT INTO rules(name, description, program, regex, result_data, action)
    VALUES('Maximum mail size exceeded - probably submitted using sendmail', 'Mail too big - it was probably submitted with the Postfix sendmail command',
        'postfix/cleanup',
        '^warning: (__QUEUEID__): queue file size limit exceeded$',
        'sender = unknown, recipient = unknown, smtp_code = unknown',
        'MAIL_DISCARDED'
);

-- C86F93FD8B: reject: body # THIS IS A WARNING ONLY.  YOU DO NOT NEED TO RESEND YOUR MESSAGE. # from dns1.dns.imagine.ie[87.232.1.40]; from=<> to=<stephen.farrell@cs.tcd.ie> proto=ESMTP helo=<relay.imagine.ie>: 5.7.1 Rejecting backscatter mail
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Rejecting backscatter mail (1)', 'Rejecting backscatter mail: THIS IS A WARNING ONLY. YOU DO NOT NEED TO RESEND YOUR MESSAGE.',
        'postfix/cleanup',
        '^(__QUEUEID__): reject: body # THIS IS A WARNING ONLY.  YOU DO NOT NEED TO RESEND YOUR MESSAGE. # from (__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\]; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>: 5.7.1 Rejecting backscatter mail$',
        'MAIL_DISCARDED'
);

-- 4EB26439F6: reject: body This is the mail system at host relay.iol.cz. from wpad.iss.tcd.ie[134.226.17.160]; from=<> to=<jones@cs.tcd.ie> proto=ESMTP helo=<imx1.tcd.ie>: 5.7.1 Rejecting backscatter mail
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Rejecting backscatter mail (2)', 'Rejecting backscatter mail: relay.iol.cz',
        'postfix/cleanup',
        '^(__QUEUEID__): reject: body This is the mail system at host relay.iol.cz. from (__CLIENT_HOSTNAME__)\[(__CLIENT_IP__)\]; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>: 5.7.1 Rejecting backscatter mail$',
        'MAIL_DISCARDED'
);

-- }}}

-- BOUNCE RULES {{{1

-- 382CD36E3: sender non-delivery notification: 4419C38A0
-- A81E338BB: sender delivery status notification: 4427638C1
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Postfix created a bounce or delivery status message', 'Postfix created a bounce or delivery status message',
        'postfix/bounce',
        '^(__QUEUEID__): sender (?:delivery status|non-delivery) notification: (__CHILD__)$',
        'BOUNCE_CREATED'
);

-- }}}

-- -- MASTER RULES {{{1

-- daemon started -- version 2.2.10, configuration /mail/postfix-2.2.10/etc
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Postfix started', 'Postfix master daemon started',
        'postfix/master',
        '^daemon started -- version \d+\.\d+\.\d+, configuration .*$',
        'POSTFIX_RELOAD'
);

-- reload configuration /mail/postfix-2.2.10/etc
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Postfix reload', 'Postfix master daemon reloaded configuration',
        'postfix/master',
        '^reload configuration .*$',
        'UNINTERESTING'
);

-- terminating on signal 15
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Postfix stop', 'Postfix master daemon stopped',
        'postfix/master',
        '^terminating on signal 15$',
        'POSTFIX_RELOAD'
);

-- warning: /mail/postfix/libexec/smtpd: bad command startup -- throttling
-- warning: ignoring inet_protocols change
-- warning: to change inet_protocols, stop and start Postfix
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Warning of some sort', 'Master logging a warning about something',
        'postfix/master',
        '^warning: .*$',
        'UNINTERESTING'
);

-- warning: process /mail/postfix/libexec/smtpd pid 17850 killed by signal 15
INSERT INTO rules(name, description, program, regex, action, priority)
    VALUES('Master daemon killed an smtpd', 'Master daemon had to kill an smtpd forcefully',
        'postfix/master',
        '^warning: process .*/libexec/smtpd pid (__PID__) killed by signal \d+$',
        'SMTPD_DIED',
        5
);

-- warning: process /mail/postfix/libexec/smtpd pid 13510 exit status 1
INSERT INTO rules(name, description, program, regex, action)
    VALUES('smtpd died', 'An smtpd died for some reason',
        'postfix/master',
        '^warning: process .*/libexec/smtpd pid (__PID__) exit status \d+$',
        'SMTPD_DIED'
);

-- }}}

-- * RULES {{{
-- These rules are applied to all log lines, after the program specific rules.
INSERT INTO rules(name, description, program, regex, action)
    VALUES('Bloody Solaris LDAP', 'Solaris LDAP is trying to load something or other',
        '*',
        '^libsldap: Status: 2  Mesg: Unable to load configuration ./var/ldap/ldap_client_file. \(..\).$',
        'UNINTERESTING'
);

INSERT INTO rules(name, description, program, regex, action)
    VALUES('Bloody Solaris LDAP 2', 'Solaris LDAP cannot connect or something',
        '*',
        '^libsldap: Status: 7  Mesg: Session error no available conn.$',
        'UNINTERESTING'
);

INSERT INTO rules(name, description, program, regex, action)
    VALUES('Bloody Solaris LDAP 3', 'Solaris LDAP cannot bind or connect or something',
        '*',
        '^libsldap: Status: 91  Mesg: openConnection: simple bind failed - Can.t connect to the LDAP server$',
        'UNINTERESTING'
);

INSERT INTO rules(name, description, program, regex, action)
    VALUES('Bloody Solaris LDAP 4', 'Solaris LDAP cannot contact server',
        '*',
        '^libsldap: Status: 81  Mesg: openConnection: simple bind failed - Can.t contact LDAP server$',
        'UNINTERESTING'
);

-- }}}

