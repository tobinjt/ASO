-- vim: set foldmethod=marker textwidth=300 :
-- $Id$

-- XXX: how will I specify warning?

DELETE FROM rules;

-- SMTPD CONNECT RULES {{{1
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('client connection', 'A client has connected',
        'postfix/smtpd',
        '^connect from (__HOSTNAME__)\[(__IP__)\]$',
        '',
        'hostname = 1, ip = 2',
        'CONNECT',
        0
);

-- }}}

-- SMTPD DISCONNECT RULES {{{1
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('client disconnection', 'The client has disconnected cleanly',
        'postfix/smtpd',
        '^disconnect from __HOSTNAME__\[__IP__\]$',
        '',
        '',
        'DISCONNECT',
        0
);

-- }}}

-- SMTPD IGNORE RULES {{{1
-- SMTPD These will always be followed by a disconnect line, as matched above {{{2
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('lost connection', 'Client disconnected uncleanly',
        'postfix/smtpd',
        '^lost connection after \w+ from __HOSTNAME__\[__IP__\]$',
        '',
        '',
        'IGNORE',
        0
);

INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('timeout', 'Timeout sending reply',
        'postfix/smtpd',
        '^timeout after (?:\w+|END-OF-MESSAGE) from __HOSTNAME__\[__IP__\]$',
        '',
        '',
        'IGNORE',
        0
);

INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Too many errors', 'The client has made so many errors postfix has disconnected it',
        'postfix/smtpd',
        '^too many errors after (?:\w+|END-OF-MESSAGE) from __HOSTNAME__\[__IP__\]$',
        '',
        '',
        'IGNORE',
        0
);

-- }}}

-- SMTPD Other lines we want to ignore {{{2
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Warning', 'Warnings of some sort',
        'postfix/smtpd',
        '^warning: ',
        '',
        '',
        'IGNORE',
        0
);

INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Table changed', 'A lookup table has changed, smtpd is quitting',
        'postfix/smtpd',
        '^table .* has changed -- restarting$',
        '',
        '',
        'IGNORE',
        0
);

INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Bloody Solaris LDAP', 'Solaris LDAP is trying to load something or other',
        'postfix/smtpd',
        '^libsldap: Status: 2  Mesg: Unable to load configuration ./var/ldap/ldap_client_file. \(..\).$',
        '',
        '',
        'IGNORE',
        0
);

INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Bloody Solaris LDAP 2', 'Solaris LDAP cannot connect or something',
        'postfix/smtpd',
        '^libsldap: Status: 7  Mesg: Session error no available conn.$',
        '',
        '',
        'IGNORE',
        0
);

-- }}}

-- }}}


-- SMTPD REJECT RULES {{{1

-- <munin@cs.tcd.ie>: Recipient address rejected: User unknown in local recipient table; from=<> to=<munin@cs.tcd.ie> proto=ESMTP helo=<lg12x22.cs.tcd.ie>
-- <hienes@cs.tcd.ie>: Recipient address rejected: User unknown in local recipient table; from=<BrooksPool@rowcmi.org> to=<hienes@cs.tcd.ie> proto=ESMTP helo=<PETTERH?DNEB?>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Unknown recipient', 'The recipient address is unknown on our system',
        'postfix/smtpd',
        '^<(__RECIPIENT__)>: Recipient address rejected: User unknown in local recipient table; from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 1, sender = 2',
        'helo = 3',
        'SAVE',
        0
);

-- <munin@cs.tcd.ie>: Sender address rejected: User unknown in local recipient table; from=<munin@cs.tcd.ie> to=<john.tobin@cs.tcd.ie> proto=ESMTP helo=<lg12x36.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Unknown sender', 'The sender address is unknown on our system',
        'postfix/smtpd',
        '^<(__SENDER__)>: Sender address rejected: User unknown in local recipient table; from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3',
        'SAVE',
        0
);

-- <ocalladw@toad.toad>: Sender address rejected: Domain not found; from=<ocalladw@toad.toad> to=<submit@bugs.gnome.org> proto=SMTP helo=<toad>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Unknown sender domain', 'We do not accept mail from unknown domains',
        'postfix/smtpd',
        '^<(__SENDER__)>: Sender address rejected: Domain not found; from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3',
        'SAVE',
        0
);

-- <stephen@tjbx.org>: Recipient address rejected: Domain not found; from=<4sdcsaz@nbsanjiang.com> to=<stephen@tjbx.org> proto=ESMTP helo=<nbsanjiang.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Unknown recipient domain', 'We do not accept mail for unknown domains',
        'postfix/smtpd',
        '^<(__RECIPIENT__)>: Recipient address rejected: Domain not found; from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3',
        'SAVE',
        0
);

-- Service unavailable; Client host [190.40.116.202] blocked using sbl-xbl.spamhaus.org; from=<taliaferraearl@blackburn-green.com> to=<amjudge@dsg.cs.tcd.ie> proto=SMTP helo=<blackburn-green.com>
-- Service unavailable; Client host [211.212.156.4] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/query/bl?ip=211.212.156.4; from=<lucia@abouttimemag.com> to=<amjudge@dsg.cs.tcd.ie> proto=SMTP helo=<abouttimemag.com>
-- Service unavailable; Client host [66.30.84.174] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/query/bl?ip=66.30.84.174; from=<DianaBoykin@movemail.com> to=<Paolo.Rosso@cs.tcd.ie> proto=SMTP helo=<b100mng10bce9ob.hsd1.ma.comcast.net.>
-- Service unavailable; Client host [210.236.32.153] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/SBL/sbl.lasso?query=SBL47877; from=<euyery@linuxmail.org> to=<vinny.cahill@cs.tcd.ie> proto=SMTP helo=<eworuetyberiyneortmweprmuete57197179680.com>
-- Service unavailable; Client host [204.14.1.123] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/SBL/sbl.lasso?query=SBL27197 / http://www.spamhaus.org/SBL/sbl.lasso?query=SBL47903; from=<tia@baraskaka.com> to=<vjcahill@dsg.cs.tcd.ie> proto=SMTP helo=<customer.optindirectmail.123.sls-hosting.com>
-- Service unavailable; Client host [82.119.202.142] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/query/bl?ip=82.119.202.142; from=<001topzine-hypertext@123point.net> to=<ecdlf@cs.tcd.ie.> proto=ESMTP helo=<cs.tcd.ie.>

INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Blacklisted by SpamHaus SBL-XBL', 'The client IP address is blacklisted by SpamHaus SBL-XBL',
        'postfix/smtpd',
        '^Service unavailable; Client host (?>\[(__IP__)\]) blocked using sbl-xbl.spamhaus.org;(?:((?:(?:(?: http://www.spamhaus.org/SBL/sbl.lasso\?query=\w+)|(?: http://www.spamhaus.org/query/bl\?ip=\1))(?: /)?)*);)? (?>from=<(__SENDER__)>) to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 4, data = 2, sender = 3',
        'helo = 5',
        'SAVE',
        0
);

-- Service unavailable; Client host [80.236.27.105] blocked using list.dsbl.org; http://dsbl.org/listing?80.236.27.105; from=<mrnpftjx@pacbell.net> to=<tom.irwin@cs.tcd.ie> proto=SMTP helo=<ip-105.net-80-236-27.asnieres.rev.numericable.fr>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Blacklisted by DSBL', 'The client IP address is blacklisted by DSBL',
        'postfix/smtpd',
        '^Service unavailable; Client host (?>\[(__IP__)\]) blocked using list.dsbl.org; (?>(http://dsbl.org/listing\?\1);) from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 4, data = 2, sender = 3',
        'helo = 5',
        'SAVE',
        0
);

-- Service unavailable; Client host [148.243.214.52] blocked using relays.ordb.org; This mail was handled by an open relay - please visit <http://ORDB.org/lookup/?host=148.243.214.52>; from=<cw-chai@umail.hinet.net> to=<webmaster@cs.tcd.ie> proto=ESMTP helo=<sicomnet.edu.mx>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Blacklisted by ordb.org', 'The client IP address is blacklisted by ordb.org',
        'postfix/smtpd',
        '^Service unavailable; Client host (?>\[(__IP__)\]) blocked using relays.ordb.org; (?>(This mail was handled by an open relay - please visit <http://ORDB.org/lookup/\?host=\1>);) from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 4, data = 2, sender = 3',
        'helo = 5',
        'SAVE',
        0
);

-- Service unavailable; Client host [60.22.99.9] blocked using cbl.abuseat.org; Blocked - see http://cbl.abuseat.org/lookup.cgi?ip=60.22.99.9; from=<pegbxbsusiiao@cowboyart.net> to=<daokeeff@cs.tcd.ie> proto=SMTP helo=<cowboyart.net>
-- Service unavailable; Client host [90.194.116.50] blocked using cbl.abuseat.org; from=<lazauear@appleleasing.com> to=<noctor@cs.tcd.ie> proto=SMTP helo=<appleleasing.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Blacklisted by CBL', 'The client IP address is blacklisted by CBL',
        'postfix/smtpd',
        '^Service unavailable; Client host (?>\[(__IP__)\]) blocked using cbl.abuseat.org;(?>( Blocked - see http://cbl.abuseat.org/lookup.cgi\?ip=\1);)? from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 4, data = 2, sender = 3',
        'helo = 5',
        'SAVE',
        0
);

-- <31.pool80-103-5.dynamic.uni2.es[80.103.5.31]>: Client host rejected: Greylisted, see http://isg.ee.ethz.ch/tools/postgrey/help/dsg.cs.tcd.ie.html; from=<iqxrgomtl@purinmail.com> to=<skenny@dsg.cs.tcd.ie> proto=SMTP helo=<31.pool80-103-5.dynamic.uni2.es>
-- <mail.saraholding.com.sa[212.12.166.254]>: Client host rejected: Greylisted, see http://isg.ee.ethz.ch/tools/postgrey/help/cs.tcd.ie.html; from=<lpty@[212.12.166.226]> to=<colin.little@cs.tcd.ie> proto=ESMTP helo=<mail.saraholding.com.sa>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Greylisted', 'Client greylisted; see http://www.greylisting.org/ for more details',
        'postfix/smtpd',
        '^<__HOSTNAME__\[__IP__\]>: Client host rejected: Greylisted, see (http://isg.ee.ethz.ch/tools/postgrey/help/[^\s]+); from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 3, data = 1, sender = 2',
        'helo = 4',
        'SAVE',
        0
);

-- <nicholas@seaton.biz>: Sender address rejected: Address uses MX in loopback address space (127.0.0.0/8); from=<nicholas@seaton.biz> to=<gillian.long@cs.tcd.ie> proto=ESMTP helo=<friend>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Sender MX in loopback address space', 'The MX for sender domain is in loopback address space, so cannot be contacted',
        'postfix/smtpd',
        '^<(__SENDER__)>: Sender address rejected: Address uses MX in loopback address space \(127.0.0.0/8\); from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3',
        'SAVE',
        0
);

-- <aaholi@web009.ahp01.lax.affinity.com>: Sender address rejected: Address uses MX in private address space (127.16.0.0/12); from=<aaholi@web009.ahp01.lax.affinity.com> to=<luzs@cs.tcd.ie> proto=ESMTP helo=<ams006.lax.affinity.com> 
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Sender MX in private address space (127.16.0.0/12)', 'The MX for sender domain is in private address space (127.16.0.0/12), so cannot be contacted',
        'postfix/smtpd',
        '^<(__SENDER__)>: Sender address rejected: Address uses MX in private address space \(127.16.0.0/12\); from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3',
        'SAVE',
        0
);

-- <hlhbs@china.org.cn>: Recipient address rejected: Address uses MX in private address space (127.16.0.0/12); from=<1221q5@chinachewang.com> to=<hlhbs@china.org.cn> proto=ESMTP helo=<chinachewang.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Recipient MX in private address space (127.16.0.0/12)', 'The MX for recipient domain is in private address space (127.16.0.0/12), so cannot be contacted',
        'postfix/smtpd',
        '^<(__RECIPIENT__)>: Recipient address rejected: Address uses MX in private address space \(127.16.0.0/12\); from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 1, sender = 2',
        'helo = 3',
        'SAVE',
        0
);

-- <aeneasdecathlon@rotnot.com>: Sender address rejected: Address uses MX in private address space (192.168.0.0/16); from=<aeneasdecathlon@rotnot.com> to=<MCCARTHY@CS.tcd.ie> proto=ESMTP helo=<vms1.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Sender MX in private address space (192.168.0.0/16)', 'The MX for sender domain is in private address space (192.168.0.0/16), so cannot be contacted',
        'postfix/smtpd',
        '^<(__SENDER__)>: Sender address rejected: Address uses MX in private address space \(192.168.0.0/16\); from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3',
        'SAVE',
        0
);

-- <showh@tdt3.com.tw>: Recipient address rejected: Address uses MX in private address space (192.168.0.0/16); from=<zsl.gzrza@yahoo.com.tw> to=<showh@tdt3.com.tw> proto=SMTP helo=<134.226.32.56>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Recipient MX in private address space (192.168.0.0/16)', 'The MX for Recipient domain is in private address space (192.168.0.0/16), so cannot be contacted',
        'postfix/smtpd',
        '<(__RECIPIENT__)>: Recipient address rejected: Address uses MX in private address space \(192.168.0.0/16\); from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>',
        'recipient = 1, sender = 2',
        'helo = 3',
        'SAVE',
        0
);

-- <acornascription@rot.wartesaal.darktech.org>: Sender address rejected: Address uses MX in private address space (10.0.0.0/8); from=<acornascription@rot.wartesaal.darktech.org> to=<gap@cs.tcd.ie> proto=ESMTP helo=<xmx1.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Sender MX in private address space (10.0.0.0/8)', 'The MX for sender domain is in private address space (10.0.0.0/8), so cannot be contacted',
        'postfix/smtpd',
        '^<(__SENDER__)>: Sender address rejected: Address uses MX in private address space \(10.0.0.0/8\); from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3',
        'SAVE',
        0
);

-- <mactusqdx@wartesaal.darktech.org>: Recipient address rejected: Address uses MX in private address space (10.0.0.0/8); from=<bartel@integramed.com> to=<mactusqdx@wartesaal.darktech.org> proto=SMTP helo=<integramed.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Recipient MX in private address space (10.0.0.0/8)', 'The MX for recipient domain is in private address space (10.0.0.0/8), so cannot be contacted',
        'postfix/smtpd',
        '^<(__RECIPIENT__)>: Recipient address rejected: Address uses MX in private address space \(10.0.0.0/8\); from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 1, sender = 2',
        'helo = 3',
        'SAVE',
        0
);

-- <banihashemian@modares.ac.ir>: Sender address rejected: Address uses MX in local address space (169.254.0.0/16); from=<banihashemian@modares.ac.ir> to=<Elisa.Baniassad@cs.tcd.ie> proto=ESMTP helo=<mail-relay1.cs.ubc.ca>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Sender MX in "local" address space (169.254.0.0/16)', 'The MX for sender domain is in "local" address space (169.254.0.0/16), so cannot be contacted',
        'postfix/smtpd',
        '^<(__SENDER__)>: Sender address rejected: Address uses MX in local address space \(169.254.0.0/16\); from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3',
        'SAVE',
        0
);

-- <lisa@telephonebooth.com>: Sender address rejected: Address uses MX in "this" address space (0.0.0.0/8); from=<lisa@telephonebooth.com> to=<francis.neelamkavil@cs.tcd.ie> proto=SMTP helo=<localhost>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Sender MX in "this" address space (0.0.0.0/8)', 'The MX for sender domain is in "this" address space (0.0.0.0/8), so cannot be contacted',
        'postfix/smtpd',
        '^<(__SENDER__)>: Sender address rejected: Address uses MX in "this" address space \(0.0.0.0/8\); from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3',
        'SAVE',
        0
);

-- <af53eec9@verpiss-dich.de>: Recipient address rejected: Address uses MX in loopback address space (127.0.0.0/8); from=<cbsrlkhaigye@allsaintsfan.com> to=<af53eec9@verpiss-dich.de> proto=SMTP helo=<127.0.0.1>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Recipient MX in loopback address space (127.0.0.0/8)', 'The MX for recipient domain is in loopback address space (127.0.0.0/8), so cannot be contacted',
        'postfix/smtpd',
        '^<(__RECIPIENT__)>: Recipient address rejected: Address uses MX in loopback address space \(127.0.0.0/8\); from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 1, sender = 2',
        'helo = 3',
        'SAVE',
        0
);

-- <ForestSimmspq@rpis.pl>: Sender address rejected: Address uses MX in reserved address space (240.0.0.0/4); from=<ForestSimmspq@rpis.pl> to=<dave.lewis@cs.tcd.ie> proto=ESMTP helo=<xmx1.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Sender MX in reserved address space (240.0.0.0/4)', 'The MX for sender domain is in reserved address space (240.0.0.0/4), so cannot be contacted',
        'postfix/smtpd',
        '^<(__SENDER__)>: Sender address rejected: Address uses MX in reserved address space \(240.0.0.0/4\); from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3',
        'SAVE',
        0
);

-- <cs.tcd.ie>: Helo command rejected: You are not in cs.tcd.ie; from=<van9219@yahoo.co.jp> to=<david.ocallaghan@cs.tcd.ie> proto=SMTP helo=<cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Faked CS HELO', 'The client used a CS address in HELO but is not within our network',
        'postfix/smtpd',
        '^<(__HELO__)>: Helo command rejected: You are not in cs.tcd.ie; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\1>$',
        'recipient = 3, sender = 2',
        'helo = 1',
        'SAVE',
        0
);

-- <a-tikx23d9jlacr>: Helo command rejected: need fully-qualified hostname; from=<aprenda06@walla.com> to=<michael.brady@cs.tcd.ie> proto=SMTP helo=<a-tikx23d9jlacr>
-- <203.162.3.152>: Helo command rejected: need fully-qualified hostname; from=<grid-ireland-ca@cs.tcd.ie> to=<grid-ireland-ca@cs.tcd.ie> proto=ESMTP helo=<203.162.3.152>
-- <qbic>: Helo command rejected: need fully-qualified hostname; from=<> to=<faircloc@cs.tcd.ie> proto=ESMTP helo=<qbic>
-- XXX: How do I match fscked up adresses like louis@contact@barclayimmo.dyndns.org ??
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Non-FQDN HELO', 'The hostname given in the HELO command is not fully qualified, i.e. it lacks a domain',
        'postfix/smtpd',
        '^(?><(.*?)>:) Helo command rejected: need fully-qualified hostname; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\1>$',
        'recipient = 3, sender = 2',
        'helo = 1',
        'SAVE',
        0
);

-- <among@ecosse.net>: Relay access denied; from=<uvqjnkhcwanbvk@walla.com> to=<among@ecosse.net> proto=SMTP helo=<88-134-149-72-dynip.superkabel.de>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Relaying denied', 'Client tried to use us as an open relay',
        'postfix/smtpd',
        '^<(__RECIPIENT__)>: Relay access denied; from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 1, sender = 2',
        'helo = 3',
        'SAVE',
        0
);

-- Client host rejected: cannot find your hostname, [190.40.183.65]; from=<dage@0451.com> to=<ebarrett@cs.tcd.ie> proto=ESMTP helo=<client-200.121.175.96.speedy.net.pe>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Unknown hostname', 'No PTR record for client IP address',
        'postfix/smtpd',
        '^Client host rejected: cannot find your hostname, \[__IP__\]; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3',
        'SAVE',
        0
);

-- <[]>: Helo command rejected: invalid ip address; from=<mrmmpwv@parfive.com> to=<hitesh.tewari@cs.tcd.ie> proto=ESMTP helo=<[]>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Invalid HELO ip address', 'The hostname used in the HELO command is invalid',
        'postfix/smtpd',
        '<(.*?)>: Helo command rejected: invalid ip address; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\1>',
        'recipient = 3, sender = 2',
        'helo = 1',
        'SAVE',
        0
);

-- <24383590>: Helo command rejected: Invalid name; from=<CBKWPMIUF@hotmail.com> to=<byrne@cs.tcd.ie> proto=SMTP helo=<24383590>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Invalid HELO hostname', 'The client used an invalid hostname in the HELO command',
        'postfix/smtpd',
        '^<(.*?)>: Helo command rejected: Invalid name; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\1>$',
        'recipient = 3, sender = 2',
        'helo = 1',
        'SAVE',
        0
);

-- <daemon@cs.tcd.ie>: Recipient address rejected: recipient address unknown; from=<> to=<daemon@cs.tcd.ie> proto=ESMTP helo=<lg12x21.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Unknown recipient (system user)', 'The recipient address is unknown on our system (system users should not receive mail)',
        'postfix/smtpd',
        '^<(__RECIPIENT__)>: Recipient address rejected: recipient address unknown; from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 1, sender = 2',
        'helo = 3',
        'SAVE',
        0
);

-- <daemon@cs.tcd.ie>: Sender address rejected: sender address unknown; from=<daemon@cs.tcd.ie> to=<root@cs.tcd.ie> proto=ESMTP helo=<apex.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Unknown sender (system user)', 'The sender address is unknown on our system (system users should not send mail)',
        'postfix/smtpd',
        '^<(__SENDER__)>: Sender address rejected: sender address unknown; from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3',
        'SAVE',
        0
);

-- <neville.harris@cs.tcd.ie>: Recipient address rejected: User no longer receiving mail at this address; from=<have@jewelprecision.com> to=<neville.harris@cs.tcd.ie> proto=SMTP helo=<jewelprecision.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Unknown recipient (user not receiving mail)', 'The recipient address is unknown on our system (user not receiving mail here any more)',
        'postfix/smtpd',
        '^<(__RECIPIENT__)>: Recipient address rejected: User no longer receiving mail at this address; from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 1, sender = 2',
        'helo = 3',
        'SAVE',
        0
);

-- <godiva.cs.tcd.ie[134.226.35.142]>: Client host rejected: Alias root to something useful.; from=<root@godiva.cs.tcd.ie> to=<root@godiva.cs.tcd.ie> proto=SMTP helo=<godiva.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Unwanted mail to root', 'People keep sending us mail for root at their machine',
        'postfix/smtpd',
        '^<__HOSTNAME__(?>\[__IP__\]>:) Client host rejected: Alias root to something useful.; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>',
        'recipient = 2, sender = 1',
        'helo = 3',
        'SAVE',
        0
);

-- <root@pc910.cs.tcd.ie>: Recipient address rejected: alias root to some other user, damnit.; from=<root@pc910.cs.tcd.ie> to=<root@pc910.cs.tcd.ie> proto=ESMTP helo=<vangogh.cs.tcd.ie>
-- <root@pc910.cs.tcd.ie>: Recipient address rejected: alias root to some other user, damnit.; from=<> to=<root@pc910.cs.tcd.ie> proto=ESMTP helo=<vangogh.cs.tcd.ie>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Unwanted mail to root 2', 'People keep sending us mail for root at their machine (2)',
        'postfix/smtpd',
        '^<(__SENDER__)>: Recipient address rejected: alias root to some other user, damnit.; from=<(__RECIPIENT__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 1, sender = 2',
        'helo = 3',
        'SAVE',
        0
);

-- Client host rejected: cannot find your hostname, [199.84.53.138]; from=<security@e-gold.com.> to=<melanie.bouroche@cs.tcd.ie> proto=ESMTP helo=<DynamicCorp.net>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Rejected client without PTR', 'Client IP address does not have associated PTR record',
        'postfix/smtpd',
        '^Client host rejected: cannot find your hostname, \[__IP__\]; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3',
        'SAVE',
        0
);

-- <localhost.localhost>: Helo command rejected: You are not me; from=<qute1212000@yahoo.it> to=<mads.haahr@cs.tcd.ie> proto=SMTP helo=<localhost.localhost>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Fake localhost HELO', 'The client claimed to be localhost in the HELO command',
        'postfix/smtpd',
        '^<(__HELO__)>: Helo command rejected: You are not me; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\1>$',
        'recipient = 3, sender = 2',
        'helo = 1',
        'SAVE',
        0
);

-- <apache>: Sender address rejected: need fully-qualified address; from=<apache> to=<Arthur.Hughes@cs.tcd.ie> proto=ESMTP helo=<najm.tendaweb.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Non-FQDN sender', 'Sender addresses must be in FQDN form, so replies can be sent',
        'postfix/smtpd',
        '^<(__SENDER__)>: Sender address rejected: need fully-qualified address; from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3',
        'SAVE',
        0
);

-- <DATA>: Data command rejected: Multi-recipient bounce; from=<> proto=SMTP helo=<mail71.messagelabs.com>
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Multi-recipient bounce rejected', 'Any mail from <> should be a bounce, therefore if there is more than one recipient it can be rejected',
        'postfix/smtpd',
        '^<DATA>: Data command rejected: Multi-recipient bounce; from=<()> proto=SMTP helo=<(__HELO__)>$',
        'sender = 1',
        'helo = 2',
        'SAVE',
        0
);

-- }}}

-- SMTPD ACCEPT RULES {{{1
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Mail accepted', 'Postfix accepted the mail; it is hardly obvious from the log message though',
        'postfix/smtpd',
        '^(__QUEUEID__): client=(__HOSTNAME__)\[(__IP__)\]$',
        '',
        'queueid = 1, hostname = 2, ip = 3',
        'SAVE',
        1
);

-- }}}


-- QMGR RULES {{{1
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Mail delivery accomplished', 'qmgr is finished with the mail; it has been delivered',
        'postfix/qmgr',
        '^(__QUEUEID__): removed$',
        '',
        'queueid = 1',
        'COMMIT',
        1
);

-- 6508A4317: from=<florenzaaluin@callisupply.com>, size=2656, nrcpt=1 (queue active)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('qmgr processing mail', 'qmgr is going to deliver this mail',
        'postfix/qmgr',
        '^(__QUEUEID__): from=<(__SENDER__)>, size=\d+, nrcpt=(\d+) \(queue active\)$',
        'sender = 2',
        'queueid = 1, nrcpt = 3',
        'SAVE',
        1
);

-- B1508348E: from=<tcd-mzones-management-bounces+79talbert=jinan.gov.cn@cs.tcd.ie>, status=expired, returned to sender
-- 9C169364A: from=<>, status=expired, returned to sender
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('mail has been queued for too long', 'mail has been sitting in the queue for too long, postifx is giving up on it',
        'postfix/qmgr',
        '^(__QUEUEID__): from=<(__SENDER__)>, status=expired, returned to sender$',
        'sender = 1',
        '',
        'SAVE',
        1
);

-- INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
--     VALUES('', '',
--         '',
--         '',
--         '',
--         '',
--         'SAVE',
--         
-- );


-- SMTP RULES {{{1

-- 058654401: to=<autosupport@netapp.com>, relay=mx1.netapp.com[216.240.18.38], delay=53, status=sent (250 ok:  Message 348102483 accepted)
-- 253234317: to=<shanneneables@granherne.com>, relay=houmail002.halliburton.com[34.254.16.14], delay=2, status=sent (250 2.0.0 kA50s0cL029158 Message accepted for delivery)
-- 0226B4317: to=<rajaverma@gmail.com>, relay=gmail-smtp-in.l.google.com[66.249.93.114], delay=1, status=sent (250 2.0.0 OK 1162706943 x33si2914313ugc)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('mail delivered to outside world', 'a mail was delivered to an outside address',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>, relay=(__HOSTNAME__)\[(__IP__)\], delay=\d+, status=sent \((250) (.*)\)$',
        'recipient = 2, data = 6, smtp_code = 5',
        'queueid = 1, hostname = 3, ip = 4',
        'SAVE',
        1
);

-- 1C8E84317: to=<dolan@cs.tcd.ie>, relay=127.0.0.1[127.0.0.1], delay=8, status=sent (250 2.6.0 Ok, id=00218-02, from MTA([127.0.0.1]:11025): 250 Ok: queued as 2677C43FD)
-- 730AC43FD: to=<grid-ireland-alert@cs.tcd.ie>, relay=127.0.0.1[127.0.0.1], delay=0, status=sent (250 2.6.0 Ok, id=15759-01-2, from MTA([127.0.0.1]:11025): 250 Ok: queued as A3B7C4403)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('mail passed to amavisd', 'mail has been passed to amavisd for filtering',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>, relay=(127.0.0.1)\[(127.0.0.1)\], delay=\d+, status=sent \((250) (2.6.0 Ok, id=\d+(?:-\d+)+, from MTA\(\[127.0.0.1\]:\d+\): 250 Ok: queued as __QUEUEID__)\)$',
        'recipient = 2, smtp_code = 5, data = 6',
        'queueid = 1, hostname = 3, ip = 4',
        'SAVE',
        1
);

-- DC1484406: to=<elisab@gmail.com>, orig_to=<elisa.baniassad@cs.tcd.ie>, relay=gmail-smtp-in.l.google.com[66.249.93.114], delay=1, status=sent (250 2.0.0 OK 1162686664 53si2666246ugd)
-- B7F9D4400: to=<dalyj1@tcd.ie>, orig_to=<dalyj1@cs.tcd.ie>, relay=imx1.tcd.ie[134.226.17.160], delay=0, status=sent (250 Ok: queued as BE7B04336)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('mail aliased to outside world', 'mail was sent to a local alias which expanded to an external address',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>, orig_to=<(__RECIPIENT__)>, relay=(__HOSTNAME__)\[(__IP__)\], delay=\d+, status=sent \((250) (.*)\)$',
        'recipient = 3, smtp_code = 6, data = 7',
        'queueid = 1, hostname = 4, ip = 5',
        'SAVE',
        1
);

-- XXX: why is this being discarded?
-- 56EE54317: to=<creans@cs.tcd.ie>, relay=127.0.0.1[127.0.0.1], delay=3, status=sent (250 2.7.1 Ok, discarded, id=00218-04 - VIRUS: HTML.Phishing.Bank-753)
-- D93E84400: to=<diana.wilson@cs.tcd.ie>, relay=127.0.0.1[127.0.0.1], delay=1, status=sent (250 2.7.1 Ok, discarded, id=00218-03-2 - VIRUS: HTML.Phishing.Bank-753)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('mail discarded by amavisd', 'mail was passed to amavisd, which discarded it',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>, relay=(127.0.0.1)\[(127.0.0.1)\], delay=\d+, status=sent \((250) (2.7.1 Ok, discarded, id=\d+(?:-\d+)+ - VIRUS: .*)\)$',
        'recipient = 2, smtp_code = 5, data = 6',
        'queueid = 1, hostname = 3, ip = 4',
        'SAVE',
        1
);

-- connect to wsatkins.co.uk[193.117.23.129]: Connection refused (port 25)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('connect refused', 'postfix tried to connect to a remote smtp server, but the connection was refused',
        'postfix/smtp',
        '^connect to (__HOSTNAME__)\[(__IP__)\]: Connection refused \(port 25\)$',
        '',
        '',
        'IGNORE',
        0
);

-- 4CC8443C5: to=<abutbrittany@route66bikers.com>, relay=none, delay=222439, status=deferred (connect to route66bikers.com[69.25.142.6]: Connection timed out)
-- D004043FD: to=<bjung@uvic.ca>, orig_to=<jungb@cs.tcd.ie>, relay=none, delay=31, status=deferred (connect to smtpx.uvic.ca[142.104.5.91]: Connection timed out)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('mail delayed', 'the connection timed out while trying to deliver mail',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=none, delay=\d+, status=deferred \(connect to (__HOSTNAME__)\[(__IP__)\]: Connection timed out\)$',
        'recipient = 2',
        'queueid = 1, hostname = 3, ip = 4',
        'SAVE',
        1
);

-- 7A06F3489: to=<azo@www.instantweb.com>, relay=www.instantweb.com[206.185.24.12], delay=68210, status=deferred (host www.instantweb.com[206.185.24.12] said: 451 qq write error or disk full (#4.3.0) (in reply to end of DATA command))
-- B697043F0: to=<matthew@sammon.info>, orig_to=<matthew.sammon@cs.tcd.ie>, relay=mail.hosting365.ie[82.195.128.132], delay=1, status=deferred (host mail.hosting365.ie[82.195.128.132] said: 450 <matthew@sammon.info>: Recipient address rejected: Greylisted for 5 minutes (in reply to RCPT TO command))
-- DDF6A3489: to=<economie-recherche@region-bretagne.fr>, relay=rain-pdl.megalis.org[217.109.171.200], delay=1, status=deferred (host rain-pdl.megalis.org[217.109.171.200] said: 450 <economie-recherche@region-bretagne.fr>: Recipient address rejected: Greylisted for 180 seco nds (see http://isg.ee.ethz.ch/tools/postgrey/help/region-bretagne.fr.html) (in reply to RCPT TO command))
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('mail deferred because of a problem at the remote end', 'mail deferred because of a problem at the remote end',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__HOSTNAME__)\[(__IP__)\], delay=\d+, status=deferred \(host \3\[\4\] said: ((__SMTP_CODE__) .*) \(in reply to (?:RCPT TO|end of DATA) command\)\)',
        'recipient = 2, smtp_code = 5, data = 6',
        'queueid = 1, host = 3, ip = 4',
        'SAVE',
        1
);

-- 99C2243F0: to=<mounderek@bigfot.com>, relay=none, delay=385069, status=deferred (connect to mail.ehostinginc.com[66.172.49.6]: Connection refused)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('connect refused (more detailed)', 'Connection refused by the remote server',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>, relay=none, delay=\d+, status=deferred \(connect to (__HOSTNAME__)\[(__IP__)\]: Connection refused\)$',
        'recipient = 2',
        'queueid = 1, hostname = 3, ip = 4',
        'SAVE',
        1
);

-- 7ABDF43FD: to=<olderro@myccccd.net>, relay=none, delay=0, status=bounced (Host or domain name not found. Name service error for name=mailcruiser.campuscruiser.com type=A: Host not found)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Recipient MX not found', 'No MX server for the recipient was found',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>, relay=none, delay=\d+, status=bounced \(Host or domain name not found. Name service error for name=(__HOSTNAME__) type=(?:MX|A): Host not found\)',
        'recipient = 2, hostname = 3',
        'queueid = 1',
        'SAVE',
        1
);

-- B028035EB: to=<Iain@fibernetix.com>, relay=none, delay=282964, status=deferred (Host or domain name not found. Name service error for name=fibernetix.com type=MX: Host not found, try again)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Recipient MX not found (try again)', 'No MX server for the recipient was found',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>, relay=none, delay=\d+, status=deferred \(Host or domain name not found. Name service error for name=(__HOSTNAME__) type=(?:A|MX): Host not found, try again\)',
        'recipient = 2, hostname = 3',
        'queueid = 1',
        'SAVE',
        1
);

-- connect to lackey.cs.qub.ac.uk[143.117.5.165]: Connection timed out (port 25)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('connect timed out', 'time out while postfix was connecting to remote server',
        'postfix/smtp',
        '^connect to __HOSTNAME__\[__IP__\]: Connection timed out \(port 25\)$',
        '',
        '',
        'IGNORE',
        0
);

-- D7B274401: to=<jaumaffup@cchlis.com>, relay=cchlis.com.s5a1.psmtp.com[64.18.4.10], delay=2, status=bounced (host cchlis.com.s5a1.psmtp.com[64.18.4.10] said: 550 5.1.1 User unknown (in reply to RCPT TO command))
-- A71B043FD: to=<dpdlbalgkcm@malaysia.net>, relay=malaysia-net.mr.outblaze.com[205.158.62.177], delay=31, status=bounced (host malaysia-net.mr.outblaze.com[205.158.62.177] said: 550 <>: No thank you rejected: Account Unavailable: Possible Forgery (in reply to RCPT TO command))
-- 224E243C3: to=<lamohtm@mail.ru>, orig_to=<sergey.tsvetkov@cs.tcd.ie>, relay=mxs.mail.ru[194.67.23.20], delay=5, status=bounced (host mxs.mail.ru[194.67.23.20] said: 550 spam message discarded. If you think that the system is mistaken, please report details to abuse@corp.mail.ru (in reply to end of DATA command))
-- 
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('mail to outside world rejected', 'mail to the outside world was rejected',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<__RECIPIENT__>,)? relay=(__HOSTNAME__)\[(__IP__)\], delay=\d+, (?>status=bounced) \(host \3\[\4\] said: ((__SMTP_CODE__) .*) \(in reply to (?:RCPT TO|end of DATA) command\)\)$',
        'recipient = 2, smtp_code = 5, data = 6',
        'queueid = 1, hostname = 3, ip = 4',
        'SAVE',
        1
);

-- connect to mx1.mail.yahoo.com[4.79.181.14]: server refused to talk to me: 421 Message from (134.226.32.56) temporarily deferred - 4.16.50. Please refer to http://help.yahoo.com/help/us/mail/defer/defer-06.html   (port 25)
-- connect to mx1.mail.ukl.yahoo.com[195.50.106.7]: server refused to talk to me: 451 Message temporarily deferred - 4.16.50   (port 25)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Server refused to talk', 'The remote server refused to talk for some reason',
        'postfix/smtp',
        '^connect to __HOSTNAME__\[__IP__\]: server refused to talk to me: __SMTP_CODE__ (?:.*) \(port 25\)$',
        '',
        '',
        'IGNORE',
        0
);

-- 31AE04400: to=<domurtag@yahoo.co.uk>, orig_to=<domurtag@cs.tcd.ie>, relay=none, delay=0, status=deferred (connect to mx2.mail.ukl.yahoo.com[217.12.11.64]: server refused to talk to me: 451 Message temporarily deferred - 4.16.50  )
-- A932037C8: to=<ayako70576@freewww.info>, relay=none, delay=30068, status=deferred (connect to vanitysmtp.changeip.com[143.215.15.51]: server refused to talk to me: 421 cannot send to name server  )
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Server refused to talk (later stage?)', 'The remote server refused to talk for some reason - at a later stage?  We have a queueid anyway',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>,(?: orig_to=<(__RECIPIENT__)>,)? relay=none, delay=\d+, status=deferred \(connect to (__HOSTNAME__)\[(__IP__)\]: server refused to talk to me: ((__SMTP_CODE__) .*)\)$',
        'recipient = 2, smtp_code = 6, data = 5',
        'queueid = 1, hostname = 3, ip = 4',
        'SAVE',
        1
);
-- warning: numeric domain name in resource data of MX record for phpcompiler.org: 80.68.89.7
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Warning from smtp', 'Warning of some sort from smtp - rare',
        'postfix/smtp',
        '^warning: ',
        '',
        '',
        'IGNORE',
        0
);

-- 18FCF43C3: host iona.com.s8a1.psmtp.com[64.18.7.10] said: 451 Can't connect to iona.ie - psmtp (in reply to RCPT TO command)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('Generic smtp failure', 'A catchall for failures we do not have more specific tests for',
        'postfix/smtp',
        '^(__QUEUEID__): host (__HOSTNAME__)\[(__IP__)\] said: (__SMTP_CODE__) (.*) \(in reply to (?:RCPT TO|end of DATA) command\)$',
        'data = 5, smtp_code = 4',
        'queueid = 1, hostname = 2, ip = 3',
        'SAVE',
        1
);

-- connect to smap-net-bk.mr.outblaze.com[205.158.62.181]: read timeout (port 25)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('read timeout', 'reading data from remote server timed out',
        'postfix/smtp',
        '^connect to __HOSTNAME__\[__IP__\]: read timeout \(port 25\)$',
        '',
        '',
        'IGNORE',
        0
);

-- C770E4317: to=<nywzssbpk@smapxsmap.net>, relay=none, delay=944, status=deferred (connect to smap-net-bk.mr.outblaze.com[205.158.62.177]: read timeout)
INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
    VALUES('read timeout (with queueid)', 'read timeout during connect - with queueid',
        'postfix/smtp',
        '^(__QUEUEID__): to=<(__RECIPIENT__)>, relay=none, delay=\d+, status=deferred \(connect to (__HOSTNAME__)\[(__IP__)\]: read timeout\)',
        'recipient = 2',
        'queueid = 1, hostname = 3, ip = 4',
        'SAVE',
        1
);

-- }}}

-- INSERT INTO rules(name, description, program, regex, result_cols, connection_cols, action, queueid)
--     VALUES('', '',
--         '',
--         '',
--         '',
--         '',
--         'SAVE',
--         
-- );

