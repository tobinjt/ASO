-- vim: set foldmethod=marker textwidth=300 :

-- result_cols: recipient, data (log_line will be added automatically)
-- connection_cols: helo, sender
-- XXX: how will I specify warning?
-- XXX: Add a restriction catching this?
-- <203.162.3.152>: Helo command rejected: need fully-qualified hostname; from=<grid-ireland-ca@cs.tcd.ie> to=<grid-ireland-ca@cs.tcd.ie> proto=ESMTP helo=<203.162.3.152>

DELETE FROM checks;

-- <munin@cs.tcd.ie>: Recipient address rejected: User unknown in local recipient table; from=<> to=<munin@cs.tcd.ie> proto=ESMTP helo=<lg12x22.cs.tcd.ie>
-- <hienes@cs.tcd.ie>: Recipient address rejected: User unknown in local recipient table; from=<BrooksPool@rowcmi.org> to=<hienes@cs.tcd.ie> proto=ESMTP helo=<PETTERH?DNEB?>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Unknown recipient', 'The recipient address is unknown on our system',
        '^<(__RECIPIENT__)>: Recipient address rejected: User unknown in local recipient table; from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 1, sender = 2',
        'helo = 3'
);

-- <munin@cs.tcd.ie>: Sender address rejected: User unknown in local recipient table; from=<munin@cs.tcd.ie> to=<john.tobin@cs.tcd.ie> proto=ESMTP helo=<lg12x36.cs.tcd.ie>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Unknown sender', 'The sender address is unknown on our system',
        '^<(__SENDER__)>: Sender address rejected: User unknown in local recipient table; from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3'
);

-- <ocalladw@toad.toad>: Sender address rejected: Domain not found; from=<ocalladw@toad.toad> to=<submit@bugs.gnome.org> proto=SMTP helo=<toad>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Unknown sender domain', 'We do not accept mail from unknown domains',
        '^<(__SENDER__)>: Sender address rejected: Domain not found; from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3'
);

-- <stephen@tjbx.org>: Recipient address rejected: Domain not found; from=<4sdcsaz@nbsanjiang.com> to=<stephen@tjbx.org> proto=ESMTP helo=<nbsanjiang.com>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Unknown recipient domain', 'We do not accept mail for unknown domains',
        '^<(__RECIPIENT__)>: Recipient address rejected: Domain not found; from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3'
);

-- Service unavailable; Client host [190.40.116.202] blocked using sbl-xbl.spamhaus.org; from=<taliaferraearl@blackburn-green.com> to=<amjudge@dsg.cs.tcd.ie> proto=SMTP helo=<blackburn-green.com>
-- Service unavailable; Client host [211.212.156.4] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/query/bl?ip=211.212.156.4; from=<lucia@abouttimemag.com> to=<amjudge@dsg.cs.tcd.ie> proto=SMTP helo=<abouttimemag.com>
-- Service unavailable; Client host [66.30.84.174] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/query/bl?ip=66.30.84.174; from=<DianaBoykin@movemail.com> to=<Paolo.Rosso@cs.tcd.ie> proto=SMTP helo=<b100mng10bce9ob.hsd1.ma.comcast.net.>
-- Service unavailable; Client host [210.236.32.153] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/SBL/sbl.lasso?query=SBL47877; from=<euyery@linuxmail.org> to=<vinny.cahill@cs.tcd.ie> proto=SMTP helo=<eworuetyberiyneortmweprmuete57197179680.com>
-- Service unavailable; Client host [204.14.1.123] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/SBL/sbl.lasso?query=SBL27197 / http://www.spamhaus.org/SBL/sbl.lasso?query=SBL47903; from=<tia@baraskaka.com> to=<vjcahill@dsg.cs.tcd.ie> proto=SMTP helo=<customer.optindirectmail.123.sls-hosting.com>
-- Service unavailable; Client host [82.119.202.142] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/query/bl?ip=82.119.202.142; from=<001topzine-hypertext@123point.net> to=<ecdlf@cs.tcd.ie.> proto=ESMTP helo=<cs.tcd.ie.>

INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Blacklisted by SpamHaus SBL-XBL', 'The client IP address is blacklisted by SpamHaus SBL-XBL',
        '^Service unavailable; Client host (?>\[(__IP__)\]) blocked using sbl-xbl.spamhaus.org;(?:((?:(?:(?: http://www.spamhaus.org/SBL/sbl.lasso\?query=\w+)|(?: http://www.spamhaus.org/query/bl\?ip=\1))(?: /)?)*);)? (?>from=<(__SENDER__)>) to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 4, data = 2, sender = 3',
        'helo = 5'
);

-- Service unavailable; Client host [80.236.27.105] blocked using list.dsbl.org; http://dsbl.org/listing?80.236.27.105; from=<mrnpftjx@pacbell.net> to=<tom.irwin@cs.tcd.ie> proto=SMTP helo=<ip-105.net-80-236-27.asnieres.rev.numericable.fr>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Blacklisted by DSBL', 'The client IP address is blacklisted by DSBL',
        '^Service unavailable; Client host (?>\[(__IP__)\]) blocked using list.dsbl.org; (?>(http://dsbl.org/listing\?\1);) from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 4, data = 2, sender = 3',
        'helo = 5'
);

-- Service unavailable; Client host [148.243.214.52] blocked using relays.ordb.org; This mail was handled by an open relay - please visit <http://ORDB.org/lookup/?host=148.243.214.52>; from=<cw-chai@umail.hinet.net> to=<webmaster@cs.tcd.ie> proto=ESMTP helo=<sicomnet.edu.mx>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Blacklisted by ordb.org', 'The client IP address is blacklisted by ordb.org',
        '^Service unavailable; Client host (?>\[(__IP__)\]) blocked using relays.ordb.org; (?>(This mail was handled by an open relay - please visit <http://ORDB.org/lookup/\?host=\1>);) from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 4, data = 2, sender = 3',
        'helo = 5'
);

-- Service unavailable; Client host [60.22.99.9] blocked using cbl.abuseat.org; Blocked - see http://cbl.abuseat.org/lookup.cgi?ip=60.22.99.9; from=<pegbxbsusiiao@cowboyart.net> to=<daokeeff@cs.tcd.ie> proto=SMTP helo=<cowboyart.net>
-- Service unavailable; Client host [90.194.116.50] blocked using cbl.abuseat.org; from=<lazauear@appleleasing.com> to=<noctor@cs.tcd.ie> proto=SMTP helo=<appleleasing.com>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Blacklisted by CBL', 'The client IP address is blacklisted by CBL',
        '^Service unavailable; Client host (?>\[(__IP__)\]) blocked using cbl.abuseat.org;(?>( Blocked - see http://cbl.abuseat.org/lookup.cgi\?ip=\1);)? from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 4, data = 2, sender = 3',
        'helo = 5'
);

-- <31.pool80-103-5.dynamic.uni2.es[80.103.5.31]>: Client host rejected: Greylisted, see http://isg.ee.ethz.ch/tools/postgrey/help/dsg.cs.tcd.ie.html; from=<iqxrgomtl@purinmail.com> to=<skenny@dsg.cs.tcd.ie> proto=SMTP helo=<31.pool80-103-5.dynamic.uni2.es>
-- <mail.saraholding.com.sa[212.12.166.254]>: Client host rejected: Greylisted, see http://isg.ee.ethz.ch/tools/postgrey/help/cs.tcd.ie.html; from=<lpty@[212.12.166.226]> to=<colin.little@cs.tcd.ie> proto=ESMTP helo=<mail.saraholding.com.sa>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Greylisted', 'Client greylisted; see http://www.greylisting.org/ for more details',
        '^<__HOSTNAME__\[__IP__\]>: Client host rejected: Greylisted, see (http://isg.ee.ethz.ch/tools/postgrey/help/[^\s]+); from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 3, data = 1, sender = 2',
        'helo = 4'
);

-- <nicholas@seaton.biz>: Sender address rejected: Address uses MX in loopback address space (127.0.0.0/8); from=<nicholas@seaton.biz> to=<gillian.long@cs.tcd.ie> proto=ESMTP helo=<friend>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Sender MX in loopback address space', 'The MX for sender domain is in loopback address space, so cannot be contacted',
        '^<(__SENDER__)>: Sender address rejected: Address uses MX in loopback address space \(127.0.0.0/8\); from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3'
);

-- <aaholi@web009.ahp01.lax.affinity.com>: Sender address rejected: Address uses MX in private address space (127.16.0.0/12); from=<aaholi@web009.ahp01.lax.affinity.com> to=<luzs@cs.tcd.ie> proto=ESMTP helo=<ams006.lax.affinity.com> 
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Sender MX in private address space (127.16.0.0/12)', 'The MX for sender domain is in private address space (127.16.0.0/12), so cannot be contacted',
        '^<(__SENDER__)>: Sender address rejected: Address uses MX in private address space \(127.16.0.0/12\); from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3'
);

-- <hlhbs@china.org.cn>: Recipient address rejected: Address uses MX in private address space (127.16.0.0/12); from=<1221q5@chinachewang.com> to=<hlhbs@china.org.cn> proto=ESMTP helo=<chinachewang.com>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Recipient MX in private address space (127.16.0.0/12)', 'The MX for recipient domain is in private address space (127.16.0.0/12), so cannot be contacted',
        '^<(__RECIPIENT__)>: Recipient address rejected: Address uses MX in private address space \(127.16.0.0/12\); from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 1, sender = 2',
        'helo = 3'
);

-- <aeneasdecathlon@rotnot.com>: Sender address rejected: Address uses MX in private address space (192.168.0.0/16); from=<aeneasdecathlon@rotnot.com> to=<MCCARTHY@CS.tcd.ie> proto=ESMTP helo=<vms1.tcd.ie>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Sender MX in private address space (192.168.0.0/16)', 'The MX for sender domain is in private address space (192.168.0.0/16), so cannot be contacted',
        '^<(__SENDER__)>: Sender address rejected: Address uses MX in private address space \(192.168.0.0/16\); from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3'
);

-- <showh@tdt3.com.tw>: Recipient address rejected: Address uses MX in private address space (192.168.0.0/16); from=<zsl.gzrza@yahoo.com.tw> to=<showh@tdt3.com.tw> proto=SMTP helo=<134.226.32.56>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Recipient MX in private address space (192.168.0.0/16)', 'The MX for Recipient domain is in private address space (192.168.0.0/16), so cannot be contacted',
        '<(__RECIPIENT__)>: Recipient address rejected: Address uses MX in private address space \(192.168.0.0/16\); from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>',
        'recipient = 1, sender = 2',
        'helo = 3'
);

-- <acornascription@rot.wartesaal.darktech.org>: Sender address rejected: Address uses MX in private address space (10.0.0.0/8); from=<acornascription@rot.wartesaal.darktech.org> to=<gap@cs.tcd.ie> proto=ESMTP helo=<xmx1.tcd.ie>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Sender MX in private address space (10.0.0.0/8)', 'The MX for sender domain is in private address space (10.0.0.0/8), so cannot be contacted',
        '^<(__SENDER__)>: Sender address rejected: Address uses MX in private address space \(10.0.0.0/8\); from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3'
);

-- <mactusqdx@wartesaal.darktech.org>: Recipient address rejected: Address uses MX in private address space (10.0.0.0/8); from=<bartel@integramed.com> to=<mactusqdx@wartesaal.darktech.org> proto=SMTP helo=<integramed.com>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Recipient MX in private address space (10.0.0.0/8)', 'The MX for recipient domain is in private address space (10.0.0.0/8), so cannot be contacted',
        '^<(__RECIPIENT__)>: Recipient address rejected: Address uses MX in private address space \(10.0.0.0/8\); from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 1, sender = 2',
        'helo = 3'
);

-- <banihashemian@modares.ac.ir>: Sender address rejected: Address uses MX in local address space (169.254.0.0/16); from=<banihashemian@modares.ac.ir> to=<Elisa.Baniassad@cs.tcd.ie> proto=ESMTP helo=<mail-relay1.cs.ubc.ca>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Sender MX in "local" address space (169.254.0.0/16)', 'The MX for sender domain is in "local" address space (169.254.0.0/16), so cannot be contacted',
        '^<(__SENDER__)>: Sender address rejected: Address uses MX in local address space \(169.254.0.0/16\); from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3'
);

-- <lisa@telephonebooth.com>: Sender address rejected: Address uses MX in "this" address space (0.0.0.0/8); from=<lisa@telephonebooth.com> to=<francis.neelamkavil@cs.tcd.ie> proto=SMTP helo=<localhost>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Sender MX in "this" address space (0.0.0.0/8)', 'The MX for sender domain is in "this" address space (0.0.0.0/8), so cannot be contacted',
        '^<(__SENDER__)>: Sender address rejected: Address uses MX in "this" address space \(0.0.0.0/8\); from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3'
);

-- <af53eec9@verpiss-dich.de>: Recipient address rejected: Address uses MX in loopback address space (127.0.0.0/8); from=<cbsrlkhaigye@allsaintsfan.com> to=<af53eec9@verpiss-dich.de> proto=SMTP helo=<127.0.0.1>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Recipient MX in loopback address space (127.0.0.0/8)', 'The MX for recipient domain is in loopback address space (127.0.0.0/8), so cannot be contacted',
        '^<(__RECIPIENT__)>: Recipient address rejected: Address uses MX in loopback address space \(127.0.0.0/8\); from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 1, sender = 2',
        'helo = 3'
);

-- <ForestSimmspq@rpis.pl>: Sender address rejected: Address uses MX in reserved address space (240.0.0.0/4); from=<ForestSimmspq@rpis.pl> to=<dave.lewis@cs.tcd.ie> proto=ESMTP helo=<xmx1.tcd.ie>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Sender MX in reserved address space (240.0.0.0/4)', 'The MX for sender domain is in reserved address space (240.0.0.0/4), so cannot be contacted',
        '^<(__SENDER__)>: Sender address rejected: Address uses MX in reserved address space \(240.0.0.0/4\); from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3'
);

-- <cs.tcd.ie>: Helo command rejected: You are not in cs.tcd.ie; from=<van9219@yahoo.co.jp> to=<david.ocallaghan@cs.tcd.ie> proto=SMTP helo=<cs.tcd.ie>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Faked CS HELO', 'The client used a CS address in HELO but is not within our network',
        '^<(__HELO__)>: Helo command rejected: You are not in cs.tcd.ie; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\1>$',
        'recipient = 3, sender = 2',
        'helo = 1'
);

-- <a-tikx23d9jlacr>: Helo command rejected: need fully-qualified hostname; from=<aprenda06@walla.com> to=<michael.brady@cs.tcd.ie> proto=SMTP helo=<a-tikx23d9jlacr>
-- <203.162.3.152>: Helo command rejected: need fully-qualified hostname; from=<grid-ireland-ca@cs.tcd.ie> to=<grid-ireland-ca@cs.tcd.ie> proto=ESMTP helo=<203.162.3.152>
-- <qbic>: Helo command rejected: need fully-qualified hostname; from=<> to=<faircloc@cs.tcd.ie> proto=ESMTP helo=<qbic>
-- XXX: How do I match fscked up adresses like louis@contact@barclayimmo.dyndns.org ??
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Non-FQDN HELO', 'The hostname given in the HELO command is not fully qualified, i.e. it lacks a domain',
        '^(?><(.*?)>:) Helo command rejected: need fully-qualified hostname; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\1>$',
        'recipient = 3, sender = 2',
        'helo = 1'
);

-- <among@ecosse.net>: Relay access denied; from=<uvqjnkhcwanbvk@walla.com> to=<among@ecosse.net> proto=SMTP helo=<88-134-149-72-dynip.superkabel.de>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Relaying denied', 'Client tried to use us as an open relay',
        '^<(__RECIPIENT__)>: Relay access denied; from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 1, sender = 2',
        'helo = 3'
);

-- Client host rejected: cannot find your hostname, [190.40.183.65]; from=<dage@0451.com> to=<ebarrett@cs.tcd.ie> proto=ESMTP helo=<client-200.121.175.96.speedy.net.pe>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Unknown hostname', 'No PTR record for client IP address',
        '^Client host rejected: cannot find your hostname, \[__IP__\]; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3'
);

-- <[]>: Helo command rejected: invalid ip address; from=<mrmmpwv@parfive.com> to=<hitesh.tewari@cs.tcd.ie> proto=ESMTP helo=<[]>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Invalid HELO ip address', 'The hostname used in the HELO command is invalid',
        '<(.*?)>: Helo command rejected: invalid ip address; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\1>',
        'recipient = 3, sender = 2',
        'helo = 1'
);

-- <24383590>: Helo command rejected: Invalid name; from=<CBKWPMIUF@hotmail.com> to=<byrne@cs.tcd.ie> proto=SMTP helo=<24383590>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Invalid HELO hostname', 'The client used an invalid hostname in the HELO command',
        '^<(.*?)>: Helo command rejected: Invalid name; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\1>$',
        'recipient = 3, sender = 2',
        'helo = 1'
);

-- <daemon@cs.tcd.ie>: Recipient address rejected: recipient address unknown; from=<> to=<daemon@cs.tcd.ie> proto=ESMTP helo=<lg12x21.cs.tcd.ie>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Unknown recipient (system user)', 'The recipient address is unknown on our system (system users should not receive mail)',
        '^<(__RECIPIENT__)>: Recipient address rejected: recipient address unknown; from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 1, sender = 2',
        'helo = 3'
);

-- <daemon@cs.tcd.ie>: Sender address rejected: sender address unknown; from=<daemon@cs.tcd.ie> to=<root@cs.tcd.ie> proto=ESMTP helo=<apex.cs.tcd.ie>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Unknown sender (system user)', 'The sender address is unknown on our system (system users should not send mail)',
        '^<(__SENDER__)>: Sender address rejected: sender address unknown; from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3'
);

-- <neville.harris@cs.tcd.ie>: Recipient address rejected: User no longer receiving mail at this address; from=<have@jewelprecision.com> to=<neville.harris@cs.tcd.ie> proto=SMTP helo=<jewelprecision.com>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Unknown recipient (user not receiving mail)', 'The recipient address is unknown on our system (user not receiving mail here any more)',
        '^<(__RECIPIENT__)>: Recipient address rejected: User no longer receiving mail at this address; from=<(__SENDER__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 1, sender = 2',
        'helo = 3'
);

-- <godiva.cs.tcd.ie[134.226.35.142]>: Client host rejected: Alias root to something useful.; from=<root@godiva.cs.tcd.ie> to=<root@godiva.cs.tcd.ie> proto=SMTP helo=<godiva.cs.tcd.ie>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Unwanted mail to root', 'People keep sending us mail for root at their machine',
        '^<__HOSTNAME__(?>\[__IP__\]>:) Client host rejected: Alias root to something useful.; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>',
        'recipient = 2, sender = 1',
        'helo = 3'
);

-- <root@pc910.cs.tcd.ie>: Recipient address rejected: alias root to some other user, damnit.; from=<root@pc910.cs.tcd.ie> to=<root@pc910.cs.tcd.ie> proto=ESMTP helo=<vangogh.cs.tcd.ie>
-- <root@pc910.cs.tcd.ie>: Recipient address rejected: alias root to some other user, damnit.; from=<> to=<root@pc910.cs.tcd.ie> proto=ESMTP helo=<vangogh.cs.tcd.ie>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Unwanted mail to root 2', 'People keep sending us mail for root at their machine (2)',
        '^<(__SENDER__)>: Recipient address rejected: alias root to some other user, damnit.; from=<(__RECIPIENT__)> to=<\1> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 1, sender = 2',
        'helo = 3'
);

-- Client host rejected: cannot find your hostname, [199.84.53.138]; from=<security@e-gold.com.> to=<melanie.bouroche@cs.tcd.ie> proto=ESMTP helo=<DynamicCorp.net>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Rejected client without PTR', 'Client IP address does not have associated PTR record',
        '^Client host rejected: cannot find your hostname, \[__IP__\]; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3'
);

-- <localhost.localhost>: Helo command rejected: You are not me; from=<qute1212000@yahoo.it> to=<mads.haahr@cs.tcd.ie> proto=SMTP helo=<localhost.localhost>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Fake localhost HELO', 'The client claimed to be localhost in the HELO command',
        '^<(__HELO__)>: Helo command rejected: You are not me; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<\1>$',
        'recipient = 3, sender = 2',
        'helo = 1'
);

-- <apache>: Sender address rejected: need fully-qualified address; from=<apache> to=<Arthur.Hughes@cs.tcd.ie> proto=ESMTP helo=<najm.tendaweb.com>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Non-FQDN sender', 'Sender addresses must be in FQDN form, so replies can be sent',
        '^<(__SENDER__)>: Sender address rejected: need fully-qualified address; from=<\1> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$',
        'recipient = 2, sender = 1',
        'helo = 3'
);

-- <DATA>: Data command rejected: Multi-recipient bounce; from=<> proto=SMTP helo=<mail71.messagelabs.com>
INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Multi-recipient bounce rejected', 'Any mail from <> should be a bounce, therefore if there is more than one recipient it can be rejected',
        '^<DATA>: Data command rejected: Multi-recipient bounce; from=<()> proto=SMTP helo=<(__HELO__)>$',
        'sender = 1',
        'helo = 2'
);

INSERT INTO checks(name, description, regex, result_cols, connection_cols)
    VALUES('Mail accepted', 'Postfix accepted the mail; it is hardly obvious though',
        '^(__QUEUEID__): client=(__HOSTNAME__)\[(__IP__)\]$',
        '',
        'queueid = 1, hostname = 2, ip = 3'
);
