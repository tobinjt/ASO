-- vim: set foldmethod=marker textwidth=300 :
-- $Id$

DELETE FROM parse_rules;

-- CONNECT lines
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('connection', 'A client has connected',
        '^connect from __HOSTNAME__\[__IP__\]$',
        'CONNECT', 0);

-- DISCONNECT lines
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('disconnection', 'The client has disconnected cleanly',
        '^disconnect from __HOSTNAME__\[__IP__\]$',
        'DISCONNECT', 1);

-- These will always be followed by a disconnect line, as matched above
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('lost connection', 'Client disconnected uncleanly',
        '^lost connection after \w+ from __HOSTNAME__\[__IP__\]$',
        'IGNORE', 2);
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('timeout', 'Timeout sending reply',
        '^timeout after (?:\w+|END-OF-MESSAGE) from __HOSTNAME__\[__IP__\]$',
        'IGNORE', 2);
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('Too many errors', 'The client has made so many errors postfix has disconnected it',
        '^too many errors after (?:\w+|END-OF-MESSAGE) from __HOSTNAME__\[__IP__\]$',
        'IGNORE', 2);

-- Lines we want to ignore.
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('Warning', 'Warnings of some sort',
        '^warning: ',
        'IGNORE', 3);
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('Table changed', 'A lookup table has changed, smtpd is quitting',
        '^table .* has changed -- restarting$',
        'IGNORE', 3);
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('Client hostname and IP logged', 'Postfix logging the client IP address and hostname, probably because of XFORWARD',
        '^[\dA-F]+: client=__HOSTNAME__\[__IP__\]$',
        'IGNORE', 3);
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('Bloody Solaris LDAP', 'Solaris LDAP is trying to load something or other',
        '^libsldap: Status: 2  Mesg: Unable to load configuration ./var/ldap/ldap_client_file. \(..\).$',
        'IGNORE', 3);
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('Bloody Solaris LDAP 2', 'Solaris LDAP cannot connect or something',
        '^libsldap: Status: 7  Mesg: Session error no available conn.$',
        'IGNORE', 3);
-- INSERT INTO parse_rules(name, description, regex, action, rule_order)
--     VALUES('', '',
--         '',
--         '', );
