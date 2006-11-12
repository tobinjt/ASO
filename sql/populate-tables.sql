-- vim: set foldmethod=marker :
-- $Id$

-- CONNECT lines
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('connection', 'A client has connected',
        '^connect from [^\s]+$',
        'CONNECT', 0);

-- DISCONNECT lines
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('disconnection', 'The client has disconnected cleanly',
        '^disconnect from [^\s]+$',
        'DISCONNECT', 1);
-- This will always be followed by a disconnect line, as matched above
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('lost connection', 'Client disconnected uncleanly',
        '^lost connection after \w+ from [^\s]+$',
        'IGNORE', 2);
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('timeout', 'Timeout sending reply',
        '^timeout after (?:\w+|END-OF-MESSAGE) from [^\s]+$',
        'DISCONNECT', 2);
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('Too many errors', 'The client has made so many errors postfix has disconnected it',
        '^too many errors after (?:\w+|END-OF-MESSAGE) from [^\s]+$',
        'DISCONNECT', 2);

-- Lines we want to ignore.
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('Warning', 'Warnings of some sort',
        '^warning: ',
        'IGNORE', 3);
INSERT INTO parse_rules(name, description, regex, action, rule_order)
    VALUES('Table changed', 'A lookup table has changed, smtpd is quitting',
        '^table .* has changed -- restarting$',
        'IGNORE', 0);
-- INSERT INTO parse_rules(name, description, regex, action, rule_order)
--     VALUES('', '',
--         '',
--         '', );
