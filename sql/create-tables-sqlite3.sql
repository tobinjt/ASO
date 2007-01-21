-- vim: set foldmethod=marker :
-- $Id$

-- This is sqlite3 specific.

DROP TABLE IF EXISTS rules; --{{{1

CREATE TABLE rules (
    id                      integer NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    name                    text    NOT NULL UNIQUE,
    description             text    NOT NULL,
    -- The program the rule applies to: smtpd, qmgr, etc.
    program                 text    NOT NULL,
    -- A regex to parse the line.
    regex                   text    NOT NULL,
    -- This is how we extract the matched fields from the regex: 
    -- result_cols and connection_cols specify fields to go in the result and
    -- connection table respectively; the format is:
    -- hostname = 1; helo = 2; sender = 4;
    -- i.e. semi-colon seperated assignment statements, with the column name on
    -- the left and the match from the regex ($1, $2 etc) on the right hand side
    -- (without $).
    result_cols             text    NOT NULL,
    connection_cols         text    NOT NULL,
    -- The action to take: IGNORE, CONNECT, DISCONNECT . . .
    action                  text    NOT NULL,
    -- The regex above should give the queueid; this give the index of the match
    -- e.g. $1, $5, whatever.  smtpd rules won't need this, as restriction_start
    -- handles it for them.
    queueid                 integer NOT NULL,
    -- The order to apply the rules in: lowest first; this is automatically
    -- updates after every run of the program.
    rule_order              integer NOT NULL DEFAULT 0,
    -- This is the user-configurable part of the rule ordering; it supercedes
    -- rule_order, and won't be changed by the program.  Higher goes first.
    priority                integer NOT NULL DEFAULT 0,
    -- Specifies one of IGNORED, INFO, BOUNCED, EXPIRED, SENT, ACCEPTED or
    -- REJECTED, saying what the rule does.
    result                  text    NOT NULL,
    -- additional data to be saved; same format as result_cols, for now.
    result_data             text    NOT NULL DEFAULT '',
    connection_data         text    NOT NULL DEFAULT ''
);

DROP TABLE IF EXISTS connections; --{{{1

CREATE TABLE connections (
    id                      integer NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    -- Sometimes we're the client (we're sending mail), sometimes we're the
    -- server (we're receiving mail).
    -- The IP address of the client
    client_ip               text    NOT NULL,
    -- The hostname of the client
    -- TODO use NULL if it's not known
    client_hostname         text,
    -- The IP address of the server
    server_ip               text    NOT NULL,
    -- The hostname of the server
    server_hostname         text,
    -- The name used in the HELO command
    -- TODO: how do I deal with clients who RSET and HELO again?
    helo                    text    NOT NULL,
    -- The queueid of the mail
    queueid                 text    NOT NULL DEFAULT 'NOQUEUE',
    -- Unix timestamp giving the start and end of the connection
    start                   integer NOT NULL,
    end                     integer NOT NULL
);

DROP TABLE IF EXISTS results; --{{{1

CREATE TABLE results (
    -- Reference to connections->id
    connection_id           integer NOT NULL,
    -- Reference to rules->id
    rule_id                 integer NOT NULL,
    -- Accept/defer/reject whatever
    result                  text    NOT NULL,
    -- True if it was a warning, false if it took effect
    warning                 integer NOT NULL DEFAULT 0,
    -- The SMTP code sent to the client
    smtp_code               text    NOT NULL,
    -- The MAIL FROM: <address>; may be <>, so can be null.
    sender                  text,
    -- The recipient; checks after DATA won't have a recipient, so allow it to
    -- be null.
    recipient               text,
    -- A place to plop anything not already covered.
    data                    text
);
