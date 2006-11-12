-- vim: set foldmethod=marker :
-- $Id$

-- This is sqlite3 specific.

CREATE TABLE parse_rules ( --{{{1
    id                      integer NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    name                    text    NOT NULL UNIQUE,
    description             text    NOT NULL,
    -- A regex to parse the line.
    regex                   text    NOT NULL,
    -- The action to take: IGNORE, CONNECT, DISCONNECT . . .
    action                  text    NOT NULL,
    -- The order to apply the rules in: lowest first.
    rule_order              integer NOT NULL
);

CREATE TABLE checks ( --{{{1
    id                      integer NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    name                    text    NOT NULL UNIQUE,
    description             text    NOT NULL,
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
    connection_cols         text    NOT NULL
);

CREATE TABLE connections ( --{{{1
    id                      integer NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    -- The IP address of the connection
    ip                      text    NOT NULL,
    -- The hostname, if known; use NULL if it's not known
    hostname                text,
    -- The name used in the HELO command
    -- TODO: how do I deal with clients who RSET and HELO again?
    helo                    text    NOT NULL,
    -- The MAIL FROM: <address>
    sender                  text    NOT NULL,
    -- Unix timestamp giving the start and end of the connection
    start                   integer NOT NULL,
    end                     integer NOT NULL
);

CREATE TABLE check_results ( --{{{1
    -- Reference to connections->id
    connection_id           integer NOT NULL,
    -- Reference to checks->id
    check_id                integer NOT NULL,
    -- Accept/defer/reject whatever
    result                  text    NOT NULL,
    -- True if it was a warning, false if it took effect
    warning                 integer NOT NULL,
    -- The SMTP code sent to the client
    smtp_code               text    NOT NULL,
    -- The recipient
    recipient               text,
    -- The full line from the log
    log_line                text    NOT NULL,
    -- A place to plop anything not already covered.
    data                    text    NOT NULL,
    PRIMARY KEY (connection_id, check_id)
);
