-- vim: set filetype=sql textwidth=1000 :
-- $Id$

DELETE FROM cluster_groups;

INSERT INTO cluster_groups(id, name, description, cluster_group, restriction_list)
    VALUES(
        1,
        'Client restrictions',
        'Restrictions applied when the client connects.',
        100,
        'smtpd_client_restrictions'
);

INSERT INTO cluster_groups(id, name, description, cluster_group, restriction_list)
    VALUES(
        2,
        'HELO restrictions',
        'Restrictions applied when the client sends the HELO command',
        200,
        'smtpd_helo_restrictions'
);

INSERT INTO cluster_groups(id, name, description, cluster_group, restriction_list)
    VALUES(
        3,
        'Sender restrictions',
        'Restrictions applied when the client sends the MAIL FROM command',
        300,
        'smtpd_sender_restrictions',
);

INSERT INTO cluster_groups(id, name, description, cluster_group, restriction_list)
    VALUES(
        4,
        'Before permit_mynetworks',
        'Restrictions which should affect all clients, including those in mynetworks.',
        400,
        'smtpd_recipient_restrictions'
);

INSERT INTO cluster_groups(id, name, description, cluster_group, restriction_list, required)
    VALUES(
        5,
        'permit_mynetworks, reject_unauth_destination',
        'Permit clients in mynetworks to relay, reject unauthorised relaying attempts.',
        500,
        'smtpd_recipient_restrictions',
        1
);

INSERT INTO cluster_groups(id, name, description, cluster_group, restriction_list)
    VALUES(
        6,
        'After permit_mynetworks',
        'Restrictions which affect clients outside mynetworks.',
        600,
        'smtpd_recipient_restrictions'
);

INSERT INTO cluster_groups(id, name, description, cluster_group, restriction_list)
    VALUES(
        7,
        'Data restrictions',
        'Restrictions which only function properly when applied to the DATA command.',
        700,
        'smtpd_data_restrictions'
);

INSERT INTO cluster_groups(id, name, description, cluster_group, restriction_list)
    VALUES(
        8,
        'End-of-data restrictions',
        'Restrictions applied when the client signals end-of-data.',
        800,
        'smtpd_end_of_data_restrictions'
);

INSERT INTO cluster_groups(id, name, description, cluster_group, restriction_list)
    VALUES(
        9,
        'ETRN restrictions',
        'Restrictions applied to the ETRN command.',
        900,
        'smtpd_etrn_restrictions'
);

INSERT INTO cluster_groups(id, name, description, cluster_group, restriction_list)
    VALUES(
        10,
        'Misc restrictions',
        'Restrictions enforced outside smtpd_mumble_restrictions, e.g. maximum mail size.',
        1000,
        'none'
);
