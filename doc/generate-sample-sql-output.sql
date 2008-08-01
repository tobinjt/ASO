SELECT restriction_name, hits_total,
        (hits_total * 100.0 / 
            (SELECT SUM(hits_total)
                FROM rules
                WHERE postfix_action = 'REJECTED'
            )
        ) || '%' AS percentage
    FROM rules
    WHERE postfix_action = 'REJECTED'
    ORDER BY hits_total DESC
    LIMIT 10;
