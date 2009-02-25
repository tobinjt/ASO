SELECT restriction_name, hits_total,
        (hits_total * 100.0 / 
            (SELECT SUM(hits_total)
                FROM rules
                WHERE action = 'DELIVERY_REJECTED'
            )
        ) || '%' AS percentage
    FROM rules
    WHERE action = 'DELIVERY_REJECTED'
    ORDER BY hits_total DESC
    LIMIT 10;
