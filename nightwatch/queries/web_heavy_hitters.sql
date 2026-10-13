-- Busiest web clients ranked with a window function, with their error rate.
SELECT
    RANK() OVER (ORDER BY COUNT(*) DESC)               AS rank,
    ip,
    COUNT(*)                                           AS requests,
    ROUND(100.0 * SUM(status >= 400) / COUNT(*), 1)    AS error_pct,
    COUNT(DISTINCT path)                               AS distinct_paths,
    MAX(user_agent)                                    AS sample_user_agent
FROM web_events
GROUP BY ip
HAVING COUNT(*) >= 5
ORDER BY rank
LIMIT 10;
