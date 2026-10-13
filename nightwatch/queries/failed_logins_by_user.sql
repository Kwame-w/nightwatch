-- Which accounts are being targeted, and from how many sources?
SELECT
    COALESCE(user, '(blank)')      AS username,
    COUNT(*)                       AS failures,
    COUNT(DISTINCT ip)             AS distinct_ips,
    MIN(ts)                        AS first_attempt,
    MAX(ts)                        AS last_attempt
FROM auth_events
WHERE kind = 'ssh_failed'
GROUP BY user
ORDER BY failures DESC;
