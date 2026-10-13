-- Activity per hour across both sources, to spot when an attack started.
WITH events AS (
    SELECT substr(ts, 1, 13) AS hour, 'auth_fail' AS type FROM auth_events WHERE kind IN ('ssh_failed', 'ssh_invalid_user')
    UNION ALL
    SELECT substr(ts, 1, 13), CASE WHEN status >= 400 THEN 'web_error' ELSE 'web_ok' END FROM web_events
)
SELECT
    hour || ':00'                     AS hour,
    SUM(type = 'auth_fail')           AS auth_failures,
    SUM(type = 'web_ok')              AS web_ok,
    SUM(type = 'web_error')           AS web_errors
FROM events
GROUP BY hour
ORDER BY hour;
