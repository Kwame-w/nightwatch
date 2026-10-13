-- Possible compromise: successful SSH logins ranked by failures from the same IP in the hour before.
-- Uses a CTE and a correlated subquery.
WITH logins AS (
    SELECT id, ts, user, ip, method
    FROM auth_events
    WHERE kind = 'ssh_accepted'
)
SELECT
    l.ts, l.user, l.ip, l.method,
    (SELECT COUNT(*)
       FROM auth_events f
      WHERE f.kind = 'ssh_failed'
        AND f.ip = l.ip
        AND f.ts <  l.ts
        AND f.ts >= strftime('%Y-%m-%dT%H:%M:%S', l.ts, '-1 hour')) AS failures_last_hour
FROM logins l
ORDER BY failures_last_hour DESC, l.ts;
