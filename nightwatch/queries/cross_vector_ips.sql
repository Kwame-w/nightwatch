-- IPs that attacked BOTH SSH and the website: a stronger signal than either alone.
-- JOINs per-source aggregates on the shared IP.
WITH ssh AS (
    SELECT ip, COUNT(*) AS ssh_failures
    FROM auth_events
    WHERE kind IN ('ssh_failed', 'ssh_invalid_user') AND ip IS NOT NULL
    GROUP BY ip
),
web AS (
    SELECT ip, COUNT(*) AS requests, SUM(status = 404) AS not_found, SUM(status >= 500) AS server_errors
    FROM web_events
    GROUP BY ip
)
SELECT ssh.ip, ssh.ssh_failures, web.requests, web.not_found, web.server_errors
FROM ssh
JOIN web ON web.ip = ssh.ip
ORDER BY ssh.ssh_failures + web.not_found DESC;
