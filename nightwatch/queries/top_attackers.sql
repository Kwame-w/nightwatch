-- Top attacking IPs: alert count, worst severity and every technique seen, across all log types.
SELECT
    ip,
    COUNT(*)                                  AS alerts,
    MAX(severity_n)                           AS worst,
    CASE MAX(severity_n) WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END AS worst_severity,
    GROUP_CONCAT(DISTINCT mitre_id)           AS techniques
FROM alerts
WHERE ip IS NOT NULL
GROUP BY ip
ORDER BY worst DESC, alerts DESC
LIMIT 10;
