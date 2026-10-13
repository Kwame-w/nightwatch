-- MITRE ATT&CK coverage of this dataset: which techniques fired, how often, from how many IPs.
SELECT mitre_id, mitre_name, COUNT(*) AS alerts, COUNT(DISTINCT ip) AS source_ips, SUM(count) AS events
FROM alerts
GROUP BY mitre_id, mitre_name
ORDER BY alerts DESC, mitre_id;
