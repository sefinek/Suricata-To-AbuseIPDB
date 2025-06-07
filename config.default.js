exports.MAIN = {
	/* --------------------------- Server --------------------------- */
	SERVER_ID: null, // Server identifier (e.g., 'hp-terminal', 'pl-cluster', 'de1'). Use 'development' for testing only. 'production' has no effect. Use null to leave it unset.
	EXTENDED_LOGS: false, // Specifies whether the script should display additional information in the logs.
	MIN_ALERT_SEVERITY: 2, // The priority level from which the script should start reporting. Default: <=2
	SURICATA_EVE_FILE: '/var/log/suricata/eve.json',
	CACHE_FILE: './tmp/suricata-abuseipdb-reporter.cache',

	/* --------------------------- Network --------------------------- */
	IP_ASSIGNMENT: 'dynamic', // IP assignment type: 'static' for a fixed IP, 'dynamic' if it may change over time.
	IP_REFRESH_SCHEDULE: '0 */6 * * *', // Cron schedule for checking the public IP assigned by your ISP. Used only with dynamic IPs to prevent accidental self-reporting. If IP_ASSIGNMENT is set to 'static', the script will check your IP only once.
	IPv6_SUPPORT: true, // IPv6 support: true if the device has a globally routable address assigned by the ISP.

	/* --------------------------- Reports --------------------------- */
	ABUSEIPDB_API_KEY: '', // https://www.abuseipdb.com/account/api
	IP_REPORT_COOLDOWN: 4 * 60 * 60 * 1000, // Minimum time between reports of the same IP. Must be >= 15 minutes. Do not set values like 1 hour, as it wouldn't make sense due to rate limits.

	/* --------------------------- Automatic Updates --------------------------- */
	AUTO_UPDATE_ENABLED: false, // True to enable auto-update via 'git pull', false to disable.
	AUTO_UPDATE_SCHEDULE: '0 15,17,18,20 * * *', // Cron schedule for automatic script updates. Default: every day at 15:00, 17:00, 18:00, 20:00

	/* --------------------------- Discord Webhooks --------------------------- */
	DISCORD_WEBHOOK_ENABLED: false, // Enables sending Discord webhooks with error reports, execution status, and other events.
	DISCORD_WEBHOOK_URL: '',
	DISCORD_WEBHOOK_USERNAME: 'SERVER_ID', // Username shown as the message author. Use null for default. 'SERVER_ID' will resolve to this.MAIN.SERVER_ID.
};

// const serverId = this.MAIN.SERVER_ID ? `on ${this.MAIN.SERVER_ID} ` : '';
exports.REPORT_COMMENT = ({ srcIp, dpt, proto, id, severity, signature, timestamp }, fullLog) =>
	`Suricata (signature ${id}, severity: ${severity}): ${signature || 'Unknown Signature'}]`;