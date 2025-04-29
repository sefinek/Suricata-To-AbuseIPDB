exports.MAIN = {
	// Server
	SURICATA_EVE_FILE: '/var/log/suricata/eve.json',
	CACHE_FILE: './tmp/suricata-abuseipdb-reporter.cache',
	SERVER_ID: null, // The server name that will be visible in reports (e.g., homeserver1, de1). Leave as null if you don't want to define it.
	EXTENDED_LOGS: false, // Specifies whether the script should display additional information in the logs.
	MIN_ALERT_SEVERITY: 2, // The priority level from which the script should start reporting. Default: 2

	// Network
	IP_REFRESH_SCHEDULE: '0 */6 * * *', // CRON: How often the script should check the IP address assigned by the ISP to prevent accidental self-reporting. If you have a static IP, you can set it to '0 0 1 * *' (once a month). Default: every 6 hours
	IPv6_SUPPORT: true, // Specifies whether the device has an assigned IPv6 address.

	// Reporting
	ABUSEIPDB_API_KEY: '', // Secret API key for AbuseIPDB.
	IP_REPORT_COOLDOWN: 12 * 60 * 60 * 1000, // Minimum time (12 hours in this example) that must pass before the same IP address can be reported again. Do not set values like 1 hour, as it wouldn't make sense due to rate limits.

	// Automatic Updates
	AUTO_UPDATE_ENABLED: false, // Should the script automatically update to the latest version using 'git pull'? If enabled, monitor the script periodically — incompatibilities may occasionally occur with the config file.
	AUTO_UPDATE_SCHEDULE: '0 18 * * *', // CRON: Schedule for automatic script updates. Default: every day at 18:00

	// Discord Webhooks | !! NOT RECOMMENDED !!
	DISCORD_WEBHOOKS_ENABLED: false, // Should the script send webhooks? These will include error reports, daily summaries, and other related information.
	DISCORD_WEBHOOKS_URL: '',
	DISCORD_WEBHOOK_USERNAME: 'SERVER_ID', // The name displayed as the message author on Discord. If you don't want to set it, leave the value as null. Providing SERVER_ID as a string will display this.MAIN.SERVER_ID.
};

// const serverId = this.MAIN.SERVER_ID ? `on ${this.MAIN.SERVER_ID} ` : '';
exports.REPORT_COMMENT = ({ srcIp, dpt, proto, id, severity, signature, timestamp }, fullLog) =>
	`Suricata (signature ${id}, severity: ${severity}): ${signature || 'Unknown Signature'}]`;