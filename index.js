//   Copyright 2024-2025 (c) by Sefinek All rights reserved.
//                     https://sefinek.net

const fs = require('node:fs');
const TailFile = require('@logdna/tail-file');
const split2 = require('split2');
// const chokidar = require('chokidar');
const { parseTimestamp } = require('ufw-log-parser');
const axios = require('./scripts/services/axios.js');
const { saveBufferToFile, loadBufferFromFile, sendBulkReport, BULK_REPORT_BUFFER } = require('./scripts/services/bulk.js');
const { reportedIPs, loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported } = require('./scripts/services/cache.js');
const { refreshServerIPs, getServerIPs } = require('./scripts/services/ipFetcher.js');
const { name, version, authorEmailWebsite, repoFullUrl } = require('./scripts/repo.js');
const sendWebhook = require('./scripts/services/discordWebhooks.js');
const isLocalIP = require('./scripts/isLocalIP.js');
const log = require('./scripts/log.js');
const config = require('./config.js');
const { SURICATA_EVE_FILE, ABUSEIPDB_API_KEY, SERVER_ID, EXTENDED_LOGS, MIN_ALERT_SEVERITY, AUTO_UPDATE_ENABLED, AUTO_UPDATE_SCHEDULE, DISCORD_WEBHOOKS_ENABLED, DISCORD_WEBHOOKS_URL } = config.MAIN;

const ABUSE_STATE = { isLimited: false, isBuffering: false, sentBulk: false };
const RATE_LIMIT_LOG_INTERVAL = 10 * 60 * 1000;
const BUFFER_STATS_INTERVAL = 5 * 60 * 1000;

const nextRateLimitReset = () => {
	const now = new Date();
	return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 1));
};

let LAST_RATELIMIT_LOG = 0, LAST_STATS_LOG = 0, RATELIMIT_RESET = nextRateLimitReset();

const checkRateLimit = async () => {
	const now = Date.now();
	if (now - LAST_STATS_LOG >= BUFFER_STATS_INTERVAL && BULK_REPORT_BUFFER.size > 0) LAST_STATS_LOG = now;

	if (ABUSE_STATE.isLimited) {
		if (now >= RATELIMIT_RESET.getTime()) {
			ABUSE_STATE.isLimited = false;
			ABUSE_STATE.isBuffering = false;
			if (!ABUSE_STATE.sentBulk && BULK_REPORT_BUFFER.size > 0) await sendBulkReport();
			RATELIMIT_RESET = nextRateLimitReset();
			ABUSE_STATE.sentBulk = false;
			log(`Rate limit reset. Next reset scheduled at ${RATELIMIT_RESET.toISOString()}`, 1);
		} else if (now - LAST_RATELIMIT_LOG >= RATE_LIMIT_LOG_INTERVAL) {
			const minutesLeft = Math.ceil((RATELIMIT_RESET.getTime() - now) / 60000);
			log(`Rate limit is still active. Collected ${BULK_REPORT_BUFFER.size} IPs. Waiting for reset in ${minutesLeft} minute(s) (${RATELIMIT_RESET.toISOString()})`, 1);
			LAST_RATELIMIT_LOG = now;
		}
	}
};

const reportIp = async ({ srcIp, dpt = 'N/A', proto = 'N/A', id, timestamp }, categories = '14', comment) => {
	if (!srcIp) return log('Missing source IP (srcIp)', 3);

	await checkRateLimit();

	if (ABUSE_STATE.isBuffering) {
		if (BULK_REPORT_BUFFER.has(srcIp)) return;
		BULK_REPORT_BUFFER.set(srcIp, { categories, timestamp, comment });
		await saveBufferToFile();
		log(`Queued ${srcIp} for bulk report (collected ${BULK_REPORT_BUFFER.size} IPs)`, 1);
		return;
	}

	try {
		const { data: res } = await axios.post('/report', new URLSearchParams({
			ip: srcIp,
			categories,
			comment,
		}), { headers: { 'Key': ABUSEIPDB_API_KEY } });

		log(`Reported ${srcIp} [${dpt}/${proto}]; ID: ${id}; Categories: ${categories}; Abuse: ${res.data.abuseConfidenceScore}%`, 1);
		return true;
	} catch (err) {
		const status = err.response?.status ?? 'unknown';
		if (status === 429 && JSON.stringify(err.response?.data || {}).includes('Daily rate limit')) {
			if (!ABUSE_STATE.isLimited) {
				ABUSE_STATE.isLimited = true;
				ABUSE_STATE.isBuffering = true;
				ABUSE_STATE.sentBulk = false;
				LAST_RATELIMIT_LOG = Date.now();
				RATELIMIT_RESET = nextRateLimitReset();
				log(`Daily AbuseIPDB limit reached. Buffering reports until ${RATELIMIT_RESET.toISOString()}`, 0, true);
			}

			if (BULK_REPORT_BUFFER.has(srcIp)) {
				log(`${srcIp} is already in buffer, skipping`);
				return;
			}

			BULK_REPORT_BUFFER.set(srcIp, { timestamp, categories, comment });
			await saveBufferToFile();
			log(`Queued ${srcIp} for bulk report due to rate limit`);
		} else {
			log(`Failed to report ${srcIp} [${dpt}/${proto}]; ${err.response?.data?.errors ? JSON.stringify(err.response.data.errors) : err.message}`, status === 429 ? 0 : 3);
		}
	}
};

const processLogLine = async (line, test = false) => {
	if (!line.includes('"event_type":"alert"') && (line.startsWith('{') && line.endsWith('}'))) return;

	let json;
	try {
		json = JSON.parse(line);
	} catch (err) {
		log(`Invalid JSON: ${err.message}:`, 3);
		return log(`Line: ${line}:`, 3);
	}

	const srcIp = json.src_ip;
	if (!srcIp) return log(`Missing SRC in the alert: ${line}`, 3);

	const ips = getServerIPs();
	if (!Array.isArray(ips)) return log(`For some reason, 'ips' from 'getServerIPs()' is not an array. Received: ${ips}`, 3, true);

	const destIp = json.dest_ip;
	let ipToReport = srcIp;
	if (ips.includes(srcIp) || isLocalIP(srcIp)) {
		if (ips.includes(destIp) || isLocalIP(destIp)) return log(`Both SRC=${srcIp} and DEST=${destIp} are local or own, ignoring alert`, 0, true);
		ipToReport = destIp;
	}

	const severity = json.alert.severity;
	const signature = json.alert?.signature || 'N/A';
	const id = json.alert?.signature_id || 'N/A';
	const dpt = json.dest_port || 'N/A';
	if (severity > MIN_ALERT_SEVERITY) {
		if (EXTENDED_LOGS) log(`${signature}: SRC=${ipToReport} DPT=${dpt} SIGNATURE_ID=${id}`);
		return;
	}

	const data = { srcIp: ipToReport, dpt, proto: json.proto || 'N/A', id, signature, timestamp: parseTimestamp(json.timestamp) };
	if (test) return data;

	if (isIPReportedRecently(ipToReport)) {
		const lastReportedTime = reportedIPs.get(ipToReport);
		const elapsedTime = Math.floor(Date.now() / 1000 - lastReportedTime);
		const days = Math.floor(elapsedTime / 86400);
		const hours = Math.floor((elapsedTime % 86400) / 3600);
		const minutes = Math.floor((elapsedTime % 3600) / 60);
		const seconds = elapsedTime % 60;
		const timeAgo = [
			days && `${days}d`,
			hours && `${hours}h`,
			minutes && `${minutes}m`,
			(seconds || (!days && !hours && !minutes)) && `${seconds}s`,
		].filter(Boolean).join(' ');

		if (EXTENDED_LOGS) log(`${ipToReport} was last reported on ${new Date(lastReportedTime * 1000).toLocaleString()} (${timeAgo} ago)`);
		return;
	}

	const comment = config.REPORT_COMMENT(data, json);
	if (await reportIp(data, undefined, comment)) {
		markIPAsReported(ipToReport);
		await saveReportedIPs();
	}
};

(async () => {
	log(`${repoFullUrl} - v${version} | Author: ${authorEmailWebsite}`);

	// Auto updates
	if (AUTO_UPDATE_ENABLED && AUTO_UPDATE_SCHEDULE && SERVER_ID !== 'development') {
		await require('./scripts/services/updates.js')();
	} else {
		await require('./scripts/services/version.js')();
	}

	// Bulk
	await loadReportedIPs();
	await loadBufferFromFile();

	if (BULK_REPORT_BUFFER.size > 0 && !ABUSE_STATE.isLimited) {
		log(`Found ${BULK_REPORT_BUFFER.size} IPs in buffer after restart. Sending bulk report...`);
		await sendBulkReport();
	}


	// Fetch IPs
	log('Trying to fetch your IPv4 and IPv6 address from api.sefinek.net...');
	await refreshServerIPs();
	log(`Fetched ${getServerIPs()?.length} of your IP addresses. If any of them accidentally appear in the UFW logs, they will be ignored.`, 1);

	if (!fs.existsSync(SURICATA_EVE_FILE)) {
		log(`Log file ${SURICATA_EVE_FILE} does not exist`, 3);
		return;
	}

	// Watch
	const tail = new TailFile(SURICATA_EVE_FILE);
	tail
		.on('tail_error', err => log(err, 3))
		.start()
		.catch(err => log(err, 3));

	tail
		.pipe(split2())
		.on('data', line => processLogLine(line));

	// Summaries
	if (DISCORD_WEBHOOKS_ENABLED && DISCORD_WEBHOOKS_URL) await require('./scripts/services/summaries.js')();

	// Ready
	await sendWebhook(`[${name}](${repoFullUrl}) has been successfully started on the device \`${SERVER_ID}\`.`, 0x59D267);
	log(`Ready! Now monitoring: ${SURICATA_EVE_FILE}`, 1);
	process.send?.('ready');
})();

module.exports = processLogLine;