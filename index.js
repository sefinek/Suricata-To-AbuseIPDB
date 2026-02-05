//   Copyright 2025-2026 © by Sefinek. All Rights Reserved.
//                   https://sefinek.net

const fs = require('node:fs');
const TailFile = require('@logdna/tail-file');
const split2 = require('split2');
const { parseTimestamp } = require('ufw-log-parser');
const banner = require('./scripts/banners/suricata.js');
const { axiosService } = require('./scripts/services/axios.js');
const { saveBufferToFile, loadBufferFromFile, sendBulkReport, BULK_REPORT_BUFFER } = require('./scripts/services/bulk.js');
const { reportedIPs, loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported } = require('./scripts/services/cache.js');
const ABUSE_STATE = require('./scripts/services/state.js');
const { refreshServerIPs, getServerIPs } = require('./scripts/services/ipFetcher.js');
const { repoSlug, repoUrl } = require('./scripts/repo.js');
const isSpecialPurposeIP = require('./scripts/isSpecialPurposeIP.js');
const ignoredSignatures = require('./scripts/suricata/ignoredSignatures.js');
const logger = require('./scripts/logger.js');
const config = require('./config.js');
const { SURICATA_EVE_FILE, SERVER_ID, EXTENDED_LOGS, MIN_ALERT_SEVERITY, AUTO_UPDATE_ENABLED, AUTO_UPDATE_SCHEDULE, DISCORD_WEBHOOK_ENABLED, DISCORD_WEBHOOK_URL, DISCORD_ALERT_SEVERITY_THRESHOLD } = config.MAIN;

const RATE_LIMIT_LOG_INTERVAL = 10 * 60 * 1000;
const BUFFER_STATS_INTERVAL = 5 * 60 * 1000;
const MAX_BUFFER_SIZE = 100000;

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
			logger.success(`Rate limit reset. Next reset scheduled at \`${RATELIMIT_RESET.toISOString()}\`.`, { discord: true });
		} else if (now - LAST_RATELIMIT_LOG >= RATE_LIMIT_LOG_INTERVAL) {
			const minutesLeft = Math.ceil((RATELIMIT_RESET.getTime() - now) / 60000);
			logger.info(`Rate limit is still active, collected ${BULK_REPORT_BUFFER.size} IPs. Waiting for reset in ${minutesLeft} minute(s) (${RATELIMIT_RESET.toISOString()})...`);
			LAST_RATELIMIT_LOG = now;
		}
	}
};

const reportIp = async ({ srcIp, dpt = 'N/A', proto = 'N/A', id, severity, timestamp }, categories = '15', comment) => {
	if (!srcIp) return logger.error('Missing source IP (srcIp)');

	await checkRateLimit();

	if (ABUSE_STATE.isBuffering) {
		if (BULK_REPORT_BUFFER.has(srcIp)) return;

		// Check buffer size limit to prevent memory overflow
		if (BULK_REPORT_BUFFER.size >= MAX_BUFFER_SIZE) {
			logger.warn(`Buffer full (${MAX_BUFFER_SIZE} IPs). Skipping ${srcIp} to prevent memory overflow.`);
			return;
		}

		BULK_REPORT_BUFFER.set(srcIp, { categories, timestamp, comment });
		await saveBufferToFile();
		return logger.success(`Queued ${srcIp} for bulk report (collected ${BULK_REPORT_BUFFER.size} IPs)`);
	}

	try {
		const { data: res } = await axiosService.post('/report', {
			ip: srcIp,
			categories,
			comment,
		});

		logger.success(`Reported ${srcIp} [${dpt}/${proto}]; Signature: ${id}; Severity ${severity}; Categories: ${categories}; Abuse: ${res.data.abuseConfidenceScore}%`);

		if (typeof DISCORD_ALERT_SEVERITY_THRESHOLD === 'number' && severity <= DISCORD_ALERT_SEVERITY_THRESHOLD) await logger.webhook(comment, 0, true);
		return true;
	} catch (err) {
		const status = err.response?.status;
		if (status === 429 && JSON.stringify(err.response?.data || {}).includes('Daily rate limit')) {
			if (!ABUSE_STATE.isLimited) {
				ABUSE_STATE.isLimited = true;
				ABUSE_STATE.isBuffering = true;
				ABUSE_STATE.sentBulk = false;
				LAST_RATELIMIT_LOG = Date.now();
				RATELIMIT_RESET = nextRateLimitReset();
				logger.info(`Daily API request limit for specified endpoint reached. Reports will be buffered until \`${RATELIMIT_RESET.toLocaleString()}\`. Bulk report will be sent the following day.`, { discord: true });
			}

			if (!BULK_REPORT_BUFFER.has(srcIp)) {
				BULK_REPORT_BUFFER.set(srcIp, { timestamp, categories, comment });
				await saveBufferToFile();
				logger.success(`Queued ${srcIp} for bulk report due to rate limit`);
			}
		} else {
			const failureMsg = `Failed to report ${srcIp} [${dpt}/${proto}]; ${err.response?.data?.errors ? JSON.stringify(err.response.data.errors) : err.message}`;
			status === 429 ? logger.info(failureMsg) : logger.error(failureMsg);
		}
	}
};

const processLogLine = async (line, test = false) => {
	if (!line || !line.startsWith('{') || !line.endsWith('}')) return;
	if (!line.includes('"event_type":"alert"')) return;

	let json;
	try {
		json = JSON.parse(line);
	} catch (err) {
		if (EXTENDED_LOGS) logger.error(`Invalid JSON: ${err.message}\nLine: ${line.slice(0, 200)}${line.length > 200 ? '...' : ''}`);
		return;
	}

	const srcIp = json.src_ip;
	if (!srcIp) return;

	// Check IP
	const ips = getServerIPs();
	if (!Array.isArray(ips)) return logger.error(`For some reason, 'ips' from 'getServerIPs()' is not an array. Received: ${ips}`);

	const destIp = json.dest_ip;
	let ipToReport = srcIp;
	const srcIsLocal = ips.includes(srcIp) || isSpecialPurposeIP(srcIp);
	const destIsLocal = ips.includes(destIp) || isSpecialPurposeIP(destIp);
	if (srcIsLocal && destIsLocal) {
		if (EXTENDED_LOGS) logger.info(`Both SRC=${srcIp} and DEST=${destIp} are local/special, ignoring alert`);
		return;
	}
	if (srcIsLocal) ipToReport = destIp;

	// Process
	const severity = json.alert.severity;
	const signature = json.alert?.signature || 'N/A';
	const id = json.alert?.signature_id || 'N/A';
	const dpt = json.dest_port || 'N/A';

	if (ignoredSignatures.isIgnored(id)) {
		if (EXTENDED_LOGS) logger.info(`Signature ${id} is ignored (${ignoredSignatures.getDescription(id)}), skipping alert`);
		return;
	}

	if (severity > MIN_ALERT_SEVERITY) {
		if (EXTENDED_LOGS) logger.info(`${signature}: SRC=${ipToReport} DPT=${dpt} SIGNATURE=${id} SEVERITY=${severity}`);
		return;
	}

	const { timestamp } = parseTimestamp(json.timestamp);
	const data = { srcIp: ipToReport, dpt, proto: json.proto || 'N/A', id, severity, signature, timestamp };
	if (test) return data;

	// Report
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

		if (EXTENDED_LOGS) logger.info(`${ipToReport} was last reported on ${new Date(lastReportedTime * 1000).toLocaleString()} (${timeAgo} ago)`);
		return;
	}

	const comment = config.REPORT_COMMENT(data, line);
	if (await reportIp(data, undefined, comment)) {
		markIPAsReported(ipToReport);
		await saveReportedIPs();
	}
};

(async () => {
	banner();

	// Auto updates
	if (AUTO_UPDATE_ENABLED && AUTO_UPDATE_SCHEDULE && SERVER_ID !== 'development') {
		await require('./scripts/services/updates.js')();
	} else {
		await require('./scripts/services/version.js');
	}

	// Fetch IPs
	await refreshServerIPs();

	// Load cache
	await loadReportedIPs();

	// Bulk
	await loadBufferFromFile();
	if (BULK_REPORT_BUFFER.size > 0 && !ABUSE_STATE.isLimited) {
		logger.info(`Found ${BULK_REPORT_BUFFER.size} IPs in buffer after restart. Sending bulk report...`);
		await sendBulkReport();
	}

	// Check SURICATA_EVE_FILE
	if (!fs.existsSync(SURICATA_EVE_FILE)) {
		logger.error(`Log file ${SURICATA_EVE_FILE} does not exist`);
		return;
	}

	// Watch
	const tail = new TailFile(SURICATA_EVE_FILE);
	tail
		.on('tail_error', err => logger.error(err))
		.start()
		.catch(err => logger.error(err));

	tail
		.pipe(split2())
		.on('data', processLogLine);

	// Summaries
	if (DISCORD_WEBHOOK_ENABLED && DISCORD_WEBHOOK_URL) await require('./scripts/services/summaries.js')();

	// Ready
	await logger.webhook(`[${repoSlug}](${repoUrl}) was successfully started!`, 0x59D267);
	logger.success(`Ready! Now monitoring: ${SURICATA_EVE_FILE}`);
	process.send?.('ready');
})();

const gracefulShutdown = async signal => {
	logger.info(`Received ${signal}, flushing pending writes...`);
	try {
		await saveBufferToFile();
		await saveReportedIPs();
	} catch (err) {
		logger.error(`Error during shutdown flush: ${err.message}`);
	}
	process.exit(0);
};

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

module.exports = processLogLine;