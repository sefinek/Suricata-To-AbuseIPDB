//   Copyright 2025-2026 © by Sefinek. All Rights Reserved.
//                   https://sefinek.net

const config = require('./config.js');
require('./scripts/validations/index.js')(config.MAIN);
const banner = require('./scripts/banners/suricata.js');
const { axiosService } = require('./scripts/services/axios.js');
const tailFile = require('./scripts/services/tailFile.js');
const { saveBufferToFile, loadBufferFromFile, sendBulkReport, BULK_REPORT_BUFFER } = require('./scripts/services/bulk.js');
const { loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported } = require('./scripts/services/cache.js');
const ABUSE_STATE = require('./scripts/services/state.js');
const { truncateComment } = require('./scripts/comment.js');
const { refreshServerIPs, getServerIPs } = require('./scripts/services/ipFetcher.js');
const { repoSlug, repoUrl } = require('./scripts/repo.js');
const { initWhitelist, isWhitelisted } = require('./scripts/services/whitelist.js');
const ignoredSignatures = require('./scripts/suricata/ignoredSignatures.js');
const { loadHomeNet, parseHomeNet } = require('./scripts/suricata/homeNet.js');
const createPolicy = require('./scripts/suricata/reportPolicy.js');
const createProcessor = require('./scripts/suricata/createProcessor.js');
const logger = require('./scripts/logger.js');
const { SURICATA_EVE_FILE, SURICATA_CONFIG_FILE, HOME_NET, EXTENDED_LOGS, DISCORD_WEBHOOK_ENABLED, DISCORD_WEBHOOK_URL, DISCORD_ALERT_SEVERITY_THRESHOLD } = config.MAIN;

const RATE_LIMIT_LOG_INTERVAL = 10 * 60 * 1000;
const RATE_LIMIT_CHECK_INTERVAL = 60 * 1000;
const MAX_BUFFER_SIZE = 100000;

const nextRateLimitReset = () => {
	const now = new Date();
	return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 1));
};

let LAST_RATELIMIT_LOG = 0, RATELIMIT_RESET = nextRateLimitReset();
let policy = null, processor = null, bulkUpload = null, rateLimitTimer = null, tail = null, shuttingDown = false;

// Includes the chain of causes, e.g. "Cannot read /etc/suricata/suricata.yaml... (EACCES: permission denied, ...)"
const describeError = err => (err.cause ? `${err.message} (${describeError(err.cause)})` : err.message);

const buildComment = data => {
	const comment = truncateComment(config.REPORT_COMMENT(data, JSON.stringify(data.evidence)));
	if (typeof comment !== 'string' || !comment.trim()) throw new Error('REPORT_COMMENT must return a non-empty string');
	return comment;
};

const addToBuffer = (data, comment) => {
	if (BULK_REPORT_BUFFER.has(data.srcIp)) return true;
	if (BULK_REPORT_BUFFER.size >= MAX_BUFFER_SIZE) {
		logger.warn(`Buffer full (${MAX_BUFFER_SIZE} IPs). Skipping ${data.srcIp} to prevent memory overflow.`);
		return false;
	}

	BULK_REPORT_BUFFER.set(data.srcIp, { categories: data.categories, timestamp: data.timestamp, comment, context: data.evidence });
	return true;
};

const queueForBulk = async (data, comment) => {
	if (BULK_REPORT_BUFFER.has(data.srcIp)) return 'queued';
	if (!addToBuffer(data, comment)) return 'failed';

	await saveBufferToFile();
	logger.success(`Queued ${data.srcIp} for bulk report (collected ${BULK_REPORT_BUFFER.size} IPs)`);
	return 'queued';
};

// Buffered entries are re-evaluated, because the ignored signatures, whitelist or server IPs may have changed since they were queued
const isBufferedEntryValid = (ip, entry) => {
	if (isIPReportedRecently(ip)) return false;

	const current = policy.evaluate(entry.context);
	return current?.srcIp === ip && current.categories === entry.categories;
};

// sendBulkReport() shares an upload in progress, the promise is kept only to await it on shutdown
const flushBulk = () => {
	bulkUpload = sendBulkReport({ validateEntry: isBufferedEntryValid });
	return bulkUpload;
};

const startBuffering = () => {
	if (ABUSE_STATE.isLimited) return;

	ABUSE_STATE.isLimited = true;
	ABUSE_STATE.isBuffering = true;
	ABUSE_STATE.sentBulk = false;
	LAST_RATELIMIT_LOG = Date.now();
	RATELIMIT_RESET = nextRateLimitReset();
	logger.info(`Daily API request limit for specified endpoint reached. Reports will be buffered until \`${RATELIMIT_RESET.toLocaleString()}\`. Bulk report will be sent the following day.`, { discord: true });
};

const checkRateLimit = async () => {
	if (!ABUSE_STATE.isLimited) return;

	const now = Date.now();
	if (now < RATELIMIT_RESET.getTime()) {
		if (now - LAST_RATELIMIT_LOG >= RATE_LIMIT_LOG_INTERVAL) {
			const minutesLeft = Math.ceil((RATELIMIT_RESET.getTime() - now) / 60000);
			logger.info(`Rate limit is still active, collected ${BULK_REPORT_BUFFER.size} IPs. Waiting for reset in ${minutesLeft} minute(s) (${RATELIMIT_RESET.toISOString()})...`);
			LAST_RATELIMIT_LOG = now;
		}
		return;
	}

	ABUSE_STATE.isLimited = false;
	ABUSE_STATE.isBuffering = false;
	ABUSE_STATE.sentBulk = false;
	RATELIMIT_RESET = nextRateLimitReset();
	logger.success(`Rate limit reset. Next reset scheduled at \`${RATELIMIT_RESET.toISOString()}\`.`, { discord: true });

	await flushBulk();
};

const reportIp = async data => {
	const { srcIp, dpt, proto, id, severity, categories } = data;

	await checkRateLimit();
	if (BULK_REPORT_BUFFER.has(srcIp)) return 'queued';

	const comment = buildComment(data);
	if (ABUSE_STATE.isBuffering) return queueForBulk(data, comment);

	let res;
	try {
		({ data: res } = await axiosService.post('/report', { ip: srcIp, categories, comment }));
	} catch (err) {
		const status = err.response?.status;
		if (status === 429 && JSON.stringify(err.response?.data || {}).includes('Daily rate limit')) {
			startBuffering();
			return queueForBulk(data, comment);
		}

		const failureMsg = `Failed to report ${srcIp} [${dpt}/${proto}]; ${err.response?.data?.errors ? JSON.stringify(err.response.data.errors) : err.message}`;
		status === 429 ? logger.info(failureMsg) : logger.error(failureMsg);
		return 'failed';
	}

	logger.success(`Reported ${srcIp} [${dpt}/${proto}]; Signature: ${id}; Severity: ${severity}; Categories: ${categories}; Abuse: ${res?.data?.abuseConfidenceScore ?? 'N/A'}%`);

	if (typeof DISCORD_ALERT_SEVERITY_THRESHOLD === 'number' && severity <= DISCORD_ALERT_SEVERITY_THRESHOLD) {
		await logger.webhook(comment, 0, true).catch(err => logger.error(`Failed to send alert webhook: ${err.message}`));
	}

	return 'reported';
};

const loadLocalNetworks = () => {
	const source = HOME_NET.length ? 'config.js' : SURICATA_CONFIG_FILE;

	try {
		const homeNet = HOME_NET.length ? parseHomeNet(HOME_NET.join(',')) : loadHomeNet(SURICATA_CONFIG_FILE);
		logger.info(`Loaded HOME_NET from ${source}: ${homeNet.networks.join(', ')}`);
		return homeNet;
	} catch (err) {
		logger.error(describeError(err));
		process.exit(1);
	}
};

const createReportPolicy = () => {
	const homeNet = loadLocalNetworks();

	return createPolicy(config.MAIN, {
		isHomeNet: homeNet.contains,
		getServerIPs,
		isWhitelisted,
		isIgnored: ignoredSignatures.isIgnored,
	});
};

const createAlertProcessor = () => createProcessor({
	policy,
	report: reportIp,
	isReportedRecently: isIPReportedRecently,
	markReported: markIPAsReported,
	persistReported: saveReportedIPs,
	deferPending: async entries => {
		for (const data of entries) addToBuffer(data, buildComment(data));
		await saveBufferToFile();
	},
	logSkip: EXTENDED_LOGS ? reason => logger.info(reason) : undefined,
	logger,
});

const start = async () => {
	banner();

	// Version check
	require('./scripts/services/version.js');

	// Fetch IPs
	await refreshServerIPs();

	// Whitelist
	initWhitelist();

	// Report policy
	policy = createReportPolicy();
	processor = createAlertProcessor();

	// Load cache
	await loadReportedIPs();

	// Bulk
	await loadBufferFromFile();
	if (BULK_REPORT_BUFFER.size > 0) {
		logger.info(`Found ${BULK_REPORT_BUFFER.size} IPs in buffer after restart. Sending bulk report...`);
		await flushBulk();
	}

	rateLimitTimer = setInterval(() => {
		checkRateLimit().catch(err => logger.error(`Rate limit check failed: ${err.message}`));
	}, RATE_LIMIT_CHECK_INTERVAL);
	rateLimitTimer.unref();

	// Tail file
	tail = await tailFile(SURICATA_EVE_FILE, processor.processLine);
	if (!tail) throw new Error(`Could not start monitoring ${SURICATA_EVE_FILE}`);

	// Summaries
	if (DISCORD_WEBHOOK_ENABLED && DISCORD_WEBHOOK_URL) await require('./scripts/services/summaries.js')();

	// Ready
	await logger.webhook(`[${repoSlug}](${repoUrl}) was successfully started!`, 0x59D267);
	logger.success(`Ready! Now monitoring: ${SURICATA_EVE_FILE}`);
	process.send?.('ready');
};

const gracefulShutdown = async signal => {
	if (shuttingDown) return;
	shuttingDown = true;

	logger.info(`Received ${signal}, flushing pending reports and writes...`);
	clearInterval(rateLimitTimer);

	try {
		await tail?.quit();
		await processor?.stop();
		await bulkUpload;
		await saveBufferToFile();
		await saveReportedIPs();
	} catch (err) {
		logger.error(`Error during shutdown flush: ${err.message}`);
		process.exit(1);
	}

	process.exit(0);
};

start().catch(err => {
	logger.error(`Startup failed: ${err.stack}`);
	process.exit(1);
});

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
