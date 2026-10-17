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
const reportApi = require('./scripts/services/reportApi.js');
const { truncateComment } = require('./scripts/reporting/comment.js');
const { refreshServerIPs, getServerIPs } = require('./scripts/services/ipFetcher.js');
const { repoSlug, repoUrl } = require('./scripts/core/repo.js');
const { initWhitelist, isWhitelisted } = require('./scripts/services/whitelist.js');
const ignoredSignatures = require('./scripts/integrations/suricata/ignoredSignatures.js');
const { loadHomeNet, parseHomeNet } = require('./scripts/integrations/suricata/homeNet.js');
const createPolicy = require('./scripts/integrations/suricata/reportPolicy.js');
const createProcessor = require('./scripts/integrations/suricata/createProcessor.js');
const createCaptureMonitor = require('./scripts/integrations/suricata/captureMonitor.js');
const logger = require('./scripts/core/logger.js');
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
const captureMonitor = createCaptureMonitor({ logger });

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

	// Categories are not compared, so a changed category mapping after an update does not drop buffered reports
	return policy.evaluate(entry.context)?.srcIp === ip;
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
	const plan = reportApi.supportsBulk ? 'Reports will be buffered and sent as a bulk report after the reset' : `${reportApi.name} has no bulk report API, so reports are paused until the reset`;
	logger.info(`Daily ${reportApi.name} report limit reached. ${plan} (\`${RATELIMIT_RESET.toLocaleString()}\`).`, { discord: true });
};

const checkRateLimit = async () => {
	if (!ABUSE_STATE.isLimited) return;

	const now = Date.now();
	if (now < RATELIMIT_RESET.getTime()) {
		if (now - LAST_RATELIMIT_LOG >= RATE_LIMIT_LOG_INTERVAL) {
			const minutesLeft = Math.ceil((RATELIMIT_RESET.getTime() - now) / 60000);
			const collected = reportApi.supportsBulk ? `, collected ${BULK_REPORT_BUFFER.size} IPs` : '';
			logger.info(`Rate limit is still active${collected}. Waiting for reset in ${minutesLeft} minute(s) (${RATELIMIT_RESET.toISOString()})...`);
			LAST_RATELIMIT_LOG = now;
		}
		return;
	}

	ABUSE_STATE.isLimited = false;
	ABUSE_STATE.isBuffering = false;
	ABUSE_STATE.sentBulk = false;
	RATELIMIT_RESET = nextRateLimitReset();
	logger.success(`Rate limit reset. Next reset scheduled at \`${RATELIMIT_RESET.toISOString()}\`.`, { discord: true });

	if (reportApi.supportsBulk) await flushBulk();
};

const reportIp = async data => {
	const { srcIp, dpt, proto, id, severity, categories } = data;

	await checkRateLimit();
	if (BULK_REPORT_BUFFER.has(srcIp)) return 'queued';

	if (ABUSE_STATE.isBuffering && !reportApi.supportsBulk) return 'failed';

	const comment = buildComment(data);
	if (ABUSE_STATE.isBuffering) return queueForBulk(data, comment);

	let res;
	try {
		({ data: res } = await axiosService.post('/report', { ip: srcIp, categories, comment }));
	} catch (err) {
		const status = err.response?.status;
		if (reportApi.isDailyLimit(err)) {
			startBuffering();
			return reportApi.supportsBulk ? queueForBulk(data, comment) : 'failed';
		}

		const failureMsg = `Failed to report ${srcIp} [${dpt}/${proto}]; ${reportApi.formatError(err)}`;
		status === 429 ? logger.info(failureMsg) : logger.error(failureMsg);
		return 'failed';
	}

	logger.success(`Reported ${srcIp} [${dpt}/${proto}]; Signature: ${id}; Severity: ${severity}; Categories: ${categories}; Abuse: ${reportApi.getScore(res) ?? 'N/A'}%`);

	if (typeof DISCORD_ALERT_SEVERITY_THRESHOLD === 'number' && severity <= DISCORD_ALERT_SEVERITY_THRESHOLD) {
		await logger.webhook(comment, 0, true).catch(err => logger.error(`Failed to send alert webhook: ${err.message}`));
	}

	return 'reported';
};

const parseConfigHomeNet = () => {
	try {
		return parseHomeNet(HOME_NET.join(','));
	} catch (err) {
		logger.error(`Invalid HOME_NET in config.js: ${describeError(err)}`);
		process.exit(1);
	}
};

// suricata.yaml is the source of truth. HOME_NET from config.js is used only if the file cannot be read or parsed.
const loadLocalNetworks = () => {
	let homeNet, source = SURICATA_CONFIG_FILE;
	try {
		homeNet = loadHomeNet(SURICATA_CONFIG_FILE);
	} catch (err) {
		if (!HOME_NET.length) {
			logger.error(`${describeError(err)}. Fix the access to the file or set HOME_NET in config.js.`);
			process.exit(1);
		}

		logger.warn(`${describeError(err)}. Using HOME_NET from config.js instead.`);
		homeNet = parseConfigHomeNet();
		source = 'config.js';
	}

	logger.info(`Loaded HOME_NET from ${source}: ${homeNet.networks.join(', ')}`);
	return homeNet;
};

const createReportPolicy = () => {
	const homeNet = loadLocalNetworks();

	return createPolicy(config.MAIN, {
		isHomeNet: homeNet.contains,
		getServerIPs,
		isWhitelisted,
		getIgnoredReason: ignoredSignatures.getDescription,
	});
};

const createAlertProcessor = () => createProcessor({
	policy,
	report: reportIp,
	isReportedRecently: isIPReportedRecently,
	markReported: markIPAsReported,
	persistReported: saveReportedIPs,
	// Without a bulk API there is nowhere to send them later, so queued alerts are dropped on shutdown
	deferPending: reportApi.supportsBulk ? async entries => {
		for (const data of entries) {
			try {
				addToBuffer(data, buildComment(data));
			} catch (err) {
				logger.error(`Failed to move ${data.srcIp} to the bulk buffer: ${err.message}`);
			}
		}

		await saveBufferToFile();
	} : undefined,
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
	if (reportApi.supportsBulk) {
		await loadBufferFromFile();
		if (BULK_REPORT_BUFFER.size > 0) {
			logger.info(`Found ${BULK_REPORT_BUFFER.size} IPs in buffer after restart. Sending bulk report...`);
			await flushBulk();
		}
	}

	rateLimitTimer = setInterval(() => {
		checkRateLimit().catch(err => logger.error(`Rate limit check failed: ${err.message}`));
	}, RATE_LIMIT_CHECK_INTERVAL);
	rateLimitTimer.unref();

	// Tail file
	tail = await tailFile(SURICATA_EVE_FILE, line => {
		captureMonitor.onLine(line);
		return processor.processLine(line);
	});
	if (!tail) throw new Error(`Could not start monitoring ${SURICATA_EVE_FILE}`);
	captureMonitor.start();

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
	captureMonitor.stop();

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
