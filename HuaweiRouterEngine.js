/**
 * ============================================================================
 * LINKA CELLULAR INFRASTRUCTURE: ISOLATED HUAWEI ROUTER ENGINE
 * ============================================================================
 * Pure, isolated Node.js engine for Huawei HiLink 4G/LTE/5G Cellular Routers.
 * Compatible with: B310, B315, B525, B535, B618, B818, E5186, etc.
 *
 * Capabilities:
 * - CookieJar-isolated HTTP Session & Dual-Token CSRF Auto-Rotation
 * - Salted SHA-256 Challenge-Response Authentication (Type 4)
 * - Hardware Cellular SMS Dispatch & Delivery Poller
 * - Lesotho Cellular Phone Normalizer (+266 / 8-digit)
 * - SIM Storage Auto-Garbage Collection (Prevents Error 113053)
 * - Real-Time Radio Telemetry (RSSI, RSRP, RAT, SIM detection)
 * - Concurrency Queue with Exponential Backoff Retries
 * - Multi-Router Clustering with Automatic Failover
 * ============================================================================
 */

'use strict';

const crypto = require('crypto');
const EventEmitter = require('events');
const axios = require('axios');
const { CookieJar } = require('tough-cookie');
const xml2js = require('xml2js');

/* ============================================================================
 * SECTION 1: ERROR TAXONOMY & HILINK ERROR DEFINITIONS
 * ============================================================================
 */

class RouterError extends Error {
  constructor(code, message) {
    super(typeof message !== 'undefined' ? message : code);
    this.name = this.constructor.name;
    this.code = code;
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
  toString() {
    return `${this.code}: ${this.message}`;
  }
}

class RouterApiError extends RouterError {
  constructor(code, message, apiCode) {
    super(code.startsWith('api_') ? code : `api_${code}`, message);
    this.apiCode = String(apiCode || code);
  }
}

class RequestError extends RouterError {
  constructor(code, message, cause) {
    super(code.startsWith('http_request_') ? code : `http_request_${code}`, message);
    if (cause) this.cause = cause;
  }
}

const HILINK_ERROR_CODES = {
  '-1': 'default_error',
  '-2': 'no_device_connected',
  '1': 'first_send',
  '100001': 'system_unknown_error',
  '100002': 'system_not_supported',
  '100003': 'system_no_rights',          // Authentication required / Session dead
  '100004': 'system_busy',
  '100005': 'format_error',
  '100006': 'parameter_error',
  '101001': 'no_sim_or_invalid_sim',
  '101002': 'sim_pin_locked',
  '101003': 'sim_puk_locked',
  '102001': 'get_network_type_failed',
  '103001': 'device_at_execute_failed',
  '108001': 'login_username_wrong',
  '108002': 'login_password_wrong',
  '108003': 'login_already_logged_in',
  '108005': 'login_too_many_users',
  '108006': 'login_username_pwd_wrong',
  '108007': 'login_username_pwd_overrun',
  '113018': 'sms_system_busy',
  '113036': 'sms_delete_failed',
  '113053': 'sms_not_enough_space',      // CRITICAL: SIM Memory Full
  '113054': 'sms_phone_number_too_long',
  '125001': 'wrong_token',               // CSRF token mismatch / expired
  '125002': 'wrong_session',             // Cookie session ID invalid
  '125003': 'wrong_session_token',       // Both cookie & token expired
};

function throwApiError(code, message = null) {
  const codeStr = String(code);
  const errorName = HILINK_ERROR_CODES[codeStr] || codeStr;
  const friendlyCode = errorName.toLowerCase();
  const fullMsg = message ? `${friendlyCode} : ${message}` : friendlyCode;
  throw new RouterApiError(friendlyCode, fullMsg, codeStr);
}

/* ============================================================================
 * SECTION 2: UTILITIES, XML ENGINE & LESOTHO NUMBER NORMALIZATION
 * ============================================================================
 */

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

function base64encode(str) {
  return Buffer.from(str, typeof str === 'string' ? 'utf8' : undefined).toString('base64');
}

const xmlParser = new xml2js.Parser({
  explicitArray: false,
  trim: true,
  explicitRoot: true,
});

function parseXml(xmlString) {
  return new Promise((resolve, reject) => {
    if (!xmlString || typeof xmlString !== 'string') return resolve({});
    xmlParser.parseString(xmlString, (err, result) => {
      if (err) return reject(err);
      resolve(result || {});
    });
  });
}

const xmlBuilder = new xml2js.Builder({
  renderOpts: { pretty: false },
  headless: true,
});

function objectToXml(obj) {
  return xmlBuilder.buildObject(obj);
}

function extractTokensFromHtml(html) {
  if (!html || typeof html !== 'string') return [];
  const tokens = [];
  const metaRegex = /<meta\s+name=["']csrf_token["']\s+content=["']([^"']+)["']/gi;
  let match;
  while ((match = metaRegex.exec(html)) !== null) {
    if (match[1]) tokens.push(match[1]);
  }
  return tokens;
}

/**
 * Normalizes phone numbers for Huawei Router SMS dispatch.
 * Lesotho cellular networks (Econet / Vodacom) require 8-digit format.
 * Example: "+26657284264" -> "57284264"
 *          "057284264"    -> "57284264"
 *          "57284264"     -> "57284264"
 */
function toRouterPhone(rawPhone) {
  if (!rawPhone || typeof rawPhone !== 'string') return '';
  const digits = rawPhone.replace(/\D/g, '');
  if (digits.startsWith('266') && digits.length === 11) {
    return digits.slice(3);
  }
  if (digits.length === 8) {
    return digits;
  }
  if (digits.length === 9 && digits.startsWith('0')) {
    return digits.slice(1);
  }
  return rawPhone.trim();
}

function parseRouterUrl(inputUrl) {
  if (!inputUrl) {
    throw new RouterError('invalid_router_url', 'Router URL cannot be empty');
  }
  let formatted = inputUrl.trim();
  if (!formatted.startsWith('http://') && !formatted.startsWith('https://')) {
    formatted = `http://${formatted}`;
  }
  try {
    const parsed = new URL(formatted);
    return {
      url: parsed.href,
      origin: parsed.origin,
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
      protocol: parsed.protocol,
    };
  } catch (e) {
    throw new RouterError('invalid_router_url', `Invalid router URL: ${inputUrl}`);
  }
}

/* ============================================================================
 * SECTION 3: HTTP TRANSPORT & COOKIE/TOKEN ROTATION
 * ============================================================================
 */

class AsyncSerialQueue {
  constructor() {
    this.queue = [];
    this.isProcessing = false;
  }
  add(task) {
    return new Promise((resolve, reject) => {
      this.queue.push(async () => {
        try {
          const res = await task();
          resolve(res);
        } catch (err) {
          reject(err);
        }
      });
      this._process();
    });
  }
  async _process() {
    if (this.isProcessing || this.queue.length === 0) return;
    this.isProcessing = true;
    const task = this.queue.shift();
    try {
      await task();
    } catch (_) {}
    finally {
      this.isProcessing = false;
      if (this.queue.length > 0) this._process();
    }
  }
}

class HttpClient {
  constructor(config) {
    this.config = config;
    this.jar = new CookieJar();
    this.tokens = [];
    this.tokenQueue = new AsyncSerialQueue();
    this.ajaxQueue = new AsyncSerialQueue();

    this.axios = axios.create({
      timeout: this.config.requestTimeout,
      validateStatus: (status) => status >= 200 && status < 400,
    });

    // Request Interceptor: Attach Session Cookie
    this.axios.interceptors.request.use(async (reqConfig) => {
      const url = reqConfig.url || '';
      try {
        const cookieString = await this.jar.getCookieString(url);
        if (cookieString) {
          reqConfig.headers = reqConfig.headers || {};
          reqConfig.headers['Cookie'] = cookieString;
        }
      } catch (_) {}
      return reqConfig;
    });

    // Response Interceptor: Capture Set-Cookie and CSRF Verification Tokens
    this.axios.interceptors.response.use(async (response) => {
      const setCookie = response.headers['set-cookie'];
      const url = response.config.url || '';
      if (setCookie) {
        const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
        for (const cookie of cookies) {
          try {
            await this.jar.setCookie(cookie, url);
          } catch (_) {}
        }
      }
      this._extractTokensFromHeaders(response.headers);
      return response;
    });
  }

  _extractTokensFromHeaders(headers = {}) {
    if (!headers) return;
    const lowerHeaders = {};
    for (const [k, v] of Object.entries(headers)) {
      lowerHeaders[k.toLowerCase()] = v;
    }

    const tCombined = lowerHeaders['__requestverificationtoken'];
    const t1 = lowerHeaders['__requestverificationtokenone'];
    const t2 = lowerHeaders['__requestverificationtokentwo'];

    const newTokens = [];
    if (tCombined && typeof tCombined === 'string') {
      const parts = tCombined.split('#').map((t) => t.trim()).filter(Boolean);
      for (const p of parts) {
        if (!this.tokens.includes(p)) newTokens.push(p);
      }
    }
    if (t1 && !this.tokens.includes(t1) && !newTokens.includes(t1)) {
      newTokens.unshift(t1);
    }
    if (t2 && !this.tokens.includes(t2) && !newTokens.includes(t2)) {
      newTokens.push(t2);
    }

    if (newTokens.length > 0) {
      this.tokens = [...newTokens, ...this.tokens];
    }
  }

  async request(options) {
    const opts = Object.assign({ method: 'GET' }, options);
    if (opts.accepts) {
      opts.headers = Object.assign({ Accept: opts.accepts }, opts.headers);
    }
    opts.timeout = this.config.requestTimeout;

    try {
      return await this.axios(opts);
    } catch (error) {
      let code = 'error';
      let msg = error.message;
      if (error.response) {
        code = error.response.status === 408 || error.code === 'ECONNABORTED' ? 'timeout' : 'invalid_status';
        msg = `HTTP status ${error.response.status}`;
      } else if (error.request) {
        code = 'no_response';
        msg = `No response received from router at ${this.config.url}`;
      }
      throw new RequestError(code, msg, error);
    }
  }

  async xmlRequest(options) {
    const response = await this.request({
      accepts: 'application/xml, text/xml, */*',
      ...options,
    });
    try {
      const parsed = await parseXml(response.data);
      return { data: parsed, headers: response.headers, raw: response.data };
    } catch (e) {
      throw new RequestError('invalid_xml', `Failed to parse XML: ${e.message}`, e);
    }
  }

  processXmlResponse(ret, responseMustBeOk = false) {
    if (!ret || typeof ret !== 'object') {
      if (responseMustBeOk) throw new RouterError('xml_response_not_ok', 'Empty response from router');
      return ret;
    }
    const keys = Object.keys(ret);
    if (keys.length === 0) return ret;

    const root = keys[0];
    const rootValue = ret[root];

    if (root === 'error') {
      const code = rootValue?.code || rootValue;
      const message = rootValue?.message;
      throwApiError(code, message);
    }

    if (responseMustBeOk) {
      const isOk =
        rootValue === 'OK' ||
        rootValue === 'ok' ||
        rootValue?.code === '0' ||
        rootValue?.Code?.toLowerCase?.() === 'ok' ||
        (typeof rootValue === 'string' && rootValue.toLowerCase() === 'ok');

      if (isOk) return rootValue;
      throw new RouterError('xml_response_not_ok', `Expected OK but received: ${JSON.stringify(rootValue)}`);
    }

    return rootValue;
  }

  async fetchTokens() {
    const parsedUrl = this.config.parsedUrl;
    if (!parsedUrl) return [];

    // Strategy 1: /api/webserver/SesTokInfo (Standard on Modern LTE/5G HiLink Routers)
    try {
      const res = await this.xmlRequest({ url: `${parsedUrl.origin}/api/webserver/SesTokInfo` });
      const tokInfo = res.data?.response?.TokInfo || res.data?.TokInfo;
      let sesInfo = res.data?.response?.SesInfo || res.data?.SesInfo;
      if (sesInfo && typeof sesInfo === 'string') {
        if (!sesInfo.startsWith('SessionID=')) sesInfo = `SessionID=${sesInfo}`;
        await this.jar.setCookie(sesInfo, parsedUrl.origin);
      }
      if (tokInfo && typeof tokInfo === 'string') return [tokInfo];
    } catch (_) {}

    // Strategy 2: Extract from /html/home.html meta tags
    try {
      const home = await this.request({ url: `${parsedUrl.origin}/html/home.html` });
      const tokens = extractTokensFromHtml(home.data);
      if (tokens.length > 0) return tokens;
    } catch (_) {}

    // Strategy 3: Legacy endpoint /api/webserver/token
    try {
      const res = await this.xmlRequest({ url: `${parsedUrl.origin}/api/webserver/token` });
      const token = res.data?.response?.token || res.data?.token;
      if (token && typeof token === 'string') return [token];
    } catch (_) {}

    return [];
  }

  async refreshTokens() {
    return this.tokenQueue.add(async () => {
      const newTokens = await this.fetchTokens();
      if (newTokens && newTokens.length > 0) {
        this.tokens = [...newTokens];
      }
      return this.tokens;
    });
  }

  async getTokens(fresh = false) {
    if (!this.tokens || this.tokens.length === 0 || fresh) {
      await this.refreshTokens();
    }
    return this.tokens;
  }

  async getAjaxData(options) {
    const url = `${this.config.parsedUrl.origin}/${options.url.replace(/^\//, '')}`;
    try {
      const ret = await this.xmlRequest({ url });
      return this.processXmlResponse(ret.data, options.responseMustBeOk);
    } catch (e) {
      if (['125001', '125002', '125003'].includes(e.apiCode) || e.code === 'api_wrong_token') {
        await this.refreshTokens();
        const retryRet = await this.xmlRequest({ url });
        return this.processXmlResponse(retryRet.data, options.responseMustBeOk);
      }
      throw e;
    }
  }

  async saveAjaxData(options) {
    return this.ajaxQueue.add(async () => {
      return this._executeSaveAjaxData(options);
    });
  }

  async _executeSaveAjaxData(options, isRetry = false) {
    let tokens = await this.getTokens();
    const headers = { 'Content-Type': 'application/xml' };

    if (tokens.length > 0) {
      headers['__RequestVerificationToken'] = tokens[0];
      this.tokens = tokens.slice(1);
    }

    const xmlString = typeof options.request === 'string'
      ? options.request
      : objectToXml({ request: options.request });

    const url = `${this.config.parsedUrl.origin}/${options.url.replace(/^\//, '')}`;

    let ret;
    try {
      ret = await this.xmlRequest({
        url,
        method: 'POST',
        data: xmlString,
        headers,
      });
    } catch (e) {
      if (!isRetry && (['125001', '125002', '125003'].includes(e.apiCode) || e.code === 'api_wrong_token')) {
        await this.refreshTokens();
        return this._executeSaveAjaxData(options, true);
      }
      throw e;
    }

    try {
      return this.processXmlResponse(ret.data, options.responseMustBeOk);
    } catch (e) {
      if (!isRetry && (['125001', '125002', '125003'].includes(e.apiCode) || e.code === 'api_wrong_token')) {
        await this.refreshTokens();
        return this._executeSaveAjaxData(options, true);
      }
      throw e;
    }
  }
}

/* ============================================================================
 * SECTION 4: ROUTER CONFIGURATION
 * ============================================================================
 */

class RouterConfig {
  constructor(options = {}) {
    const rawUrl = options.url || options.ip || '192.168.9.1';
    this.parsedUrl = parseRouterUrl(rawUrl);
    this.url = this.parsedUrl.url;
    this.username = options.username || 'admin';
    this.password = options.password || '';
    this.requestTimeout = parseInt(options.timeout || options.requestTimeout || '10000', 10);
    this.autoLogin = options.autoLogin !== false;
  }
}

/* ============================================================================
 * SECTION 5: AUTHENTICATION MODULE (SALTED SHA-256)
 * ============================================================================
 */

class AdminModule {
  constructor(client) {
    this.client = client;
  }

  async getLoginState() {
    const data = await this.client.http.getAjaxData({ url: 'api/user/state-login' });
    return {
      State: parseInt(data?.State, 10) || 0,
      Username: data?.Username || '',
      password_type: parseInt(data?.password_type, 10) || 4,
    };
  }

  async isLoggedIn() {
    try {
      const state = await this.getLoginState();
      return state.State === 0;
    } catch (_) {
      return false;
    }
  }

  async login(username = null, password = null) {
    const user = username || this.client.config.username;
    const pass = password || this.client.config.password;

    // Step 1: Pre-fetch fresh tokens & challenge
    await this.client.http.refreshTokens();
    const tokens = await this.client.http.getTokens();
    const token = tokens.length > 0 ? tokens[0] : '';

    // Step 2: Query router for password hash mode
    const loginState = await this.getLoginState();

    // Step 3: Compute Challenge-Response Hash
    let processedPassword;
    if (token && String(loginState.password_type) === '4') {
      // Modern Huawei HiLink Salted SHA-256 Protocol:
      // 1. innerHash = SHA256(password)
      // 2. innerBase64 = Base64(innerHash)
      // 3. outerHash = SHA256(username + innerBase64 + token)
      // 4. processedPassword = Base64(outerHash)
      const innerHash = sha256(pass);
      const innerBase64 = base64encode(innerHash);
      const outerHash = sha256(user + innerBase64 + token);
      processedPassword = base64encode(outerHash);
    } else {
      // Legacy Base64
      processedPassword = base64encode(pass);
    }

    // Step 4: Dispatch Login POST
    return this.client.http.saveAjaxData({
      url: 'api/user/login',
      request: {
        Username: user,
        Password: processedPassword,
        password_type: loginState.password_type || 4,
      },
      responseMustBeOk: true,
    });
  }

  async logout() {
    try {
      return await this.client.http.saveAjaxData({
        url: 'api/user/logout',
        request: { Logout: 1 },
        responseMustBeOk: true,
      });
    } catch (_) {
      return true;
    }
  }

  async ensureLoggedIn() {
    const logged = await this.isLoggedIn();
    if (!logged) await this.login();
    return true;
  }
}

/* ============================================================================
 * SECTION 6: SMS MODULE (DISPATCH, INBOX & DELETION)
 * ============================================================================
 */

class SmsModule {
  constructor(client) {
    this.client = client;
  }

  _formatDate(d) {
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  async getSmsCount() {
    const data = await this.client.http.getAjaxData({ url: 'api/sms/sms-count' });
    const p = {};
    for (const key of Object.keys(data || {})) {
      p[key] = parseInt(data[key], 10) || 0;
    }
    p.SimTotal = 'SimUsed' in p ? p.SimUsed : (p.SimInbox || 0) + (p.SimOutbox || 0) + (p.SimDraft || 0);
    p.LocalTotal = (p.LocalInbox || 0) + (p.LocalOutbox || 0) + (p.LocalDraft || 0) + (p.LocalDeleted || 0);
    p.TotalMessages = p.SimTotal + p.LocalTotal;
    p.UnreadTotal = (p.LocalUnread || 0) + (p.SimUnread || 0);
    p.SimMax = p.SimMax || 20;
    p.LocalMax = p.LocalMax || 500;
    return p;
  }

  async getSmsList(options = {}) {
    const opts = Object.assign(
      { page: 1, perPage: 20, boxType: 1, sortOrder: 'desc' },
      options
    );

    const data = await this.client.http.saveAjaxData({
      url: 'api/sms/sms-list',
      request: {
        PageIndex: opts.page,
        ReadCount: opts.perPage,
        BoxType: opts.boxType,
        SortType: 0,
        Ascending: opts.sortOrder === 'desc' ? 0 : 1,
        UnreadPreferred: 0,
      },
    });

    if (!data) return [];
    const count = parseInt(data.Count, 10) || 0;
    if (count > 1 && data.Messages?.Message) {
      return Array.isArray(data.Messages.Message) ? data.Messages.Message : [data.Messages.Message];
    } else if (count === 1 && data.Messages?.Message) {
      return [data.Messages.Message];
    }
    return [];
  }

  async sendSms(options) {
    if (this.client.config.autoLogin) {
      await this.client.admin.ensureLoggedIn().catch(() => {});
    }

    const rawPhones = options.numbers || (options.phone ? [options.phone] : []);
    const phones = (Array.isArray(rawPhones) ? rawPhones : [rawPhones]).map(toRouterPhone);
    const content = String(options.content || options.message || '');
    const dateStr = this._formatDate(new Date());

    const payload = {
      Index: -1,
      Phones: { Phone: phones },
      Sca: options.sca || '',
      Content: content,
      Length: content.length,
      Reserved: 1,
      Date: dateStr,
    };

    try {
      await this.client.http.saveAjaxData({
        url: 'api/sms/send-sms',
        request: payload,
        responseMustBeOk: true,
      });
    } catch (err) {
      // On permission/session errors, re-authenticate once
      if (['100003', '125002'].includes(err.apiCode) || err.code === 'api_system_no_rights') {
        await this.client.admin.login();
        await this.client.http.saveAjaxData({
          url: 'api/sms/send-sms',
          request: payload,
          responseMustBeOk: true,
        });
      } else {
        throw err;
      }
    }

    // Verify delivery status
    try {
      const status = await this.getSmsSendStatus();
      return {
        success: true,
        status,
        phones,
        content,
        sentAt: new Date().toISOString(),
      };
    } catch (_) {
      return {
        success: true,
        phones,
        content,
        sentAt: new Date().toISOString(),
      };
    }
  }

  async getSmsSendStatus() {
    return this.client.http.getAjaxData({ url: 'api/sms/send-status' });
  }

  async deleteSms(indices) {
    const rawList = Array.isArray(indices) ? indices : [indices];
    const list = rawList
      .map((i) => (typeof i === 'object' && i !== null ? i.Index : i))
      .filter((i) => i !== undefined && i !== null);
    if (list.length === 0) return true;

    return this.client.http.saveAjaxData({
      url: 'api/sms/delete-sms',
      request: { Index: list },
      responseMustBeOk: true,
    });
  }

  async setSmsAsRead(indices) {
    const list = Array.isArray(indices) ? indices : [indices];
    return this.client.http.saveAjaxData({
      url: 'api/sms/set-read',
      request: { Index: list.map((i) => parseInt(i, 10)) },
      responseMustBeOk: true,
    });
  }
}

/* ============================================================================
 * SECTION 7: SIM GARBAGE COLLECTION DAEMON (PREVENTS ERROR 113053)
 * ============================================================================
 */

class SimGarbageCollector extends EventEmitter {
  constructor(client, options = {}) {
    super();
    this.client = client;
    this.pollIntervalMs = options.pollIntervalMs || 45000; // 45 seconds
    this.maxSimThreshold = options.maxSimThreshold || 15;   // Trigger threshold
    this.isRunning = false;
    this.isChecking = false;
    this.timer = null;
    this.totalCleaned = 0;
  }

  start() {
    if (this.isRunning) return;
    this.isRunning = true;
    this.emit('started');

    setTimeout(() => {
      if (this.isRunning) this.collect();
    }, 5000);

    this.timer = setInterval(() => {
      this.collect();
    }, this.pollIntervalMs);
  }

  stop() {
    if (!this.isRunning) return;
    this.isRunning = false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.emit('stopped');
  }

  async collect() {
    if (this.isChecking || !this.isRunning) return;
    this.isChecking = true;

    try {
      if (this.client.config.autoLogin) {
        await this.client.admin.ensureLoggedIn().catch(() => {});
      }

      const count = await this.client.sms.getSmsCount();
      const simRatio = count.SimMax > 0 ? count.SimTotal / count.SimMax : 0;
      const shouldClean = count.SimTotal >= this.maxSimThreshold || simRatio >= 0.75;

      if (!shouldClean) {
        this.isChecking = false;
        return { cleaned: 0, count };
      }

      // Query SIM Inbox (BoxType: 5)
      const messages = await this.client.sms.getSmsList({ boxType: 5, perPage: 15 });
      let cleaned = 0;

      if (Array.isArray(messages) && messages.length > 0) {
        const ids = messages.map((m) => {
          this.emit('sms_received', m);
          return m.Index;
        });

        if (ids.length > 0) {
          await this.client.sms.deleteSms(ids);
          cleaned = ids.length;
          this.totalCleaned += cleaned;
          this.emit('sim_cleaned', { cleaned, totalCleaned: this.totalCleaned });
        }
      }

      return { cleaned, count };
    } catch (err) {
      this.emit('error', err);
      return { error: err.message };
    } finally {
      this.isChecking = false;
    }
  }
}

/* ============================================================================
 * SECTION 8: MONITORING & TELEMETRY MODULE
 * ============================================================================
 */

const NETWORK_TYPES = {
  0: 'No Service',
  1: 'GSM',
  2: 'GPRS',
  3: 'EDGE',
  4: 'WCDMA',
  7: 'HSPA',
  9: 'HSPA+',
  19: 'LTE',
  101: 'LTE-Advanced',
};

class MonitoringModule {
  constructor(client) {
    this.client = client;
  }

  async getStatus() {
    const data = await this.client.http.getAjaxData({ url: 'api/monitoring/status' });
    const parsed = { ...data };
    const numFields = [
      'ConnectionStatus', 'SignalIcon', 'CurrentNetworkType', 'BatteryStatus',
      'SimStatus', 'CurrentWifiUser', 'TotalWifiUser', 'maxsignal'
    ];
    for (const f of numFields) {
      if (parsed[f] !== undefined) parsed[f] = parseInt(parsed[f], 10) || 0;
    }
    parsed.NetworkTypeName = NETWORK_TYPES[parsed.CurrentNetworkType] || `Type ${parsed.CurrentNetworkType}`;
    parsed.IsConnected = parsed.ConnectionStatus === 901;
    parsed.HasSimCard = parsed.SimStatus === 1;
    return parsed;
  }

  async getTrafficStatistics() {
    return this.client.http.getAjaxData({ url: 'api/monitoring/traffic-statistics' });
  }

  async checkNotifications() {
    const ret = await this.client.http.getAjaxData({ url: 'api/monitoring/check-notifications' });
    return {
      UnreadMessage: parseInt(ret?.UnreadMessage, 10) || 0,
      SmsStorageFull: ret?.SmsStorageFull === '1' || ret?.SmsStorageFull === 1,
      OnlineUpdateStatus: parseInt(ret?.OnlineUpdateStatus, 10) || 0,
    };
  }
}

/* ============================================================================
 * SECTION 9: DIALUP & USSD MODULES
 * ============================================================================
 */

class DialupModule {
  constructor(client) {
    this.client = client;
  }
  async getConnection() {
    return this.client.http.getAjaxData({ url: 'api/dialup/connection' });
  }
  async setMobileDataSwitch(enable = true) {
    return this.client.http.saveAjaxData({
      url: 'api/dialup/mobile-dataswitch',
      request: { dataswitch: enable ? 1 : 0 },
      responseMustBeOk: true,
    });
  }
}

class UssdModule {
  constructor(client) {
    this.client = client;
  }
  async sendUssdCommand(command) {
    return this.client.http.saveAjaxData({
      url: 'api/ussd/send',
      request: { content: command, codeType: 'CodeType', timeout: '' },
      responseMustBeOk: true,
    });
  }
  async getUssdResult() {
    return this.client.http.getAjaxData({ url: 'api/ussd/get' });
  }
  async releaseUssd() {
    return this.client.http.getAjaxData({ url: 'api/ussd/release' });
  }
}

/* ============================================================================
 * SECTION 10: CONCURRENCY QUEUE & PRIORITY RETRY CONTROLLER
 * ============================================================================
 */

class ResilientSmsQueue extends EventEmitter {
  constructor(options = {}) {
    super();
    this.concurrency = options.concurrency || 2;
    this.maxRetries = options.maxRetries || 3;
    this.initialBackoffMs = options.initialBackoffMs || 1500;
    this.maxBackoffMs = options.maxBackoffMs || 30000;
    this.queue = [];
    this.activeJobs = new Map();
    this.handler = null;
  }

  setHandler(handler) {
    this.handler = handler;
    this._processNext();
  }

  enqueue(payload, options = {}) {
    const job = {
      id: `job_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
      data: payload,
      priority: options.priority || (payload.isOtp ? 10 : 0),
      attempts: 0,
      maxRetries: options.maxRetries !== undefined ? options.maxRetries : this.maxRetries,
      createdAt: new Date().toISOString(),
    };
    this.queue.push(job);
    this.queue.sort((a, b) => b.priority - a.priority);
    this._processNext();
    return job;
  }

  _processNext() {
    if (!this.handler || this.activeJobs.size >= this.concurrency || this.queue.length === 0) return;
    const job = this.queue.shift();
    if (!job) return;

    this.activeJobs.set(job.id, job);
    job.attempts++;

    this.handler(job.data, job)
      .then((res) => {
        this.emit('completed', job, res);
      })
      .catch((err) => {
        if (job.attempts <= job.maxRetries) {
          const backoff = Math.min(
            this.maxBackoffMs,
            this.initialBackoffMs * Math.pow(2, job.attempts - 1) + Math.floor(Math.random() * 500)
          );
          setTimeout(() => {
            this.queue.unshift(job);
            this.queue.sort((a, b) => b.priority - a.priority);
            this._processNext();
          }, backoff);
        } else {
          this.emit('failed', job, err);
        }
      })
      .finally(() => {
        this.activeJobs.delete(job.id);
        this._processNext();
      });

    if (this.activeJobs.size < this.concurrency && this.queue.length > 0) {
      this._processNext();
    }
  }
}

/* ============================================================================
 * SECTION 11: SINGLE ROUTER CLIENT (FACADE)
 * ============================================================================
 */

class HuaweiClient extends EventEmitter {
  constructor(options = {}) {
    super();
    this.config = options instanceof RouterConfig ? options : new RouterConfig(options);
    this.http = new HttpClient(this.config);

    this.admin = new AdminModule(this);
    this.sms = new SmsModule(this);
    this.monitoring = new MonitoringModule(this);
    this.dialup = new DialupModule(this);
    this.ussd = new UssdModule(this);

    this.gc = new SimGarbageCollector(this, {
      pollIntervalMs: options.gcIntervalMs || 45000,
      maxSimThreshold: options.gcThreshold || 15,
    });

    this.gc.on('sms_received', (msg) => this.emit('sms_received', msg));
    this.gc.on('sim_cleaned', (info) => this.emit('sim_cleaned', info));
    this.gc.on('error', (err) => this.emit('gc_error', err));
  }

  async testConnection() {
    try {
      const loginState = await this.admin.getLoginState();
      return {
        reachable: true,
        loggedIn: loginState.State === 0,
        username: loginState.Username,
        url: this.config.url,
      };
    } catch (err) {
      return {
        reachable: false,
        loggedIn: false,
        error: err.message,
        url: this.config.url,
      };
    }
  }

  async sendOtp(phone, otp, options = {}) {
    const appName = options.appName || 'Linka';
    const ttlMinutes = options.ttlMinutes || 5;
    const message = options.customTemplate
      ? options.customTemplate.replace('{otp}', otp)
      : `[${appName}] Your verification code is: ${otp}. Valid for ${ttlMinutes} minutes. Do not share this code.`;

    return this.sms.sendSms({
      phone,
      content: message,
    });
  }

  startGarbageCollection() {
    this.gc.start();
    return this;
  }

  stopGarbageCollection() {
    this.gc.stop();
    return this;
  }

  async getHealthTelemetry() {
    try {
      const status = await this.monitoring.getStatus();
      const smsCount = await this.sms.getSmsCount();
      return {
        online: true,
        ip: this.config.parsedUrl.hostname,
        connected: status.IsConnected,
        signalBars: status.SignalIcon,
        networkType: status.NetworkTypeName,
        simPresent: status.HasSimCard,
        simUsed: smsCount.SimTotal,
        simMax: smsCount.SimMax,
        unreadSms: smsCount.UnreadTotal,
        gcRunning: this.gc.isRunning,
      };
    } catch (err) {
      return {
        online: false,
        ip: this.config.parsedUrl.hostname,
        error: err.message,
        gcRunning: this.gc.isRunning,
      };
    }
  }
}

/* ============================================================================
 * SECTION 12: MULTI-ROUTER POOL & FAILOVER CONTROLLER
 * ============================================================================
 */

class RouterPool extends EventEmitter {
  constructor(routerConfigs = [], options = {}) {
    super();
    this.strategy = options.strategy || 'failover'; // 'failover' | 'round-robin'
    this.clients = [];
    this.currentIndex = 0;

    this.queue = new ResilientSmsQueue({
      concurrency: options.concurrency || Math.max(1, routerConfigs.length * 2),
      maxRetries: options.maxRetries || 3,
      initialBackoffMs: options.initialBackoffMs || 1500,
    });

    this.queue.setHandler(async (jobData) => {
      return this._dispatchSms(jobData);
    });

    for (const cfg of routerConfigs) {
      this.addRouter(cfg);
    }
  }

  addRouter(config) {
    const client = config instanceof HuaweiClient ? config : new HuaweiClient(config);
    this.clients.push(client);
    client.on('sms_received', (msg) => this.emit('sms_received', msg, client));
    client.on('sim_cleaned', (info) => this.emit('sim_cleaned', info, client));
    return client;
  }

  async initialize() {
    const results = await Promise.allSettled(
      this.clients.map(async (client, idx) => {
        const test = await client.testConnection();
        if (test.reachable) {
          client.startGarbageCollection();
        }
        return { index: idx, ...test };
      })
    );
    return results;
  }

  async sendOtp(phone, otp, options = {}) {
    return this._dispatchSms({
      phone,
      otp,
      isOtp: true,
      appName: options.appName || 'Linka',
      ttlMinutes: options.ttlMinutes || 5,
      content: options.customTemplate
        ? options.customTemplate.replace('{otp}', otp)
        : `[${options.appName || 'Linka'}] Your verification code is: ${otp}. Valid for ${options.ttlMinutes || 5} minutes. Do not share this code.`,
    });
  }

  async _dispatchSms(payload) {
    if (this.clients.length === 0) throw new Error('No routers configured in pool');

    const clientOrder = this._getClientOrder();
    const errors = [];

    for (const client of clientOrder) {
      const ip = client.config.parsedUrl.hostname;
      try {
        const result = await client.sms.sendSms(payload);
        return { ...result, deliveredBy: ip };
      } catch (err) {
        errors.push({ router: ip, error: err.message });
      }
    }

    const combinedError = new Error(
      `All ${this.clients.length} router gateway(s) failed: ${errors.map((e) => `${e.router} (${e.error})`).join(', ')}`
    );
    combinedError.routerErrors = errors;
    throw combinedError;
  }

  _getClientOrder() {
    if (this.strategy === 'round-robin') {
      const order = [];
      for (let i = 0; i < this.clients.length; i++) {
        order.push(this.clients[(this.currentIndex + i) % this.clients.length]);
      }
      this.currentIndex = (this.currentIndex + 1) % this.clients.length;
      return order;
    }
    // Failover: Always try primary first
    return [...this.clients];
  }

  startAllGarbageCollection() {
    for (const c of this.clients) c.startGarbageCollection();
  }

  stopAllGarbageCollection() {
    for (const c of this.clients) c.stopGarbageCollection();
  }

  async getPoolTelemetry() {
    const statuses = await Promise.all(this.clients.map((c) => c.getHealthTelemetry()));
    return {
      poolSize: this.clients.length,
      onlineCount: statuses.filter((s) => s.online).length,
      strategy: this.strategy,
      routers: statuses,
    };
  }
}

/* ============================================================================
 * SECTION 13: UNIFIED HIGH-LEVEL GATEWAY
 * ============================================================================
 */

class HuaweiGateway {
  constructor(options = {}) {
    const routerList = [];

    if (Array.isArray(options)) {
      routerList.push(...options);
    } else if (options.routers && Array.isArray(options.routers)) {
      routerList.push(...options.routers);
    } else {
      routerList.push(options);
    }

    this.pool = new RouterPool(routerList, options);
    this.primaryClient = this.pool.clients[0] || null;
  }

  static fromEnv(env = process.env) {
    const primaryIp = env.ROUTER_1_IP || env.ROUTER_IP || env.HUAWEI_ROUTER_IP || '192.168.9.1';
    const user = env.ROUTER_USER || env.HUAWEI_ROUTER_USER || 'admin';
    const pass = env.ROUTER_PASS || env.HUAWEI_ROUTER_PASS || 'Technomath';
    const timeout = parseInt(env.ROUTER_TIMEOUT_MS || '10000', 10);

    const routers = [
      {
        url: primaryIp,
        username: user,
        password: pass,
        timeout,
        gcIntervalMs: parseInt(env.SIM_GC_INTERVAL_MS || '45000', 10),
        gcThreshold: parseInt(env.SIM_GC_THRESHOLD || '15', 10),
      },
    ];

    if (env.ENABLE_ROUTER_2 === 'true' && env.ROUTER_2_IP) {
      routers.push({
        url: env.ROUTER_2_IP,
        username: env.ROUTER_2_USER || user,
        password: env.ROUTER_2_PASS || pass,
        timeout,
      });
    }

    return new HuaweiGateway({
      routers,
      strategy: env.ROUTER_POOL_STRATEGY || 'failover',
    });
  }

  async initialize() {
    return this.pool.initialize();
  }

  async sendOtp(phone, otp, options = {}) {
    return this.pool.sendOtp(phone, otp, options);
  }

  async getTelemetry() {
    return this.pool.getPoolTelemetry();
  }

  startGarbageCollection() {
    this.pool.startAllGarbageCollection();
  }

  stopGarbageCollection() {
    this.pool.stopAllGarbageCollection();
  }
}

/* ============================================================================
 * SECTION 14: STANDALONE CLI TEST ENTRYPOINT
 * ============================================================================
 */

if (require.main === module) {
  (async () => {
    console.log('===============================================================');
    console.log('🔍 Testing Isolated Huawei Router Program Execution');
    console.log('===============================================================');

    // Load from local .env or fallback
    const targetIp = process.env.ROUTER_1_IP || '192.168.9.1';
    const username = process.env.ROUTER_USER || 'admin';
    const password = process.env.ROUTER_PASS || 'Technomath';

    console.log(`🎯 Connecting to Router: http://${targetIp} (User: ${username})...`);

    const router = new HuaweiClient({
      url: targetIp,
      username,
      password,
      timeout: 8000,
    });

    try {
      const conn = await router.testConnection();
      console.log('📡 Connection Probe Result:', conn);

      if (conn.reachable) {
        console.log('🔐 Authenticating via Salted SHA-256...');
        await router.admin.ensureLoggedIn();
        console.log('✅ Logged in successfully!');

        console.log('📊 Querying Telemetry & Radio Metrics...');
        const telemetry = await router.getHealthTelemetry();
        console.log('📶 Radio Status:', JSON.stringify(telemetry, null, 2));

        console.log('🧹 Triggering Test SIM Garbage Collection run...');
        const gcResult = await router.gc.collect();
        console.log('🧹 GC Result:', gcResult);
      } else {
        console.log('⚠️ Physical router is offline or unreachable on local subnet.');
      }
    } catch (err) {
      console.error('❌ Execution Error:', err.message);
    }
  })();
}

module.exports = {
  HuaweiClient,
  HuaweiGateway,
  RouterPool,
  RouterConfig,
  HttpClient,
  AdminModule,
  SmsModule,
  MonitoringModule,
  DialupModule,
  UssdModule,
  SimGarbageCollector,
  ResilientSmsQueue,
  toRouterPhone,
  RouterError,
  RouterApiError,
  RequestError,
  HILINK_ERROR_CODES,
};


