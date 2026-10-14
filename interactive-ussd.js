#!/usr/bin/env node
/**
 * ============================================================================
 * INTERACTIVE USSD SESSION CLI — Huawei HiLink B315s-936
 * ----------------------------------------------------------------------------
 * Maintains a live, multi-step USSD session against a Huawei HiLink router
 * (same as the router's built-in web USSD portal, but scriptable over SSH).
 *
 * REQUIREMENT: this file must sit in the SAME folder as HuaweiRouterEngine.js
 *
 * Setup (on the deployment PC):
 *   npm install            # axios, tough-cookie, xml2js  (from your package.json)
 *
 * Run:
 *   node interactive-ussd.js --ip 192.168.10.1 --user admin --pass 'Technomath'
 *   node interactive-ussd.js                          # uses env vars / defaults
 *
 * Env overrides:
 *   ROUTER_1_IP / ROUTER_IP   (default 192.168.10.1 — your mobile router)
 *   ROUTER_USER               (default admin)
 *   ROUTER_PASS               (default Technomath)
 *   ROUTER_TIMEOUT_MS         (default 12000)
 *
 * REPL commands once inside:
 *   *121#        start a USSD session with any code (asterisk/hash allowed)
 *   1            any plain number/text = respond to the current USSD menu
 *   release      abort/end the USSD session
 *   status       show radio / SIM / network telemetry
 *   quit | exit  leave the CLI
 * ============================================================================
 */

'use strict';

const readline = require('readline');
const { HuaweiClient } = require('./HuaweiRouterEngine');

/* ----------------------------- arg parsing -------------------------------- */

function parseArgs(argv) {
  const args = { ip: null, user: null, pass: null, timeout: null };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === '--ip' || a === '-i') args.ip = next();
    else if (a === '--user' || a === '-u') args.user = next();
    else if (a === '--pass' || a === '-p') args.pass = next();
    else if (a === '--timeout' || a === '-t') args.timeout = next();
    else if (a.startsWith('--ip=')) args.ip = a.slice(5);
    else if (a.startsWith('--user=')) args.user = a.slice(7);
    else if (a.startsWith('--pass=')) args.pass = a.slice(7);
    else if (a === '--help' || a === '-h') { printUsage(); process.exit(0); }
  }
  return args;
}

function printUsage() {
  console.log(`
Usage: node interactive-ussd.js [--ip 192.168.10.1] [--user admin] [--pass '...']

Inside the REPL:
  *121#      start a USSD session (any *code#)
  1          reply to the current USSD menu (any number or text)
  release    end the current USSD session
  status     radio / SIM / network telemetry
  quit       exit
`);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/* --------------------------- session wrapper ------------------------------ */

class UssdSession {
  constructor(client) {
    this.client = client;
    this.active = false;
  }

  _extractContent(result) {
    if (!result) return null;
    if (typeof result === 'string') return result.trim() || null;
    const c = result.content ?? result.Content ?? result.result ?? result.Result ?? result.reply ?? result.Reply;
    return c ? String(c).trim() : null;
  }

  /**
   * Send a USSD payload and poll until a textual reply arrives
   * (or attempts are exhausted). Returns the reply text or null.
   */
  async send(payload) {
    await this.client.ussd.sendUssdCommand(payload);
    this.active = true;

    const maxAttempts = 14;          // ~21 s worst case
    let lastRaw = null;
    for (let i = 1; i <= maxAttempts; i++) {
      await sleep(1500);
      try {
        const res = await this.client.ussd.getUssdResult();
        lastRaw = res;
        const content = this._extractContent(res);
        if (content) return content;
      } catch (_) {
        /* transient read failure — keep polling */
      }
    }

    console.log('   (no reply text; raw response follows)');
    console.log('   ' + JSON.stringify(lastRaw));
    return null;
  }

  async release() {
    try {
      await this.client.ussd.releaseUssd();
    } catch (_) { /* already released */ }
    this.active = false;
  }
}

/* --------------------------------- main ----------------------------------- */

async function main() {
  const args = parseArgs(process.argv);

  const IP      = args.ip      || process.env.ROUTER_1_IP || process.env.ROUTER_IP || '192.168.10.1';
  const USER    = args.user    || process.env.ROUTER_USER || 'admin';
  const PASS    = args.pass    || process.env.ROUTER_PASS || 'Technomath';
  const TIMEOUT = parseInt(args.timeout || process.env.ROUTER_TIMEOUT_MS || '12000', 10);

  console.log('===============================================================');
  console.log('  Interactive USSD Session — Huawei HiLink (B315s-936)');
  console.log('===============================================================');
  console.log(`Router : http://${IP}   User: ${USER}`);

  const client = new HuaweiClient({ url: IP, username: USER, password: PASS, timeout: TIMEOUT });

  // --- connect + authenticate (same flow as the web portal) ---
  const probe = await client.testConnection();
  if (!probe.reachable) {
    console.error(`\n❌ Router unreachable at http://${IP}: ${probe.error || 'no response'}`);
    console.error('   Check: are you SSH\'d into the PC on the 192.168.10.x subnet?');
    process.exit(2);
  }
  console.log('Reachable ✓');

  await client.admin.ensureLoggedIn();
  console.log('Authenticated ✓');

  try {
    const st = await client.monitoring.getStatus();
    console.log(`Network: ${st.NetworkTypeName || '?'} | Signal: ${st.SignalIcon ?? '?'} bars | SIM: ${st.HasSimCard ? 'present' : 'MISSING'} | Connected: ${st.IsConnected ? 'yes' : 'no'}`);
  } catch (_) { /* telemetry is best-effort */ }

  console.log('\nType a USSD code (e.g. *121#) to start. Type "quit" to exit.\n');

  const session = new UssdSession(client);

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: true,
    prompt: session.active ? 'ussd> ' : 'code> ',
  });

  // re-render prompt correctly as session state changes
  const refreshPrompt = () => rl.setPrompt(session.active ? 'ussd> ' : 'code> ');

  rl.on('close', async () => {
    await session.release();
    console.log('\nUSSD session released. Bye.');
    process.exit(0);
  });

  rl.on('line', async (line) => {
    const input = line.trim();
    if (!input) { rl.prompt(); return; }

    rl.pause();                       // no overlapping input while a request is in flight

    try {
      const lower = input.toLowerCase();

      if (lower === 'quit' || lower === 'exit' || lower === 'q') {
        await session.release();
        rl.close();
        return;
      }

      if (lower === 'status') {
        const t = await client.getHealthTelemetry();
        console.log(' ', JSON.stringify(t, null, 2));
        rl.resume(); refreshPrompt(); rl.prompt();
        return;
      }

      if (lower === 'release' || lower === 'end') {
        await session.release();
        console.log('   USSD session released.');
        rl.resume(); refreshPrompt(); rl.prompt();
        return;
      }

      // Anything else is a USSD payload: a fresh code (*xxx#) or a menu reply
      const reply = await session.send(input);
      if (reply) {
        console.log('--- USSD reply --------------------------------------------');
        console.log(reply);
        console.log('------------------------------------------------------------');
      }
    } catch (err) {
      const apiCode = err && err.apiCode ? ` [api ${err.apiCode}]` : '';
      console.error(`   Error: ${err.message || err}${apiCode}`);
      if (err.apiCode === '100003' || err.code === 'api_system_no_rights') {
        try { await client.admin.login(); console.log('   (re-authenticated, try again)'); } catch (_) {}
      }
      // Session most likely dead after a send failure
      session.active = false;
    }

    rl.resume(); refreshPrompt(); rl.prompt();
  });

  refreshPrompt();
  rl.prompt();
}

main().catch((err) => {
  console.error('\nFatal:', err.message || err);
  process.exit(1);
});
