#!/usr/bin/env node
/**
 * One-shot USSD session tester for Huawei HiLink routers
 * Usage:
 *   node test-ussd.js "*121#"
 *   node test-ussd.js "*134#"
 *   ROUTER_1_IP=192.168.8.1 ROUTER_PASS=secret node test-ussd.js "*121#"
 *
 * Env (optional):
 *   ROUTER_1_IP / ROUTER_IP   default 192.168.9.1
 *   ROUTER_USER               default admin
 *   ROUTER_PASS               default Technomath
 *   ROUTER_TIMEOUT_MS         default 12000
 */

'use strict';

const { HuaweiClient } = require('./HuaweiRouterEngine');

const USSD_CODE = process.argv[2];

if (!USSD_CODE) {
  console.error(`
Usage: node test-ussd.js "<ussd-code>"

Examples:
  node test-ussd.js "*121#"          # Econet balance (Lesotho)
  node test-ussd.js "*134#"          # Vodacom recharge / balance
  node test-ussd.js "*100#"

Environment overrides:
  ROUTER_1_IP=192.168.9.1
  ROUTER_USER=admin
  ROUTER_PASS=Technomath
`);
  process.exit(1);
}

const IP       = process.env.ROUTER_1_IP || process.env.ROUTER_IP || '192.168.9.1';
const USER     = process.env.ROUTER_USER || 'admin';
const PASS     = process.env.ROUTER_PASS || 'Technomath';
const TIMEOUT  = parseInt(process.env.ROUTER_TIMEOUT_MS || '12000', 10);

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function main() {
  console.log('===============================================================');
  console.log('  Huawei HiLink – One-shot USSD Session Tester');
  console.log('===============================================================');
  console.log(`Router : http://${IP}`);
  console.log(`User   : ${USER}`);
  console.log(`USSD   : ${USSD_CODE}`);
  console.log('---------------------------------------------------------------');

  const client = new HuaweiClient({
    url: IP,
    username: USER,
    password: PASS,
    timeout: TIMEOUT,
    autoLogin: true,
  });

  // 1. Reachability + login
  console.log('\n[1/5] Probing router & authenticating…');
  const probe = await client.testConnection();
  if (!probe.reachable) {
    console.error('❌ Router unreachable:', probe.error || 'no response');
    process.exit(2);
  }
  console.log('    Reachable ✓');

  await client.admin.ensureLoggedIn();
  console.log('    Logged in ✓');

  // 2. Optional radio status
  try {
    const status = await client.monitoring.getStatus();
    console.log(`    Network : ${status.NetworkTypeName || 'unknown'} | Signal: ${status.SignalIcon || '?'} bars | SIM: ${status.HasSimCard ? 'present' : 'missing'}`);
  } catch (_) {
    console.log('    (could not read radio status)');
  }

  // 3. Send USSD
  console.log(`\n[2/5] Sending USSD command: ${USSD_CODE}`);
  try {
    await client.ussd.sendUssdCommand(USSD_CODE);
    console.log('    Command accepted by modem ✓');
  } catch (err) {
    console.error('❌ Failed to send USSD:', err.message || err);
    process.exit(3);
  }

  // 4. Poll for result (USSD responses can take 2–15 s)
  console.log('\n[3/5] Waiting for network response…');
  const maxAttempts = 12;
  let result = null;

  for (let i = 1; i <= maxAttempts; i++) {
    await sleep(1500);
    process.stdout.write(`    poll ${i}/${maxAttempts}… `);

    try {
      result = await client.ussd.getUssdResult();
      // Typical successful shape contains content / result / reply
      const content =
        result?.content ||
        result?.Content ||
        result?.result ||
        result?.Result ||
        result?.reply ||
        result?.Reply ||
        (typeof result === 'string' ? result : null);

      if (content && String(content).trim().length > 0) {
        console.log('got reply ✓');
        console.log('\n---------------------------------------------------------------');
        console.log('USSD REPLY:');
        console.log(String(content).trim());
        console.log('---------------------------------------------------------------');
        break;
      }

      // Some firmwares return a status code instead of content while pending
      const status = result?.status || result?.Status || result?.code;
      if (status && String(status) !== '0' && String(status) !== '1') {
        console.log(`status=${status}`);
      } else {
        console.log('pending');
      }
    } catch (err) {
      console.log('error:', err.message || err);
    }
  }

  if (!result || !(result.content || result.Content || result.result || result.Result || result.reply || result.Reply)) {
    console.log('\n⚠️  No textual reply received within timeout.');
    console.log('Raw last response:', JSON.stringify(result, null, 2));
  }

  // 5. Always release the USSD session
  console.log('\n[4/5] Releasing USSD session…');
  try {
    await client.ussd.releaseUssd();
    console.log('    Session released ✓');
  } catch (err) {
    console.log('    (release failed – usually harmless):', err.message || err);
  }

  console.log('\n[5/5] Done.\n');
}

main().catch((err) => {
  console.error('\nFatal:', err.message || err);
  process.exit(1);
});


