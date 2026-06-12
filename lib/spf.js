'use strict'

const { SPF } = require('haraka-plugin-spf')
const net_utils = require('haraka-net-utils')

// Lazy regexp to get IPs from Received: headers in bounces
const received_re = net_utils.get_ipany_re('^Received:[\\s\\S]*?[\\[\\(](?:IPv6:)?', '[\\]\\)]')

// Collects public IP addresses from Received headers throughout the message body.
function findReceivedHeaders(body, ips = new Set()) {
  if (!body) return ips

  let match
  received_re.lastIndex = 0
  while ((match = received_re.exec(body.bodytext))) {
    const ip = match[1]
    if (net_utils.is_private_ip(ip)) continue
    ips.add(ip)
  }

  for (const child of body.children ?? []) {
    findReceivedHeaders(child, ips)
  }

  return ips
}

// Maps an SPF result code to a bounce_spf decision. Pure; no I/O.
function classifyResult(spf, result) {
  switch (result) {
    // No SPF record, or a lookup error that every subsequent IP would repeat.
    case spf.SPF_NONE:
    case spf.SPF_TEMPERROR:
    case spf.SPF_PERMERROR:
      return { action: 'skip', msg: `SPF returned ${spf.result(result)}` }
    case spf.SPF_PASS:
      return { action: 'pass' }
    default:
      return { action: 'continue' }
  }
}

function defaultLookup(spf, ip, rcpt) {
  return spf.check_host(ip, rcpt.host, rcpt.address)
}

// Checks each IP against the recipient domain's SPF, short-circuiting on the
// first definitive result. `lookup` is injectable so callers can avoid DNS.
// Returns a verdict: { type: 'pass' | 'skip' | 'fail', msg?, ip? }
async function evaluate(ips, rcpt, lookup = defaultLookup) {
  const spf = new SPF()

  for (const ip of ips) {
    let result
    try {
      result = await lookup(spf, ip, rcpt)
    } catch (err) {
      return { type: 'skip', msg: err.message }
    }

    const decision = classifyResult(spf, result)
    if (decision.action === 'skip') return { type: 'skip', msg: decision.msg, ip }
    if (decision.action === 'pass') return { type: 'pass', ip }
  }

  return { type: 'fail', msg: 'invalid bounce (spoofed sender)' }
}

module.exports = { classifyResult, defaultLookup, evaluate, findReceivedHeaders }
