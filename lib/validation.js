'use strict'

const crypto = require('node:crypto')
const addrparser = require('@haraka/email-address')

// HMAC over the original message's identifying headers.
function computeHash(algorithm, secret, { from, date, message_id }) {
  return crypto.createHmac(algorithm, secret).update(`${from}:${date}:${message_id}`).digest('hex')
}

// Timing-safe comparison that also distinguishes a length mismatch.
function compareHash(expected, actual) {
  const buf1 = Buffer.from(expected)
  const buf2 = Buffer.from(actual)

  // Length isn't secret, and unequal lengths can never match. Compare byte
  // lengths first: it keeps timingSafeEqual on equal-size buffers (it throws
  // otherwise) and avoids the truncation that hid a longer prefix match.
  if (buf1.length !== buf2.length) {
    return { match: false, msg: 'hash length mismatch' }
  }

  if (crypto.timingSafeEqual(buf1, buf2)) return { match: true }

  return { match: false, msg: 'hash does not match' }
}

// Rejects bounces whose original message is unparseable or older than maxAgeDays.
function isDateValid(date, maxAgeDays) {
  const email_date = new Date(date)
  if (isNaN(email_date.getTime())) {
    return { valid: false, msg: 'invalid date header' }
  }

  const age = Math.floor((new Date() - email_date) / (1000 * 60 * 60 * 24))
  if (age > maxAgeDays) {
    return { valid: false, msg: 'hash is too old' }
  }

  return { valid: true }
}

// Whitelist supports exact From matches and domain wildcards (e.g. *@example.com).
function isWhitelisted(whitelist, rcpt, from) {
  const entries = whitelist[rcpt]
  if (!entries) return false
  if (entries.includes(from)) return true
  return entries.some((addr) => addr.startsWith('*@') && from.endsWith(addr.substring(1)))
}

// Finds the From/Date/Message-ID/validation-hash headers in the bounce body,
// recursing into MIME children until a part carries at least one of them.
function findBounceHeaders(body) {
  const headers = {}

  if (body?.bodytext?.length) {
    headers.from = extractHeader(body.bodytext, 'From')
    headers.date = extractHeader(body.bodytext, 'Date')
    headers.message_id = extractHeader(body.bodytext, 'Message-ID')
    headers.hash = extractHeader(body.bodytext, 'X-Haraka-Bounce-Validation')

    if (headers.from || headers.date || headers.message_id || headers.hash) {
      return headers
    }
  }

  for (const child of body?.children ?? []) {
    const child_hdrs = findBounceHeaders(child)
    if (child_hdrs.from || child_hdrs.date || child_hdrs.message_id || child_hdrs.hash) {
      return child_hdrs
    }
  }

  return headers
}

function extractHeader(bodytext, header_name) {
  if (!bodytext || typeof bodytext !== 'string') return

  const header_re = new RegExp(
    `^${header_name}:(?<value>[^\r\n]*(?:[\r\n]+[ \t][^\r\n]*)*?)[\r\n]+(?:[a-z\\-]+:|$)`,
    'imu',
  )

  const match = header_re.exec(bodytext)
  if (!match?.groups?.value) return

  // Unfold: strip leading whitespace on continuation lines and join with spaces.
  return match.groups.value
    .split(/[\r\n]+/u)
    .map((line, i) => (i === 0 ? line : line.replace(/^[ \t]+/u, '')))
    .join(' ')
    .trim()
}

function fail(value, msg, rejectOn) {
  return { type: 'fail', value, msg, rejectOn }
}

// Decides the fate of a bounce from its extracted headers, with no I/O or
// plugin state. Returns a verdict the caller maps to results + next:
//   { type: 'pass' }
//   { type: 'skip', msg, emit?, parseError? }
//   { type: 'fail', value, msg, rejectOn }   // rejectOn is a cfg.reject key
function verify(headers, { algorithm, secret, maxAgeDays, whitelist, rcpt, fromHeader }) {
  const { from, date, message_id, hash } = headers

  if (hash) {
    if (!from || !date || !message_id) {
      return fail('validate_bounce', 'missing headers', 'hash_validation')
    }

    const expected = computeHash(algorithm, secret, { from, date, message_id })
    const comparison = compareHash(expected, hash)
    if (!comparison.match) {
      return fail('validate_bounce', comparison.msg, 'hash_validation')
    }

    const dateResult = isDateValid(date, maxAgeDays)
    if (!dateResult.valid) {
      return fail('bounce_date', dateResult.msg, 'hash_date')
    }

    return { type: 'pass' }
  }

  if (from && date && message_id) {
    let parsed_from
    try {
      parsed_from = addrparser.parseHeader(fromHeader)[0].address
    } catch (err) {
      return { type: 'skip', msg: 'invalid from header', emit: true, parseError: err.message }
    }

    if (isWhitelisted(whitelist, rcpt, parsed_from)) {
      return { type: 'skip', msg: 'whitelisted' }
    }

    return fail('validate_bounce', 'missing validation hash', 'hash_validation')
  }

  return { type: 'skip', msg: 'missing all headers' }
}

module.exports = { computeHash, compareHash, isDateValid, isWhitelisted, findBounceHeaders, verify }
