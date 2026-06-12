'use strict'

const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const { describe, it, beforeEach } = require('node:test')

const { Address } = require('@haraka/email-address')
const { callHook, makeConnection, makePlugin } = require('haraka-test-fixtures')

const validationLib = require('../lib/validation')

let plugin, connection

beforeEach(() => {
  plugin = makePlugin('bounce')
  connection = makeConnection({ ip: '8.8.8.8', mailFrom: '<>', rcptTo: ['test@example.com'] })
})

const call = async (fn, ...args) => {
  const { rc, msg } = await callHook(plugin, fn, connection, ...args)
  return [rc, msg]
}

const assertNext = ([code, msg]) => {
  assert.equal(code, undefined)
  assert.equal(msg, undefined)
}

describe('create_validation_hash', () => {
  let from_header, date_header, message_id

  beforeEach(() => {
    connection.transaction.body = { bodytext: '', children: [] }
    connection.transaction.parse_body = true
    connection.transaction.mail_from = new Address('<test@example.com>')
    connection.relaying = true
    plugin.cfg.check.hash_validation = true
    plugin.cfg.validation = {
      hash_algorithm: 'sha256',
      secret: crypto.randomBytes(32).toString('base64'),
    }

    from_header = '<test@example.com>'
    date_header = new Date().toISOString()
    message_id = '<test@example.COM>'
  })

  const validation_header = () => connection.transaction.header.get('X-Haraka-Bounce-Validation').trim()

  const add_all_headers = () => {
    connection.transaction.add_header('From', from_header)
    connection.transaction.add_header('Date', date_header)
    connection.transaction.add_header('Message-ID', message_id)
  }

  it('create_validation_hash - missing transaction', async () => {
    delete connection.transaction

    assertNext(await call('empty_return_path'))
  })

  it('should not create validation hash', async () => {
    plugin.cfg.check.hash_validation = false
    add_all_headers()

    const [code, msg] = await call('create_validation_hash')
    assert.equal(validation_header(), '')
    assertNext([code, msg])
  })

  it('should ignore inbound mail', async () => {
    connection.relaying = false
    add_all_headers()

    const [code, msg] = await call('create_validation_hash')
    assert.equal(validation_header(), '')
    assertNext([code, msg])
  })

  it('should skip outbound with null sender', async () => {
    connection.transaction.mail_from = new Address('<>')
    connection.relaying = true
    connection.transaction.results.add(plugin, { isa: true })
    add_all_headers()

    const [code, msg] = await call('create_validation_hash')
    assert.equal(validation_header(), '')
    assertNext([code, msg])
  })

  it('missing Message-ID header', async () => {
    connection.transaction.add_header('From', from_header)
    connection.transaction.add_header('Date', date_header)

    const [code, msg] = await call('create_validation_hash')
    assert.equal(validation_header(), '')
    assertNext([code, msg])
  })

  it('missing From, Date, and Message-ID headers', async () => {
    const [code, msg] = await call('create_validation_hash')
    assert.equal(validation_header(), '')
    assertNext([code, msg])
  })

  it('should create a validation hash', async () => {
    add_all_headers()

    const amalgam = `${from_header}:${date_header}:${message_id}`
    const expected = crypto
      .createHmac(plugin.cfg.validation.hash_algorithm, plugin.cfg.validation.secret)
      .update(amalgam)
      .digest('hex')

    const [code, msg] = await call('create_validation_hash')
    assert.equal(validation_header(), expected)
    assertNext([code, msg])
  })
})

describe('validate_bounce', () => {
  let amalgam, date_header, from_header, message_id

  beforeEach(() => {
    plugin.cfg.check.hash_date = true
    plugin.cfg.check.hash_validation = true
    plugin.cfg.reject.hash_validation = true
    plugin.cfg.reject.hash_date = true
    plugin.cfg.validation = {
      max_hash_age_days: 6,
      hash_algorithm: 'sha256',
      secret: crypto.randomBytes(32).toString('base64'),
    }

    connection.transaction.body = { bodytext: '', children: [] }

    date_header = new Date().toISOString()
    from_header = '<test@example.com>'
    message_id = '<test@example.com>'
    amalgam = `${from_header}:${date_header}:${message_id}`
  })

  it('validate_bounce - missing transaction', async () => {
    delete connection.transaction

    assertNext(await call('empty_return_path'))
  })

  it('should skip validation check', async () => {
    plugin.cfg.check.hash_validation = false

    const [code, msg] = await call('validate_bounce')
    assert.ok(!connection.transaction.results.has(plugin, 'pass', 'validate_bounce'))
    assert.ok(!connection.transaction.results.has(plugin, 'skip', 'validate_bounce'))
    assertNext([code, msg])
  })

  it('has hash size that is too short', async () => {
    plugin.cfg.reject.hash_validation = false
    connection.transaction.body.bodytext = create_body(plugin, { hash: '1234567890' })

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash length mismatch'))
    assertNext([code, msg])
  })

  it('has hash size that is too long', async () => {
    plugin.cfg.reject.hash_validation = false
    const hash = '1234567890123456789012345678901234567890123456789012345678901234567890'
    connection.transaction.body.bodytext = create_body(plugin, { hash })

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash length mismatch'))
    assertNext([code, msg])
  })

  it('will reject if wrong hash size', async () => {
    connection.transaction.body.bodytext = create_body(plugin, { hash: '1234567890' })

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash length mismatch'))
    assert.equal(code, DENY)
    assert.equal(msg, 'invalid bounce')
  })

  it('is a valid inbound bounce', async () => {
    connection.transaction.body.bodytext = create_body(plugin)

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'pass', 'validate_bounce'))
    assertNext([code, msg])
  })

  it('has incorrect hash', async () => {
    plugin.cfg.reject.hash_validation = false
    const hash = crypto
      .createHmac(plugin.cfg.validation.hash_algorithm, crypto.randomBytes(32).toString('base64'))
      .update(amalgam)
      .digest('hex')
    connection.transaction.body.bodytext = create_body(plugin, { hash })

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash does not match'))
    assertNext([code, msg])
  })

  it('will deny when incorrect hash', async () => {
    const hash = crypto
      .createHmac(plugin.cfg.validation.hash_algorithm, crypto.randomBytes(32).toString('base64'))
      .update(amalgam)
      .digest('hex')
    connection.transaction.body.bodytext = create_body(plugin, { hash })

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash does not match'))
    assert.equal(code, DENY)
    assert.equal(msg, 'invalid bounce')
  })

  for (const [field, label] of [
    ['from', 'From'],
    ['date', 'Date'],
    ['message_id', 'Message-ID'],
  ]) {
    it(`is missing the ${label} header`, async () => {
      plugin.cfg.reject.hash_validation = false
      connection.transaction.body.bodytext = create_body(plugin, { omit: [field] })

      const [code, msg] = await call('validate_bounce')
      assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
      assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing headers'))
      assertNext([code, msg])
    })

    it(`will deny when missing the ${label} header`, async () => {
      connection.transaction.body.bodytext = create_body(plugin, { omit: [field] })

      const [code, msg] = await call('validate_bounce')
      assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
      assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing headers'))
      assert.equal(code, DENY)
      assert.equal(msg, 'invalid bounce')
    })
  }

  it('is missing hash header and email address is whitelisted', async () => {
    plugin.cfg.whitelist = { 'test@example.com': ['no-reply@example.com'] }
    connection.transaction.rcpt_to[0] = new Address('test@example.com')
    connection.transaction.add_header('From', '<no-reply@example.com>')
    connection.transaction.body.bodytext = create_body(plugin, { omit: ['hash'] })

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'skip', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'whitelisted'))
    assertNext([code, msg])
  })

  it('is missing hash header and sender domain is whitelisted', async () => {
    plugin.cfg.whitelist = { 'bar@example.com': ['*@example.net'] }
    connection.transaction.rcpt_to[0] = new Address('bar@example.com')
    connection.transaction.add_header('From', '<info@example.net>')
    connection.transaction.body.bodytext = create_body(plugin, { omit: ['hash'] })

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'skip', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'whitelisted'))
    assertNext([code, msg])
  })

  it('is missing hash header and has invalid from header', async () => {
    connection.transaction.add_header('From', '<invalid>')
    connection.transaction.body.bodytext = create_body(plugin, { omit: ['hash'] })

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'skip', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'invalid from header'))
    assertNext([code, msg])
  })

  it('is missing hash header and is not whitelisted', async () => {
    plugin.cfg.reject.hash_validation = false
    connection.transaction.add_header('From', '<info@example.net>')
    connection.transaction.body.bodytext = create_body(plugin, { omit: ['hash'] })

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing validation hash'))
    assertNext([code, msg])
  })

  it('will deny when missing hash header and not whitelisted', async () => {
    connection.transaction.add_header('From', '<info@example.net>')
    connection.transaction.body.bodytext = create_body(plugin, { omit: ['hash'] })

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing validation hash'))
    assert.equal(code, DENY)
    assert.equal(msg, 'invalid bounce')
  })

  it('is missing all headers', async () => {
    connection.transaction.body.bodytext = 'no recognizable headers here'

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'skip', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing all headers'))
    assertNext([code, msg])
  })

  it('will Deny when hash is too old', async () => {
    plugin.cfg.reject.hash_date = true
    const eightDaysAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 8)
    connection.transaction.body.bodytext = create_body(plugin, { date_header: eightDaysAgo.toUTCString() })

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_date'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash is too old'))
    assert.equal(code, DENY)
    assert.equal(msg, 'invalid bounce')
  })

  it('hash is too old', async () => {
    plugin.cfg.reject.hash_date = false
    const eightDaysAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 8)
    connection.transaction.body.bodytext = create_body(plugin, { date_header: eightDaysAgo.toUTCString() })

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_date'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash is too old'))
    assertNext([code, msg])
  })

  it('has invalid date header', async () => {
    plugin.cfg.reject.hash_date = false
    connection.transaction.body.bodytext = create_body(plugin, { date_header: 'invalid date' })

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_date'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'invalid date header'))
    assertNext([code, msg])
  })

  it('will DENY when date header is invalid', async () => {
    connection.transaction.body.bodytext = create_body(plugin, { date_header: 'invalid date' })

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_date'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'invalid date header'))
    assert.equal(code, DENY)
    assert.equal(msg, 'invalid bounce')
  })
})

describe('lib/validation findBounceHeaders', () => {
  let date_header, from_header, message_id, hash, amalgam
  let msg_body, transaction

  beforeEach(() => {
    date_header = new Date().toISOString()
    from_header = '<test@EXAMPLE.com>'
    message_id = '<test@example.COM>'

    plugin.cfg.validation = {
      hash_algorithm: 'sha256',
      secret: crypto.randomBytes(32).toString('base64'),
    }

    amalgam = `${from_header}:${date_header}:${message_id}`
    hash = crypto
      .createHmac(plugin.cfg.validation.hash_algorithm, plugin.cfg.validation.secret)
      .update(amalgam)
      .digest('hex')

    msg_body = `
X-Haraka-Bounce-Validation: ${hash}
From: ${from_header}
Date: ${date_header}
Message-ID: ${message_id}
`
    transaction = connection.transaction

    transaction.body = {
      bodytext: msg_body,
      children: [],
    }
  })

  it('has no body', () => {
    delete transaction.body

    const headers = validationLib.findBounceHeaders(transaction.body)

    assert.equal(JSON.stringify(headers), '{}')
  })

  it('has all headers in body', () => {
    const headers = validationLib.findBounceHeaders(transaction.body)

    assert.equal(headers.from, from_header)
    assert.equal(headers.date, date_header)
    assert.equal(headers.message_id, message_id)
    assert.equal(headers.hash, hash)
  })

  it('has From header in body', () => {
    transaction.body.bodytext = `From: ${from_header}\n`

    const headers = validationLib.findBounceHeaders(transaction.body)

    assert.equal(headers.from, from_header)
    assert.equal(headers.date, undefined)
    assert.equal(headers.message_id, undefined)
    assert.equal(headers.hash, undefined)
  })

  it('has Date header in body', () => {
    transaction.body.bodytext = `Date: ${date_header}\n`

    const headers = validationLib.findBounceHeaders(transaction.body)

    assert.equal(headers.from, undefined)
    assert.equal(headers.date, date_header)
    assert.equal(headers.message_id, undefined)
    assert.equal(headers.hash, undefined)
  })

  it('has one header in body', () => {
    transaction.body.bodytext = `Date: ${date_header}\n`

    const headers = validationLib.findBounceHeaders(transaction.body)

    assert.equal(headers.from, undefined)
    assert.equal(headers.date, date_header)
    assert.equal(headers.message_id, undefined)
    assert.equal(headers.hash, undefined)
  })

  it('has no headers in body', () => {
    transaction.body = {
      bodytext: 'no headers in this body',
      children: [],
    }

    const headers = validationLib.findBounceHeaders(transaction.body)

    assert.equal(headers.from, undefined)
    assert.equal(headers.date, undefined)
    assert.equal(headers.message_id, undefined)
    assert.equal(headers.hash, undefined)
  })

  it('has headers in body.children', () => {
    transaction.body = {
      bodytext: 'Hello World',
      children: [{ bodytext: msg_body }],
    }

    const headers = validationLib.findBounceHeaders(transaction.body)

    assert.equal(headers.from, from_header)
    assert.equal(headers.date, date_header)
    assert.equal(headers.message_id, message_id)
    assert.equal(headers.hash, hash)
  })

  it('has folded headers', () => {
    from_header = `"Dr. Smith - Back & Neck Care Center of San Fransisco" <dr.smith@example.com>`
    hash = crypto
      .createHmac(plugin.cfg.validation.hash_algorithm, plugin.cfg.validation.secret)
      .update(amalgam)
      .digest('hex')

    transaction.body.bodytext = `
Message-ID: ${message_id}
Date: ${date_header}
From: "Dr. Smith - Back & Neck Care Center of San Fransisco"
  <dr.smith@example.com>
X-Haraka-Bounce-Validation: ${hash}
`
    const headers = validationLib.findBounceHeaders(transaction.body)

    assert.equal(headers.from, from_header)
    assert.equal(headers.date, date_header)
    assert.equal(headers.message_id, message_id)
    assert.equal(headers.hash, hash)
  })
})

describe('lib/validation computeHash', () => {
  const headers = { from: 'a', date: 'b', message_id: 'c' }

  it('is a stable HMAC over from:date:message_id', () => {
    const hash = validationLib.computeHash('sha256', 'secret', headers)
    assert.equal(hash, validationLib.computeHash('sha256', 'secret', headers))
    assert.equal(hash, crypto.createHmac('sha256', 'secret').update('a:b:c').digest('hex'))
  })

  it('changes when a header changes', () => {
    const a = validationLib.computeHash('sha256', 'secret', headers)
    const b = validationLib.computeHash('sha256', 'secret', { ...headers, message_id: 'd' })
    assert.notEqual(a, b)
  })
})

describe('lib/validation compareHash', () => {
  it('matches identical hashes', () => {
    assert.deepEqual(validationLib.compareHash('abcdef', 'abcdef'), { match: true })
  })

  it('reports a mismatch for same-length hashes', () => {
    const result = validationLib.compareHash('abcdef', 'abcxyz')
    assert.equal(result.match, false)
    assert.equal(result.msg, 'hash does not match')
  })

  it('reports a length mismatch', () => {
    const result = validationLib.compareHash('abcdef', 'abc')
    assert.equal(result.match, false)
    assert.equal(result.msg, 'hash length mismatch')
  })

  it('does not match a longer actual that shares the full prefix', () => {
    const result = validationLib.compareHash('abcdef', 'abcdefXYZ')
    assert.equal(result.match, false)
    assert.equal(result.msg, 'hash length mismatch')
  })

  it('handles a multibyte actual of equal string length without throwing', () => {
    const result = validationLib.compareHash('abcdef', 'abcdeé')
    assert.equal(result.match, false)
    assert.equal(result.msg, 'hash length mismatch')
  })
})

describe('lib/validation isDateValid', () => {
  it('accepts a recent date', () => {
    const date = new Date(new Date() - 1000 * 60 * 60 * 24).toUTCString()
    assert.ok(validationLib.isDateValid(date, 6).valid)
  })

  it('rejects an expired date', () => {
    const date = new Date(new Date() - 1000 * 60 * 60 * 24 * 7).toUTCString()
    const result = validationLib.isDateValid(date, 6)
    assert.equal(result.valid, false)
    assert.equal(result.msg, 'hash is too old')
  })

  it('rejects an unparseable date', () => {
    const result = validationLib.isDateValid('hello world', 6)
    assert.equal(result.valid, false)
    assert.equal(result.msg, 'invalid date header')
  })
})

describe('lib/validation isWhitelisted', () => {
  it('is not whitelisted', () => {
    assert.equal(validationLib.isWhitelisted({}, 'test@example.com', 'support@example.com'), false)
  })

  it('is whitelisted with an exact match', () => {
    const whitelist = { 'test@example.com': ['support@example.com'] }
    assert.ok(validationLib.isWhitelisted(whitelist, 'test@example.com', 'support@example.com'))
  })

  it('is whitelisted with a wildcard match', () => {
    const whitelist = { 'test@example.com': ['support@example.net', '*@example.com'] }
    assert.ok(validationLib.isWhitelisted(whitelist, 'test@example.com', 'support@example.com'))
  })
})

describe('lib/validation verify', () => {
  const secret = crypto.randomBytes(32).toString('base64')

  const opts = (over = {}) => ({
    algorithm: 'sha256',
    secret,
    maxAgeDays: 6,
    whitelist: {},
    rcpt: 'test@example.com',
    fromHeader: '<sender@example.com>',
    ...over,
  })

  const baseHeaders = () => ({
    from: '<sender@example.com>',
    date: new Date().toISOString(),
    message_id: '<mid@example.com>',
  })

  const hashFor = (headers) => validationLib.computeHash('sha256', secret, headers)

  it('passes a valid hash with a recent date', () => {
    const headers = baseHeaders()
    const verdict = validationLib.verify({ ...headers, hash: hashFor(headers) }, opts())
    assert.deepEqual(verdict, { type: 'pass' })
  })

  it('fails a mismatched hash, rejectable via hash_validation', () => {
    const verdict = validationLib.verify({ ...baseHeaders(), hash: 'a'.repeat(64) }, opts())
    assert.equal(verdict.type, 'fail')
    assert.equal(verdict.value, 'validate_bounce')
    assert.equal(verdict.rejectOn, 'hash_validation')
    assert.equal(verdict.msg, 'hash does not match')
  })

  it('fails an expired hash via hash_date', () => {
    const headers = { ...baseHeaders(), date: new Date(new Date() - 1000 * 60 * 60 * 24 * 8).toUTCString() }
    const verdict = validationLib.verify({ ...headers, hash: hashFor(headers) }, opts())
    assert.equal(verdict.type, 'fail')
    assert.equal(verdict.value, 'bounce_date')
    assert.equal(verdict.rejectOn, 'hash_date')
    assert.equal(verdict.msg, 'hash is too old')
  })

  it('fails when a hash is present but a header is missing', () => {
    const { from, date } = baseHeaders()
    const verdict = validationLib.verify({ from, date, hash: 'x' }, opts())
    assert.equal(verdict.type, 'fail')
    assert.equal(verdict.msg, 'missing headers')
  })

  it('skips a whitelisted unhashed bounce', () => {
    const whitelist = { 'test@example.com': ['sender@example.com'] }
    const verdict = validationLib.verify(baseHeaders(), opts({ whitelist }))
    assert.deepEqual(verdict, { type: 'skip', msg: 'whitelisted' })
  })

  it('fails an unhashed bounce that is not whitelisted', () => {
    const verdict = validationLib.verify(baseHeaders(), opts())
    assert.equal(verdict.type, 'fail')
    assert.equal(verdict.msg, 'missing validation hash')
    assert.equal(verdict.rejectOn, 'hash_validation')
  })

  it('skips an unparseable From header', () => {
    const verdict = validationLib.verify(baseHeaders(), opts({ fromHeader: '<invalid>' }))
    assert.equal(verdict.type, 'skip')
    assert.equal(verdict.msg, 'invalid from header')
    assert.ok(verdict.parseError)
  })

  it('skips when no headers are present', () => {
    assert.deepEqual(validationLib.verify({}, opts()), { type: 'skip', msg: 'missing all headers' })
  })
})

// Builds bounce body text that the real find_bounce_headers() parses.
// options.omit lists header fields (from, date, message_id, hash) to leave out.
function create_body(plugin, options = {}) {
  const date_header = options.date_header || new Date().toISOString()
  const from_header = options.from_header || '<test@example.com>'
  const message_id = options.message_id || '<test@example.com>'
  const omit = options.omit ?? []

  let hash = options.hash
  if (!hash) {
    const amalgam = `${from_header}:${date_header}:${message_id}`
    hash = crypto
      .createHmac(plugin.cfg.validation.hash_algorithm, plugin.cfg.validation.secret)
      .update(amalgam)
      .digest('hex')
  }

  const lines = [
    ['hash', `X-Haraka-Bounce-Validation: ${hash}`],
    ['from', `From: ${from_header}`],
    ['date', `Date: ${date_header}`],
    ['message_id', `Message-ID: ${message_id}`],
  ]
    .filter(([field]) => !omit.includes(field))
    .map(([, line]) => line)

  return `\n${lines.join('\n')}\n`
}
