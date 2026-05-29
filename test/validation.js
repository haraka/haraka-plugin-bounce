'use strict'

const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const { describe, it, beforeEach, afterEach } = require('node:test')
const sinon = require('sinon')

const { Address } = require('@haraka/email-address')
const { callHook, makeConnection, makePlugin } = require('haraka-test-fixtures')

let plugin, connection, should_skip_spy

beforeEach(() => {
  plugin = makePlugin('bounce')
  connection = makeConnection({ ip: '8.8.8.8', mailFrom: '<>', rcptTo: ['test@example.com'] })
  should_skip_spy = sinon.spy(plugin, 'should_skip')
})

afterEach(() => sinon.restore())

const call = async (fn, ...args) => {
  const { rc, msg } = await callHook(plugin, fn, connection, ...args)
  return [rc, msg]
}

const assertNext = ([code, msg]) => {
  assert.equal(code, undefined)
  assert.equal(msg, undefined)
}

describe('create_validation_hash', () => {
  let get_decoded_stub

  beforeEach(() => {
    connection.transaction.body = {
      bodytext: '',
      children: [],
    }
    connection.transaction.parse_body = true
    connection.transaction.mail_from = new Address('<test@example.com>')
    connection.relaying = true
    plugin.cfg.check.hash_validation = true

    get_decoded_stub = sinon.stub(connection.transaction.header, 'get_decoded')
  })

  it('create_validation_hash - missing transaction', async () => {
    delete connection.transaction

    assertNext(await call('empty_return_path'))
  })

  it('should not create validation hash', async () => {
    plugin.cfg.check.hash_validation = false

    const [code, msg] = await call('create_validation_hash')
    sinon.assert.notCalled(get_decoded_stub)
    assertNext([code, msg])
  })

  it('should ignore inbound mail', async () => {
    connection.relaying = false

    const [code, msg] = await call('create_validation_hash')
    sinon.assert.notCalled(get_decoded_stub)
    assertNext([code, msg])
  })

  it('should skip outbound with null sender', async () => {
    connection.transaction.mail_from = new Address('<>')
    connection.relaying = true
    connection.transaction.results.add(plugin, { isa: 'yes' })

    const [code, msg] = await call('create_validation_hash')
    sinon.assert.notCalled(get_decoded_stub)
    assertNext([code, msg])
  })

  it('missing Message-ID header', async () => {
    const date_header = new Date().toISOString()
    const from_header = '<test@example.com>'

    connection.transaction.add_header('From', from_header)
    connection.transaction.add_header('Date', date_header)

    const [code, msg] = await call('create_validation_hash')
    sinon.assert.calledThrice(get_decoded_stub)
    assertNext([code, msg])
  })

  it('missing From, Date, and Message-ID headers', async () => {
    const [code, msg] = await call('create_validation_hash')
    sinon.assert.calledThrice(get_decoded_stub)
    assertNext([code, msg])
  })

  it('should create a validation hash', async () => {
    const date_header = new Date().toISOString()
    const from_header = '<test@example.com>'
    const message_id = '<test@example.COM>'

    connection.transaction.add_header('From', from_header)
    connection.transaction.add_header('Date', date_header)
    connection.transaction.add_header('Message-ID', message_id)

    const [code, msg] = await call('create_validation_hash')
    sinon.assert.calledThrice(get_decoded_stub)
    assertNext([code, msg])
  })
})

describe('validate_bounce', () => {
  let find_bounce_headers_stub
  let hash, amalgam
  let date_header, from_header, message_id

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

    connection.transaction.body = {
      bodytext: '',
      children: [],
    }

    date_header = new Date().toISOString()
    from_header = '<test@example.com>'
    message_id = '<test@example.com>'

    amalgam = `${from_header}:${date_header}:${message_id}`
    hash = crypto
      .createHmac(plugin.cfg.validation.hash_algorithm, plugin.cfg.validation.secret)
      .update(amalgam)
      .digest('hex')

    find_bounce_headers_stub = sinon.stub(plugin, 'find_bounce_headers')
  })

  it('validate_bounce - missing transaction', async () => {
    delete connection.transaction

    assertNext(await call('empty_return_path'))
  })

  it('should skip validation check', async () => {
    plugin.cfg.check.hash_validation = false

    const [code, msg] = await call('validate_bounce')
    assert.ok(should_skip_spy.notCalled)
    assertNext([code, msg])
  })

  it('has hash size that is too short', async () => {
    hash = '1234567890'

    const headers = create_headers(plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    plugin.cfg.reject.hash_validation = false

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash length mismatch'))
    assert(find_bounce_headers_stub.calledOnce)
    assert(find_bounce_headers_stub.calledWith(connection.transaction, connection.transaction.body))
    assertNext([code, msg])
  })

  it('has hash size that is too long', async () => {
    plugin.cfg.reject.hash_validation = false

    const hash = '1234567890123456789012345678901234567890123456789012345678901234567890'

    const headers = create_headers(plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash length mismatch'))
    assertNext([code, msg])
  })

  it('will reject if wrong hash size', async () => {
    const hash = '1234567890'

    const headers = create_headers(plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash length mismatch'))
    assert.equal(code, DENY)
    assert.equal(msg, 'invalid bounce')
  })

  it('is a valid inbound bounce', async () => {
    const headers = create_headers(plugin)
    find_bounce_headers_stub.returns(headers)

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'pass', 'validate_bounce'))
    assert(find_bounce_headers_stub.calledOnce)
    assert(find_bounce_headers_stub.calledWith(connection.transaction, connection.transaction.body))
    assertNext([code, msg])
  })

  it('has incorrect hash', async () => {
    plugin.cfg.reject.hash_validation = false

    hash = crypto
      .createHmac(plugin.cfg.validation.hash_algorithm, crypto.randomBytes(32).toString('base64'))
      .update(amalgam)
      .digest('hex')

    const headers = create_headers(plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash does not match'))
    assertNext([code, msg])
  })

  it('will deny when incorrect hash', async () => {
    hash = crypto
      .createHmac(plugin.cfg.validation.hash_algorithm, crypto.randomBytes(32).toString('base64'))
      .update(amalgam)
      .digest('hex')

    const headers = create_headers(plugin, { hash })
    find_bounce_headers_stub.returns(headers)

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
      const headers = create_headers(plugin)
      delete headers[field]
      find_bounce_headers_stub.returns(headers)
      const [code, msg] = await call('validate_bounce')
      assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
      assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing headers'))
      assertNext([code, msg])
    })

    it(`will deny when missing the ${label} header`, async () => {
      const headers = create_headers(plugin)
      delete headers[field]
      find_bounce_headers_stub.returns(headers)
      const [code, msg] = await call('validate_bounce')
      assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
      assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing headers'))
      assert.equal(code, DENY)
      assert.equal(msg, 'invalid bounce')
    })
  }

  it.skip('is missing hash header and address parsing fails', async () => {
    const from = 'mail delivery system <mailer-daemon@example.com>'
    const rcpt = new Address('test@example.com')

    plugin.cfg.reject.hash_validation = false
    connection.transaction.rcpt_to[0] = rcpt
    connection.transaction.add_header('From', from)

    const headers = create_headers(plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing validation hash'))
    assertNext([code, msg])
  })

  it.skip('is missing hash header and email address is whitelisted', async () => {
    plugin.cfg.whitelist = { 'test@example.com': ['no-reply@example.com'] }

    const from = '<no-reply@example.com>'
    const rcpt = new Address('test@example.com')

    connection.transaction.rcpt_to[0] = rcpt
    connection.transaction.add_header('From', from)

    const headers = create_headers(plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'skip', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'whitelisted'))
    assertNext([code, msg])
  })

  it.skip('is missing hash header and sender domain is whitelisted', async () => {
    plugin.cfg.whitelist = { 'bar@example.com': ['*@example.net'] }

    const from = '<info@example.net>'
    const rcpt = new Address('bar@example.com')

    connection.transaction.rcpt_to[0] = rcpt
    connection.transaction.add_header('From', from)

    const headers = create_headers(plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'skip', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'whitelisted'))
    assertNext([code, msg])
  })

  it('is missing hash header and has invalid from header', async () => {
    const from = '<invalid>'
    connection.transaction.add_header('From', from)

    const headers = create_headers(plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'skip', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'invalid from header'))
    assertNext([code, msg])
  })

  it.skip('is missing hash header', async () => {
    const from = '<info@example.net>'
    connection.transaction.add_header('From', from)
    plugin.cfg.reject.hash_validation = false

    const headers = create_headers(plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing validation hash'))
    assertNext([code, msg])
  })

  it.skip('will deny when missing hash header', async () => {
    const from = '<info@example.net>'
    connection.transaction.add_header('From', from)

    const headers = create_headers(plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing validation hash'))
    assert.equal(code, DENY)
    assert.equal(msg, 'invalid bounce')
  })

  it('is missing all headers', async () => {
    const headers = {}
    find_bounce_headers_stub.returns(headers)

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'skip', 'validate_bounce'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing all headers'))
    assertNext([code, msg])
  })

  it('will Deny when hash is too old', async () => {
    plugin.cfg.reject.hash_date = true
    const eightDaysAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 8)
    date_header = eightDaysAgo.toUTCString()

    const headers = create_headers(plugin, { date_header })
    find_bounce_headers_stub.returns(headers)

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_date'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash is too old'))
    assert(find_bounce_headers_stub.calledOnce)
    assert(find_bounce_headers_stub.calledWith(connection.transaction, connection.transaction.body))
    assert.equal(code, DENY)
    assert.equal(msg, 'invalid bounce')
  })

  it('hash is too old', async () => {
    plugin.cfg.reject.hash_date = false
    const eightDaysAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 8)
    date_header = eightDaysAgo.toUTCString()

    const headers = create_headers(plugin, { date_header })
    find_bounce_headers_stub.returns(headers)

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_date'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash is too old'))
    assert(find_bounce_headers_stub.calledOnce)
    assert(find_bounce_headers_stub.calledWith(connection.transaction, connection.transaction.body))
    assertNext([code, msg])
  })

  it('has invalid date header', async () => {
    plugin.cfg.reject.hash_date = false
    date_header = 'invalid date'

    const headers = create_headers(plugin, { date_header })
    find_bounce_headers_stub.returns(headers)

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_date'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'invalid date header'))
    assertNext([code, msg])
  })

  it('will DENY when date header is invalid', async () => {
    date_header = 'invalid date'

    const headers = create_headers(plugin, { date_header })
    find_bounce_headers_stub.returns(headers)

    const [code, msg] = await call('validate_bounce')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_date'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'invalid date header'))
    assert.equal(code, DENY)
    assert.equal(msg, 'invalid bounce')
  })
})

describe('find_bounce_headers', () => {
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

    const headers = plugin.find_bounce_headers(transaction.body)

    assert.equal(JSON.stringify(headers), '{}')
  })

  it('has all headers in body', () => {
    const headers = plugin.find_bounce_headers(transaction.body)

    assert.equal(headers.from, from_header)
    assert.equal(headers.date, date_header)
    assert.equal(headers.message_id, message_id)
    assert.equal(headers.hash, hash)
  })

  it('has From header in body', () => {
    transaction.body.bodytext = `From: ${from_header}\n`

    const headers = plugin.find_bounce_headers(transaction.body)

    assert.equal(headers.from, from_header)
    assert.equal(headers.date, undefined)
    assert.equal(headers.message_id, undefined)
    assert.equal(headers.hash, undefined)
  })

  it('has Date header in body', () => {
    transaction.body.bodytext = `Date: ${date_header}\n`

    const headers = plugin.find_bounce_headers(transaction.body)

    assert.equal(headers.from, undefined)
    assert.equal(headers.date, date_header)
    assert.equal(headers.message_id, undefined)
    assert.equal(headers.hash, undefined)
  })

  it('has one header in body', () => {
    transaction.body.bodytext = `Date: ${date_header}\n`

    const headers = plugin.find_bounce_headers(transaction.body)

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

    const headers = plugin.find_bounce_headers(transaction.body)

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

    const headers = plugin.find_bounce_headers(transaction.body)

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
    const headers = plugin.find_bounce_headers(transaction.body)

    assert.equal(headers.from, from_header)
    assert.equal(headers.date, date_header)
    assert.equal(headers.message_id, message_id)
    assert.equal(headers.hash, hash)
  })
})

function create_headers(plugin, options = {}) {
  const date_header = options.date_header || new Date().toISOString()
  const from_header = options.from_header || '<test@example.com>'
  const message_id = options.message_id || '<test@example.com>'

  let hash = options.hash
  if (!hash) {
    const amalgam = `${from_header}:${date_header}:${message_id}`
    hash = crypto
      .createHmac(plugin.cfg.validation.hash_algorithm, plugin.cfg.validation.secret)
      .update(amalgam)
      .digest('hex')
  }

  return {
    from: from_header,
    date: date_header,
    message_id: message_id,
    hash: hash,
  }
}
