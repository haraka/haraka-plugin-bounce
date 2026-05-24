'use strict'

const assert = require('node:assert/strict')
const { describe, it, beforeEach, afterEach } = require('node:test')
const sinon = require('sinon')

const { Address } = require('@haraka/email-address')
const fixtures = require('haraka-test-fixtures')

let plugin, connection, should_skip_spy

beforeEach(() => {
  plugin = new fixtures.plugin('bounce')
  connection = fixtures.connection.createConnection()
  connection.remote.ip = '8.8.8.8'
  connection.relaying = false
  connection.init_transaction()
  connection.transaction.mail_from = new Address('<>')
  connection.transaction.rcpt_to.push(new Address('test@example.com'))
  plugin.register()
  should_skip_spy = sinon.spy(plugin, 'should_skip')
  void should_skip_spy
})

afterEach(() => sinon.restore())

describe('should_skip', () => {
  it('is relaying and is not a bounce', () => {
    connection.transaction.mail_from = new Address('<test@example.com>')
    connection.relaying = true
    connection.transaction.results.add(plugin, { isa: 'no' })

    assert.equal(plugin.should_skip(connection), true)
  })

  it('is relaying and is a bounce', () => {
    connection.relaying = true
    connection.transaction.results.add(plugin, { isa: 'yes' })

    assert.equal(plugin.should_skip(connection), true)
  })

  it('is not relaying and is not a bounce', () => {
    connection.transaction.mail_from = new Address('<test@example.com>')
    connection.relaying = false
    connection.transaction.results.add(plugin, { isa: 'no' })

    assert.equal(plugin.should_skip(connection), true)
  })

  it('is not relaying and is a bounce', () => {
    connection.relaying = false
    connection.transaction.results.add(plugin, { isa: 'yes' })

    assert.equal(plugin.should_skip(connection), false)
  })
})

describe('find_received_headers', () => {
  beforeEach(() => {
    connection.transaction.body = { bodytext: '', children: [] }
  })

  it('has no Received headers', () => {
    const ips = plugin.find_received_headers(connection.transaction.body)

    assert.equal(ips.size, 0)
  })

  it('has one Received header', () => {
    const ip = '209.85.128.52'
    const received_headers = `Received: from example.com (example.com [${ip}])`
    connection.transaction.body.bodytext = received_headers

    const ips = plugin.find_received_headers(connection.transaction.body)

    assert.equal(ips.size, 1)
    assert.ok(ips.has(ip))
  })

  it('has two Received headers with one private IP', () => {
    const ip1 = '10.10.10.10'
    const ip2 = '209.85.128.52'
    const received_headers = `
Received: from mx (mx.example.com [${ip1}])
Received: from mail.example.com (HELO mail.example.com) (${ip2})
`
    connection.transaction.body.bodytext = received_headers

    const ips = plugin.find_received_headers(connection.transaction.body)

    assert.equal(ips.size, 1)
    assert.ok(ips.has(ip2))
  })

  it('has two Received headers with public IPs', () => {
    const ip1 = '108.177.12.26'
    const ip2 = '209.85.128.52'
    const received_headers = `
Received: from mx (mx.example.com [${ip1}])
Received: from mail.example.com (mail.example.com [${ip2}])
`
    connection.transaction.body.bodytext = received_headers

    const ips = plugin.find_received_headers(connection.transaction.body)

    assert.equal(ips.size, 2)
    assert.ok(ips.has(ip1))
    assert.ok(ips.has(ip2))
  })

  it('has two Received headers with IPv4 and IPv6 IPs', () => {
    const ip1 = '108.177.12.26'
    const ip2 = '2603:10b6:8:189::16'
    const ip3 = '2603:10b6:303:e9::7'
    const received_headers = `
Received: from mx (mx.example.com [${ip1}])
Received: from prod.example.com
 ([${ip2}]) by prod.example.com (${ip3})
`
    connection.transaction.body.bodytext = received_headers

    const ips = plugin.find_received_headers(connection.transaction.body)

    assert.equal(ips.size, 2)
    assert.ok(ips.has(ip1))
    assert.ok(ips.has(ip2))
  })

  it('has Received headers in child', () => {
    const ip1 = '108.177.12.26'
    const ip2 = '209.85.128.52'
    const received_headers = `
Received: from mx (mx.example.com [${ip1}])
Received: from mail.example.com (mail.example.com [${ip2}])
`
    connection.transaction.body.children[0] = {
      bodytext: received_headers,
      children: [],
    }
    const ips = plugin.find_received_headers(connection.transaction.body)

    assert.equal(ips.size, 2)
    assert.ok(ips.has(ip1))
    assert.ok(ips.has(ip2))
  })

  it('has Received headers in both parent body and child (regex state-leak regression)', () => {
    const parent_ip = '108.177.12.26'
    const child_ip = '209.85.128.52'

    connection.transaction.body.bodytext = `Received: from mx (mx.example.com [${parent_ip}])`
    connection.transaction.body.children[0] = {
      bodytext: `Received: from mail.example.com (mail.example.com [${child_ip}])`,
      children: [],
    }

    const ips = plugin.find_received_headers(connection.transaction.body)

    assert.equal(ips.size, 2)
    assert.ok(ips.has(parent_ip))
    assert.ok(ips.has(child_ip))
  })
})

describe('is_date_valid', () => {
  beforeEach(() => {
    plugin.cfg.validation.max_hash_age_days = 6
  })

  it('has recent date', () => {
    const oneDayAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 1)
    const date_header = oneDayAgo.toUTCString()

    const result = plugin.is_date_valid(date_header)
    assert(result.valid)
  })

  it('has expired date', () => {
    const SevenDaysAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 7)
    const date_header = SevenDaysAgo.toUTCString()
    const result = plugin.is_date_valid(date_header)
    assert.equal(result.valid, false)
    assert.equal(result.msg, 'hash is too old')
  })

  it('has invalid date', () => {
    const not_a_date = 'hello world'
    const result = plugin.is_date_valid(not_a_date)
    assert.equal(result.valid, false)
    assert.equal(result.msg, 'invalid date header')
  })
})

describe('is_whitelisted', () => {
  it('is not whitelisted', () => {
    plugin.cfg.whitelist = {}

    const whitelisted = plugin.is_whitelisted('test@example.com', 'support@example.com')

    assert.equal(whitelisted, false)
  })

  it('is whitelisted with an exact match', () => {
    plugin.cfg.whitelist = { 'test@example.com': ['support@example.com'] }

    const whitelisted = plugin.is_whitelisted('test@example.com', 'support@example.com')

    assert.ok(whitelisted)
  })

  it('is whitelisted with a wildcard match', () => {
    plugin.cfg.whitelist = {
      'test@example.com': ['support@example.net', '*@example.com'],
    }

    const whitelisted = plugin.is_whitelisted('test@example.com', 'support@example.com')

    assert.ok(whitelisted)
  })
})
