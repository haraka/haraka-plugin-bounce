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
})

afterEach(() => sinon.restore())

const call = (fn, ...args) =>
  new Promise((resolve) => plugin[fn]((code, msg) => resolve([code, msg]), connection, ...args))

const assertNext = ([code, msg]) => {
  assert.equal(code, undefined)
  assert.equal(msg, undefined)
}

describe('reject_all', () => {
  beforeEach(() => {
    plugin.cfg.reject.all_bounces = true
  })

  it('will allow bounces', async () => {
    plugin.cfg.reject.all_bounces = false
    const [code, msg] = await call('reject_all')
    assert.ok(should_skip_spy.notCalled)
    assertNext([code, msg])
  })

  it('reject_all - missing transaction', async () => {
    delete connection.transaction

    assertNext(await call('empty_return_path'))
  })

  it('will ignore outbound mail', async () => {
    connection.relaying = true

    const [code, msg] = await call('reject_all')
    assert.ok(should_skip_spy.returned(true))
    assertNext([code, msg])
  })

  it('will ignore non-bounce mail', async () => {
    connection.transaction.mail_from = new Address('<test@example.com>')
    connection.transaction.results.add(plugin, { isa: 'no' })
    const [code, msg] = await call('reject_all')
    assert.ok(should_skip_spy.returned(true))
    assertNext([code, msg])
  })

  it('will reject all bounces', async () => {
    const [code, msg] = await call('reject_all')
    assert.ok(should_skip_spy.returned(false))
    connection.transaction.results.has(plugin, 'fail', 'bounces_accepted')
    connection.transaction.results.has(plugin, 'msg', 'bounces not accepted here')
    assert.equal(code, DENY)
    assert.equal(msg, 'Bounces not accepted here')
  })
})

describe('empty_return_path', () => {
  beforeEach(() => {
    plugin.cfg.check.empty_return_path = true
    plugin.cfg.reject.empty_return_path = true
  })

  it('empty_return_path - missing transaction', async () => {
    delete connection.transaction

    const [code, msg] = await call('empty_return_path')
    assert.ok(should_skip_spy.notCalled)
    assertNext([code, msg])
  })

  it('should ignore empty_return_path', async () => {
    plugin.cfg.check.empty_return_path = false

    const [code, msg] = await call('empty_return_path')
    assert.ok(should_skip_spy.notCalled)
    assertNext([code, msg])
  })

  it('missing Return-Path header', async () => {
    const [code, msg] = await call('empty_return_path')
    assert.ok(should_skip_spy.returned(false))
    assert.ok(connection.transaction.results.has(plugin, 'pass', 'empty_return_path'))
    assertNext([code, msg])
  })

  it('has empty Return-Path header', async () => {
    connection.transaction.add_header('Return-Path', '')
    const [code, msg] = await call('empty_return_path')
    assert.ok(should_skip_spy.returned(false))
    assert.ok(connection.transaction.results.has(plugin, 'pass', 'empty_return_path'))
    assertNext([code, msg])
  })

  it('will allow non-empty Return-Path header', async () => {
    connection.transaction.add_header('Return-Path', 'Hello World!')

    plugin.cfg.reject.empty_return_path = false

    const [code, msg] = await call('empty_return_path')
    assert.ok(should_skip_spy.returned(false))
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'empty_return_path'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'bounce with non-empty Return-Path'))
    assertNext([code, msg])
  })

  it('will reject non-empty Return-Path header', async () => {
    connection.transaction.add_header('Return-Path', 'Hello World!')

    const [code, msg] = await call('empty_return_path')
    assert.ok(should_skip_spy.returned(false))
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'empty_return_path'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'bounce with non-empty Return-Path'))
    assert.equal(code, DENY)
    assert.equal(msg, 'bounce with non-empty Return-Path (RFC 3834)')
  })
})

describe('single_recipient', () => {
  it('single_recipient - missing transaction', async () => {
    delete connection.transaction

    assertNext(await call('empty_return_path'))
  })

  it('will not check for single recipient', async () => {
    plugin.cfg.check.single_recipient = false
    const [code, msg] = await call('single_recipient')
    assert.ok(should_skip_spy.notCalled)
    assertNext([code, msg])
  })

  it('has single recipient', async () => {
    const [code, msg] = await call('single_recipient')
    assert.ok(connection.transaction.results.has(plugin, 'pass', 'single_recipient'))
    assert.ok(should_skip_spy.calledOnce)
    assertNext([code, msg])
  })

  it('will allow multiple recipients', async () => {
    plugin.cfg.reject.single_recipient = false
    connection.transaction.rcpt_to.push(new Address('test2@example.com'))
    const [code, msg] = await call('single_recipient')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'single_recipient'))
    assert.ok(should_skip_spy.calledOnce)
    assertNext([code, msg])
  })

  it('will reject multiple recipients', async () => {
    connection.transaction.rcpt_to.push(new Address('test2@example.com'))
    const [code, msg] = await call('single_recipient')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'single_recipient'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'too many recipients'))
    assert.ok(should_skip_spy.calledOnce)
    assert.equal(code, DENY)
    assert.equal(msg, 'this bounce message has too many recipients')
  })
})

describe('bad_rcpt', () => {
  beforeEach(() => {
    plugin.cfg.invalid_addrs = ['bad1@example.com', 'bad2@example.com']
  })

  it('will not check for bad recipient', async () => {
    plugin.cfg.reject.bad_rcpt = false

    const [code, msg] = await call('reject_all', [new Address('<>')])
    assert.ok(should_skip_spy.notCalled)
    assertNext([code, msg])
  })

  it('bad_rcpt - missing transaction', async () => {
    delete connection.transaction

    const [code, msg] = await call('empty_return_path')
    assert.ok(should_skip_spy.notCalled)
    assertNext([code, msg])
  })

  it('will check for valid recipient', async () => {
    plugin.cfg.invalid_addrs = []
    const rcpt = new Address('test@example.com')
    const [code, msg] = await call('bad_rcpt', rcpt)
    assert.ok(connection.transaction.results.has(plugin, 'pass', 'bad_rcpt'))
    assert.ok(should_skip_spy.calledOnce)
    assertNext([code, msg])
  })

  it('will check for invalid recipient', async () => {
    const rcpt = new Address('bad1@example.com')
    const [code, msg] = await call('bad_rcpt', rcpt)
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'bad_rcpt'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'rcpt does not accept bounces'))
    assert.ok(should_skip_spy.calledOnce)
    assert.equal(code, DENY)
    assert.equal(msg, `${rcpt.address} does not accept bounces`)
  })
})
