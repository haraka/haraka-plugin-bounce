'use strict'

const assert = require('node:assert/strict')
const { describe, it, beforeEach, afterEach } = require('node:test')
const sinon = require('sinon')

const { Address } = require('address-rfc2821')
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

describe('check_null_sender', () => {
  it('has null sender', async () => {
    assertNext(await call('check_null_sender'))
    assert.ok(connection.transaction.results.has(plugin, 'isa', 'yes'))
  })

  it('has empty string sender', async () => {
    connection.transaction.mail_from = new Address('')
    assertNext(await call('check_null_sender'))
    assert.ok(connection.transaction.results.has(plugin, 'isa', 'yes'))
  })

  it('is not a null sender', async () => {
    connection.transaction.mail_from = new Address('user@example.com')
    assertNext(await call('check_null_sender'))
    assert.ok(connection.transaction.results.has(plugin, 'isa', 'no'))
  })
})

describe('bounce_spf_enable', () => {
  it('bounce_spf_enable - missing transaction', async () => {
    delete connection.transaction

    assertNext(await call('empty_return_path'))
  })

  it('is outbound mail', async () => {
    connection.relaying = true

    const [code, msg] = await call('bounce_spf_enable')
    assert.equal(connection.transaction.parse_body, false)
    assertNext([code, msg])
  })

  it('is inbound mail', async () => {
    connection.relaying = false

    const [code, msg] = await call('bounce_spf_enable')
    assert.equal(connection.transaction.parse_body, true)
    assertNext([code, msg])
  })
})

describe('bounce_spf', () => {
  const { SPF } = require('haraka-plugin-spf')

  let check_host_stub, find_received_headers_stub
  let spf

  beforeEach(() => {
    connection.transaction.body = {
      bodytext: `Received: from example.com (example.com [96.7.128.198])`,
      children: [],
    }
    connection.transaction.parse_body = true
    connection.transaction.mail_from = new Address('<>')

    plugin.cfg.reject.bounce_spf = true

    check_host_stub = sinon.stub(SPF.prototype, 'check_host')
    find_received_headers_stub = sinon.stub(plugin, 'find_received_headers')

    spf = new SPF()
  })

  it('bounce_spf - missing transaction', async () => {
    delete connection.transaction

    assertNext(await call('empty_return_path'))
  })

  it('skip SPF check', async () => {
    plugin.cfg.check.bounce_spf = false

    const [code, msg] = await call('bounce_spf')
    assert.ok(should_skip_spy.notCalled)
    assertNext([code, msg])
  })

  it('will skip outbound mail', async () => {
    connection.relaying = true

    const [code, msg] = await call('bounce_spf')
    assert.ok(should_skip_spy.calledOnce)
    assert.ok(find_received_headers_stub.notCalled)
    assertNext([code, msg])
  })

  it('will skip when not a null sender', async () => {
    connection.transaction.mail_from = new Address('<test@example.com>')
    connection.transaction.results.add(plugin, { isa: 'no' })

    const [code, msg] = await call('bounce_spf')
    assert.ok(should_skip_spy.calledOnce)
    assert.ok(find_received_headers_stub.notCalled)
    assertNext([code, msg])
  })

  it('will skip when hash validation passed', async () => {
    connection.transaction.results.add(plugin, {
      pass: 'validate_bounce',
    })

    const [code, msg] = await call('bounce_spf')
    assert.ok(should_skip_spy.calledOnce)
    assert.ok(find_received_headers_stub.notCalled)
    assertNext([code, msg])
  })

  it('no IPs', async () => {
    connection.transaction.body.bodytext = ''

    find_received_headers_stub.returns(new Set())
    const [code, msg] = await call('bounce_spf')
    assert.ok(connection.transaction.results.get(plugin, 'isa', true))
    assert(find_received_headers_stub.calledOnce)
    assert(find_received_headers_stub.calledWith(connection.transaction.body))
    assert.ok(connection.transaction.results.has(plugin, 'skip', 'bounce_spf'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'no IP addresses found in message'))
    assert.ok(check_host_stub.notCalled)
    assertNext([code, msg])
  })

  it('has multiple IPs - 1st IP fails, 2nd IP passes', async () => {
    connection.transaction.body.bodytext = 'filler'

    find_received_headers_stub.returns(new Set('1.2.3.4', '5.6.7.8'))
    check_host_stub.returns(spf.SPF_FAIL).returns(spf.SPF_PASS)

    const [code, msg] = await call('bounce_spf')
    assert(find_received_headers_stub.calledOnce)
    assert.ok(connection.transaction.results.get(plugin, 'isa', true))
    assert(find_received_headers_stub.calledWith(connection.transaction.body))
    assert.ok(connection.transaction.results.has(plugin, 'pass', 'bounce_spf'))
    assert.ok(check_host_stub.calledOnce)
    assertNext([code, msg])
  })

  for (const { name, result, type, resultMsg, deny } of [
    { name: 'TEMPERROR', result: 'SPF_TEMPERROR', type: 'skip', resultMsg: 'SPF returned TempError', deny: false },
    { name: 'PERMERROR', result: 'SPF_PERMERROR', type: 'skip', resultMsg: 'SPF returned PermError', deny: false },
    { name: 'NONE', result: 'SPF_NONE', type: 'skip', resultMsg: 'SPF returned None', deny: false },
    { name: 'PASS', result: 'SPF_PASS', type: 'pass', resultMsg: null, deny: false },
    { name: 'NEUTRAL', result: 'SPF_NEUTRAL', type: 'fail', resultMsg: 'invalid bounce (spoofed sender)', deny: true },
    {
      name: 'SOFTFAIL',
      result: 'SPF_SOFTFAIL',
      type: 'fail',
      resultMsg: 'invalid bounce (spoofed sender)',
      deny: true,
    },
    { name: 'FAIL', result: 'SPF_FAIL', type: 'fail', resultMsg: 'invalid bounce (spoofed sender)', deny: true },
  ]) {
    it(`SPF_${name}`, async () => {
      find_received_headers_stub.returns(new Set().add('1.2.3.4'))
      check_host_stub.returns(spf[result])
      const [code, msg] = await call('bounce_spf')
      assert.ok(check_host_stub.calledOnce)
      assert.ok(connection.transaction.results.has(plugin, type, 'bounce_spf'))
      if (resultMsg) assert.ok(connection.transaction.results.has(plugin, 'msg', resultMsg))
      assert.equal(code, deny ? DENY : undefined)
      assert.equal(msg, deny ? 'Invalid bounce (spoofed sender)' : undefined)
    })
  }

  it('skip SPF reject', async () => {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_FAIL)

    plugin.cfg.reject.bounce_spf = false

    const [code, msg] = await call('bounce_spf')
    assert.ok(check_host_stub.calledOnce)
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_spf'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'invalid bounce (spoofed sender)'))
    assertNext([code, msg])
  })
})
