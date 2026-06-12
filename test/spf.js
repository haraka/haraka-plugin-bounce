'use strict'

const assert = require('node:assert/strict')
const { describe, it, beforeEach } = require('node:test')

const { Address } = require('@haraka/email-address')
const { SPF } = require('haraka-plugin-spf')
const { callHook, makeConnection, makePlugin } = require('haraka-test-fixtures')

const spfLib = require('../lib/spf')

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

describe('check_null_sender', () => {
  it('has null sender', async () => {
    assertNext(await call('check_null_sender'))
    assert.equal(connection.transaction.results.get(plugin).isa, true)
  })

  it('has empty string sender', async () => {
    connection.transaction.mail_from = new Address('')
    assertNext(await call('check_null_sender'))
    assert.equal(connection.transaction.results.get(plugin).isa, true)
  })

  it('is not a null sender', async () => {
    connection.transaction.mail_from = new Address('user@example.com')
    assertNext(await call('check_null_sender'))
    assert.equal(connection.transaction.results.get(plugin).isa, false)
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
  let lookups

  beforeEach(() => {
    connection.transaction.body = {
      bodytext: `Received: from example.com (example.com [96.7.128.198])`,
      children: [],
    }
    connection.transaction.parse_body = true
    connection.transaction.mail_from = new Address('<>')

    plugin.cfg.reject.bounce_spf = true

    // Inject the SPF lookup so tests never touch DNS. Records each IP checked
    // and returns Pass by default; tests override for other verdicts.
    lookups = []
    plugin.spf_lookup = async (spf, ip) => {
      lookups.push(ip)
      return spf.SPF_PASS
    }
  })

  it('bounce_spf - missing transaction', async () => {
    delete connection.transaction

    assertNext(await call('empty_return_path'))
  })

  it('skip SPF check', async () => {
    plugin.cfg.check.bounce_spf = false

    const [code, msg] = await call('bounce_spf')
    assert.deepEqual(lookups, [])
    assertNext([code, msg])
  })

  it('will skip outbound mail', async () => {
    connection.relaying = true

    const [code, msg] = await call('bounce_spf')
    assert.deepEqual(lookups, [])
    assertNext([code, msg])
  })

  it('will skip when not a null sender', async () => {
    connection.transaction.mail_from = new Address('<test@example.com>')
    connection.transaction.results.add(plugin, { isa: false })

    const [code, msg] = await call('bounce_spf')
    assert.deepEqual(lookups, [])
    assertNext([code, msg])
  })

  it('will skip when hash validation passed', async () => {
    connection.transaction.results.add(plugin, {
      pass: 'validate_bounce',
    })

    const [code, msg] = await call('bounce_spf')
    assert.deepEqual(lookups, [])
    assertNext([code, msg])
  })

  it('no IPs', async () => {
    connection.transaction.body.bodytext = ''

    const [code, msg] = await call('bounce_spf')
    assert.ok(connection.transaction.results.has(plugin, 'skip', 'bounce_spf'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'no IP addresses found in message'))
    assert.deepEqual(lookups, [])
    assertNext([code, msg])
  })

  it('passes when an IP passes SPF', async () => {
    const [code, msg] = await call('bounce_spf')
    assert.ok(connection.transaction.results.has(plugin, 'pass', 'bounce_spf'))
    assert.deepEqual(lookups, ['96.7.128.198'])
    assertNext([code, msg])
  })

  it('has multiple IPs - 1st IP fails, 2nd IP passes', async () => {
    connection.transaction.body.bodytext = `
Received: from mx (mx.example.com [108.177.12.26])
Received: from mail.example.com (mail.example.com [209.85.128.52])
`
    plugin.spf_lookup = async (spf, ip) => {
      lookups.push(ip)
      return lookups.length === 1 ? spf.SPF_FAIL : spf.SPF_PASS
    }

    const [code, msg] = await call('bounce_spf')
    assert.ok(connection.transaction.results.has(plugin, 'pass', 'bounce_spf'))
    assert.deepEqual(lookups, ['108.177.12.26', '209.85.128.52'])
    assertNext([code, msg])
  })

  for (const { name, type, resultMsg, deny } of [
    { name: 'SPF_TEMPERROR', type: 'skip', resultMsg: 'SPF returned TempError', deny: false },
    { name: 'SPF_PERMERROR', type: 'skip', resultMsg: 'SPF returned PermError', deny: false },
    { name: 'SPF_NONE', type: 'skip', resultMsg: 'SPF returned None', deny: false },
    { name: 'SPF_PASS', type: 'pass', resultMsg: null, deny: false },
    { name: 'SPF_NEUTRAL', type: 'fail', resultMsg: 'invalid bounce (spoofed sender)', deny: true },
    { name: 'SPF_SOFTFAIL', type: 'fail', resultMsg: 'invalid bounce (spoofed sender)', deny: true },
    { name: 'SPF_FAIL', type: 'fail', resultMsg: 'invalid bounce (spoofed sender)', deny: true },
  ]) {
    it(name, async () => {
      plugin.spf_lookup = async (spf) => spf[name]
      const [code, msg] = await call('bounce_spf')
      assert.ok(connection.transaction.results.has(plugin, type, 'bounce_spf'))
      if (resultMsg) assert.ok(connection.transaction.results.has(plugin, 'msg', resultMsg))
      assert.equal(code, deny ? DENY : undefined)
      assert.equal(msg, deny ? 'Invalid bounce (spoofed sender)' : undefined)
    })
  }

  it('skip SPF reject', async () => {
    plugin.spf_lookup = async (spf) => spf.SPF_FAIL
    plugin.cfg.reject.bounce_spf = false

    const [code, msg] = await call('bounce_spf')
    assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_spf'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'invalid bounce (spoofed sender)'))
    assertNext([code, msg])
  })

  it('skips when the SPF lookup errors', async () => {
    plugin.spf_lookup = async () => {
      throw new Error('DNS timeout')
    }

    const [code, msg] = await call('bounce_spf')
    assert.ok(connection.transaction.results.has(plugin, 'skip', 'bounce_spf'))
    assert.ok(connection.transaction.results.has(plugin, 'msg', 'DNS timeout'))
    assertNext([code, msg])
  })
})

describe('lib/spf classifyResult', () => {
  const spf = new SPF()

  for (const [code, action] of [
    ['SPF_NONE', 'skip'],
    ['SPF_TEMPERROR', 'skip'],
    ['SPF_PERMERROR', 'skip'],
    ['SPF_PASS', 'pass'],
    ['SPF_NEUTRAL', 'continue'],
    ['SPF_SOFTFAIL', 'continue'],
    ['SPF_FAIL', 'continue'],
  ]) {
    it(`${code} -> ${action}`, () => {
      assert.equal(spfLib.classifyResult(spf, spf[code]).action, action)
    })
  }

  it('skip carries the SPF result name', () => {
    assert.equal(spfLib.classifyResult(spf, spf.SPF_NONE).msg, 'SPF returned None')
  })
})

describe('lib/spf evaluate', () => {
  const rcpt = { host: 'example.com', address: 'test@example.com' }

  const lookupReturning = (...codes) => {
    let i = 0
    return async (spf, ip, r) => {
      assert.equal(r, rcpt)
      const name = codes[Math.min(i, codes.length - 1)]
      i += 1
      return spf[name]
    }
  }

  it('passes on the first PASS', async () => {
    const verdict = await spfLib.evaluate(['1.1.1.1'], rcpt, lookupReturning('SPF_PASS'))
    assert.equal(verdict.type, 'pass')
    assert.equal(verdict.ip, '1.1.1.1')
  })

  it('continues past a FAIL and passes on a later IP', async () => {
    const verdict = await spfLib.evaluate(['1.1.1.1', '2.2.2.2'], rcpt, lookupReturning('SPF_FAIL', 'SPF_PASS'))
    assert.equal(verdict.type, 'pass')
    assert.equal(verdict.ip, '2.2.2.2')
  })

  it('fails when no IP passes', async () => {
    const verdict = await spfLib.evaluate(['1.1.1.1', '2.2.2.2'], rcpt, lookupReturning('SPF_FAIL'))
    assert.equal(verdict.type, 'fail')
    assert.equal(verdict.msg, 'invalid bounce (spoofed sender)')
  })

  it('aborts on a definitive non-result (NONE)', async () => {
    let calls = 0
    const lookup = async (spf) => {
      calls += 1
      return spf.SPF_NONE
    }
    const verdict = await spfLib.evaluate(['1.1.1.1', '2.2.2.2'], rcpt, lookup)
    assert.equal(verdict.type, 'skip')
    assert.equal(verdict.msg, 'SPF returned None')
    assert.equal(calls, 1) // short-circuits, does not check the 2nd IP
  })

  it('skips when the lookup throws', async () => {
    const lookup = async () => {
      throw new Error('dns boom')
    }
    const verdict = await spfLib.evaluate(['1.1.1.1'], rcpt, lookup)
    assert.equal(verdict.type, 'skip')
    assert.equal(verdict.msg, 'dns boom')
  })
})

describe('lib/spf findReceivedHeaders', () => {
  it('has no Received headers', () => {
    const ips = spfLib.findReceivedHeaders({ bodytext: '', children: [] })
    assert.equal(ips.size, 0)
  })

  it('has one Received header', () => {
    const ip = '209.85.128.52'
    const ips = spfLib.findReceivedHeaders({
      bodytext: `Received: from example.com (example.com [${ip}])`,
      children: [],
    })
    assert.equal(ips.size, 1)
    assert.ok(ips.has(ip))
  })

  it('skips private IPs', () => {
    const ip1 = '10.10.10.10'
    const ip2 = '209.85.128.52'
    const ips = spfLib.findReceivedHeaders({
      bodytext: `
Received: from mx (mx.example.com [${ip1}])
Received: from mail.example.com (HELO mail.example.com) (${ip2})
`,
      children: [],
    })
    assert.equal(ips.size, 1)
    assert.ok(ips.has(ip2))
  })

  it('collects two public IPs', () => {
    const ip1 = '108.177.12.26'
    const ip2 = '209.85.128.52'
    const ips = spfLib.findReceivedHeaders({
      bodytext: `
Received: from mx (mx.example.com [${ip1}])
Received: from mail.example.com (mail.example.com [${ip2}])
`,
      children: [],
    })
    assert.equal(ips.size, 2)
    assert.ok(ips.has(ip1))
    assert.ok(ips.has(ip2))
  })

  it('collects IPv4 and IPv6 IPs', () => {
    const ip1 = '108.177.12.26'
    const ip2 = '2603:10b6:8:189::16'
    const ip3 = '2603:10b6:303:e9::7'
    const ips = spfLib.findReceivedHeaders({
      bodytext: `
Received: from mx (mx.example.com [${ip1}])
Received: from prod.example.com
 ([${ip2}]) by prod.example.com (${ip3})
`,
      children: [],
    })
    assert.equal(ips.size, 2)
    assert.ok(ips.has(ip1))
    assert.ok(ips.has(ip2))
  })

  it('finds Received headers in a child part', () => {
    const ip1 = '108.177.12.26'
    const ip2 = '209.85.128.52'
    const ips = spfLib.findReceivedHeaders({
      bodytext: 'Hello World',
      children: [
        {
          bodytext: `
Received: from mx (mx.example.com [${ip1}])
Received: from mail.example.com (mail.example.com [${ip2}])
`,
          children: [],
        },
      ],
    })
    assert.equal(ips.size, 2)
    assert.ok(ips.has(ip1))
    assert.ok(ips.has(ip2))
  })

  it('finds headers in both parent and child (regex state-leak regression)', () => {
    const parent_ip = '108.177.12.26'
    const child_ip = '209.85.128.52'
    const ips = spfLib.findReceivedHeaders({
      bodytext: `Received: from mx (mx.example.com [${parent_ip}])`,
      children: [
        {
          bodytext: `Received: from mail.example.com (mail.example.com [${child_ip}])`,
          children: [],
        },
      ],
    })
    assert.equal(ips.size, 2)
    assert.ok(ips.has(parent_ip))
    assert.ok(ips.has(child_ip))
  })
})
