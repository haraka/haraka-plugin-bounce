'use strict'

const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const sinon = require('sinon')
const { describe, it, beforeEach, afterEach } = require('node:test')

const Address = require('@haraka/email-address')
const fixtures = require('haraka-test-fixtures')

let plugin, connection, should_skip_spy

beforeEach(() => {
  plugin = new fixtures.plugin('bounce')
  connection = fixtures.connection.createConnection()
  connection.remote.ip = '8.8.8.8'
  connection.relaying = false
  connection.init_transaction()
  connection.transaction.mail_from = new Address.Address('<>')
  connection.transaction.rcpt_to.push(new Address.Address('test@example.com'))

  plugin.register()

  should_skip_spy = sinon.spy(plugin, 'should_skip')
})

afterEach(() => sinon.restore())

describe('register', () => {
  it('should have register function', () => {
    const load_bounce_ini_stub = sinon.stub(plugin, 'load_bounce_ini')
    const load_bounce_bad_rcpt_stub = sinon.stub(plugin, 'load_bounce_bad_rcpt')
    const load_bounce_whitelist_stub = sinon.stub(plugin, 'load_bounce_whitelist')

    assert.equal('function', typeof plugin.register)

    plugin.register()

    assert.ok(load_bounce_ini_stub.calledOnce)
    assert.ok(load_bounce_bad_rcpt_stub.calledOnce)
    assert.ok(load_bounce_whitelist_stub.calledOnce)
  })

  it('registers hooks', () => {
    assert.deepEqual(plugin.hooks, {
      mail: ['reject_all'],
      rcpt_ok: ['bad_rcpt'],
      data: ['single_recipient', 'bounce_spf_enable'],
      data_post: ['empty_return_path', 'create_validation_hash', 'validate_bounce', 'bounce_spf'],
    })
  })
})

describe('load_configs', () => {
  it('load_bounce_ini', () => {
    const validate_config_stub = sinon.stub(plugin, 'validate_config')

    plugin.load_bounce_ini()

    assert.ok(validate_config_stub.calledOnce)
    assert.ok(plugin.cfg.check)
    assert.ok(plugin.cfg.reject)
    assert.ok(plugin.cfg.validation)
  })

  it('load_bounce_bad_rcpt', () => {
    const load_bounce_bad_rcpt_stub = sinon.stub(plugin, 'load_bounce_bad_rcpt')

    plugin.load_bounce_bad_rcpt()

    assert.ok(load_bounce_bad_rcpt_stub.calledOnce)
    assert.ok(plugin.cfg.invalid_addrs)
  })

  it('load_bounce_whitelist', () => {
    const load_bounce_whitelist_stub = sinon.stub(plugin, 'load_bounce_whitelist')

    plugin.load_bounce_whitelist()

    assert.ok(load_bounce_whitelist_stub.calledOnce)
    assert.ok(plugin.cfg.whitelist)
  })
})

describe('validate_config', () => {
  let getHashes_stub, logerror_stub

  beforeEach(() => {
    plugin.cfg = {
      validation: {
        max_hash_age_days: 6,
        hash_algorithm: 'sha256',
        secret: crypto.randomBytes(32).toString('base64'),
      },
      check: {
        single_recipient: true,
        empty_return_path: false,
        bounce_spf: true,
        hash_validation: false,
        hash_date: true,
      },
      reject: {
        single_recipient: true,
        empty_return_path: false,
        bounce_spf: false,
        hash_validation: false,
        hash_date: false,
      },
    }
    logerror_stub = sinon.stub(plugin, 'logerror')
    getHashes_stub = sinon.stub(crypto, 'getHashes')
    getHashes_stub.returns(['sha256', 'sha512', 'md5'])
  })

  it('will enable single recipient check', () => {
    plugin.cfg.check.single_recipient = false

    plugin.validate_config()

    assert.ok(getHashes_stub.notCalled)
    assert.ok(plugin.cfg.check.single_recipient)
  })

  it('will enable empty return path check', () => {
    plugin.cfg.reject.empty_return_path = true

    plugin.validate_config()

    assert.ok(getHashes_stub.notCalled)
    assert.ok(plugin.cfg.check.empty_return_path)
  })

  it('will enable bounce SPF check', () => {
    plugin.cfg.check.bounce_spf = false
    plugin.cfg.reject.bounce_spf = true

    plugin.validate_config()

    assert.ok(getHashes_stub.notCalled)
    assert.ok(plugin.cfg.check.bounce_spf)
  })

  it('will enable hash date check', () => {
    plugin.cfg.check.hash_validation = true
    plugin.cfg.check.hash_date = false
    plugin.cfg.reject.hash_date = true

    plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.ok(plugin.cfg.check.hash_date)
  })

  it('will not check hash validation', () => {
    plugin.validate_config()

    assert.ok(getHashes_stub.notCalled)
    assert.equal(plugin.cfg.check.hash_validation, false)
  })

  it('has invalid hash algorithm', () => {
    plugin.cfg.check.hash_validation = true
    plugin.cfg.validation.hash_algorithm = 'invalid_algorithm'

    plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.equal(plugin.cfg.check.hash_validation, false)
  })

  it('is missing the secret key', () => {
    delete plugin.cfg.validation.secret
    plugin.cfg.check.hash_validation = true

    plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.equal(plugin.cfg.check.hash_validation, false)
  })

  it('has short secret key', () => {
    plugin.cfg.validation.secret = 'short_key'
    plugin.cfg.check.hash_validation = true

    plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.ok(logerror_stub.calledOnce)
    assert.equal(plugin.cfg.check.hash_validation, false)
  })

  it('has default config settings', () => {
    plugin.cfg.check.hash_validation = true
    plugin.cfg.validation.secret = 'your_generated_secret_here'

    plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.ok(logerror_stub.calledOnce)
    assert.equal(plugin.cfg.check.hash_validation, false)
  })

  it('has valid config settings', () => {
    plugin.cfg.check.hash_validation = true
    plugin.cfg.validation.secret = 'valid_secret_thats_at_least_32_characters_long'

    plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.ok(logerror_stub.notCalled)
  })
})

describe('reject_all', () => {
  beforeEach(() => {
    plugin.cfg.reject.all_bounces = true
  })

  it('will allow bounces', async () => {
    plugin.cfg.reject.all_bounces = false
    await new Promise((resolve) => {
      plugin.reject_all((code, msg) => {
        assert.ok(should_skip_spy.notCalled)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('reject_all - missing transaction', async () => {
    delete connection.transaction

    await new Promise((resolve) => {
      plugin.empty_return_path((code, msg) => {
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will ignore outbound mail', async () => {
    connection.relaying = true

    await new Promise((resolve) => {
      plugin.reject_all((code, msg) => {
        assert.ok(should_skip_spy.returned(true))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will ignore non-bounce mail', async () => {
    connection.transaction.mail_from = new Address.Address('<test@example.com>')
    await new Promise((resolve) => {
      plugin.reject_all((code, msg) => {
        assert.ok(should_skip_spy.returned(true))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will reject all bounces', async () => {
    await new Promise((resolve) => {
      plugin.reject_all((code, msg) => {
        assert.ok(should_skip_spy.returned(false))
        connection.transaction.results.has(plugin, 'fail', 'bounces_accepted')
        connection.transaction.results.has(plugin, 'msg', 'bounces not accepted here')
        assert.equal(code, DENY)
        assert.equal(msg, 'Bounces not accepted here')
        resolve()
      }, connection)
    })
  })
})

describe('empty_return_path', () => {
  beforeEach(() => {
    plugin.cfg.check.empty_return_path = true
    plugin.cfg.reject.empty_return_path = true
  })

  it('empty_return_path - missing transaction', async () => {
    delete connection.transaction

    await new Promise((resolve) => {
      plugin.empty_return_path((code, msg) => {
        assert.ok(should_skip_spy.notCalled)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('should ignore empty_return_path', async () => {
    plugin.cfg.check.empty_return_path = false

    await new Promise((resolve) => {
      plugin.empty_return_path((code, msg) => {
        assert.ok(should_skip_spy.notCalled)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('missing Return-Path header', async () => {
    await new Promise((resolve) => {
      plugin.empty_return_path((code, msg) => {
        assert.ok(should_skip_spy.returned(false))
        assert.ok(connection.transaction.results.has(plugin, 'pass', 'empty_return_path'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('has empty Return-Path header', async () => {
    connection.transaction.add_header('Return-Path', '')
    await new Promise((resolve) => {
      plugin.empty_return_path((code, msg) => {
        assert.ok(should_skip_spy.returned(false))
        assert.ok(connection.transaction.results.has(plugin, 'pass', 'empty_return_path'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will allow non-empty Return-Path header', async () => {
    connection.transaction.add_header('Return-Path', 'Hello World!')

    plugin.cfg.reject.empty_return_path = false

    await new Promise((resolve) => {
      plugin.empty_return_path((code, msg) => {
        assert.ok(should_skip_spy.returned(false))
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'empty_return_path'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'bounce with non-empty Return-Path'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will reject non-empty Return-Path header', async () => {
    connection.transaction.add_header('Return-Path', 'Hello World!')

    await new Promise((resolve) => {
      plugin.empty_return_path((code, msg) => {
        assert.ok(should_skip_spy.returned(false))
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'empty_return_path'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'bounce with non-empty Return-Path'))
        assert.equal(code, DENY)
        assert.equal(msg, 'bounce with non-empty Return-Path (RFC 3834)')
        resolve()
      }, connection)
    })
  })
})

describe('single_recipient', () => {
  it('single_recipient - missing transaction', async () => {
    delete connection.transaction

    await new Promise((resolve) => {
      plugin.empty_return_path((code, msg) => {
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will not check for single recipient', async () => {
    plugin.cfg.check.single_recipient = false
    await new Promise((resolve) => {
      plugin.single_recipient((code, msg) => {
        assert.ok(should_skip_spy.notCalled)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('has single recipient', async () => {
    await new Promise((resolve) => {
      plugin.single_recipient((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'pass', 'single_recipient'))
        assert.ok(should_skip_spy.calledOnce)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will allow multiple recipients', async () => {
    plugin.cfg.reject.single_recipient = false
    connection.transaction.rcpt_to.push(new Address.Address('test2@example.com'))
    await new Promise((resolve) => {
      plugin.single_recipient((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'single_recipient'))
        assert.ok(should_skip_spy.calledOnce)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will reject multiple recipients', async () => {
    connection.transaction.rcpt_to.push(new Address.Address('test2@example.com'))
    await new Promise((resolve) => {
      plugin.single_recipient((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'single_recipient'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'too many recipients'))
        assert.ok(should_skip_spy.calledOnce)
        assert.equal(code, DENY)
        assert.equal(msg, 'this bounce message has too many recipients')
        resolve()
      }, connection)
    })
  })
})

describe('bad_rcpt', () => {
  beforeEach(() => {
    plugin.cfg.invalid_addrs = ['bad1@example.com', 'bad2@example.com']
  })

  it('will not check for bad recipient', async () => {
    plugin.cfg.reject.bad_rcpt = false

    await new Promise((resolve) => {
      plugin.reject_all(
        (code, msg) => {
          assert.ok(should_skip_spy.notCalled)
          assert.equal(code, undefined)
          assert.equal(msg, undefined)
          resolve()
        },
        connection,
        [new Address.Address('<>')],
      )
    })
  })

  it('bad_rcpt - missing transaction', async () => {
    delete connection.transaction

    await new Promise((resolve) => {
      plugin.empty_return_path((code, msg) => {
        assert.ok(should_skip_spy.notCalled)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will check for valid recipient', async () => {
    plugin.cfg.invalid_addrs = []
    const rcpt = new Address.Address('test@example.com')
    await new Promise((resolve) => {
      plugin.bad_rcpt(
        (code, msg) => {
          assert.ok(connection.transaction.results.has(plugin, 'pass', 'bad_rcpt'))
          assert.ok(should_skip_spy.calledOnce)
          assert.equal(code, undefined)
          assert.equal(msg, undefined)
          resolve()
        },
        connection,
        rcpt,
      )
    })
  })

  it('will check for invalid recipient', async () => {
    const rcpt = new Address.Address('bad1@example.com')
    await new Promise((resolve) => {
      plugin.bad_rcpt(
        (code, msg) => {
          assert.ok(connection.transaction.results.has(plugin, 'fail', 'bad_rcpt'))
          assert.ok(connection.transaction.results.has(plugin, 'msg', 'rcpt does not accept bounces'))
          assert.ok(should_skip_spy.calledOnce)
          assert.equal(code, DENY)
          assert.equal(msg, `${rcpt.address} does not accept bounces`)
          resolve()
        },
        connection,
        rcpt,
      )
    })
  })
})

describe('has_null_sender', () => {
  it('has null sender', () => {
    assert.ok(plugin.has_null_sender(connection.transaction))

    assert.ok(connection.transaction.results.get(plugin, 'isa', true))
  })

  it('has empty string sender', () => {
    connection.transaction.mail_from = new Address.Address('')
    assert.ok(plugin.has_null_sender(connection.transaction))
    assert.ok(connection.transaction.results.get(plugin, 'isa', true))
  })

  it('is not a null sender', () => {
    connection.transaction.mail_from = new Address.Address('user@example.com')
    assert.equal(plugin.has_null_sender(connection.transaction), false)
    assert.ok(connection.transaction.results.get(plugin, 'isa', false))
  })
})

describe('bounce_spf_enable', () => {
  it('bounce_spf_enable - missing transaction', async () => {
    delete connection.transaction

    await new Promise((resolve) => {
      plugin.empty_return_path((code, msg) => {
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('is outbound mail', async () => {
    connection.relaying = true

    await new Promise((resolve) => {
      plugin.bounce_spf_enable((code, msg) => {
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        assert.equal(connection.transaction.parse_body, false)
        resolve()
      }, connection)
    })
  })

  it('is inbound mail', async () => {
    connection.relaying = false

    await new Promise((resolve) => {
      plugin.bounce_spf_enable((code, msg) => {
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        assert.equal(connection.transaction.parse_body, true)
        resolve()
      }, connection)
    })
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
    connection.transaction.mail_from = new Address.Address('<>')

    plugin.cfg.reject.bounce_spf = true

    check_host_stub = sinon.stub(SPF.prototype, 'check_host')
    find_received_headers_stub = sinon.stub(plugin, 'find_received_headers')

    spf = new SPF()
  })

  it('bounce_spf - missing transaction', async () => {
    delete connection.transaction

    await new Promise((resolve) => {
      plugin.empty_return_path((code, msg) => {
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('skip SPF check', async () => {
    plugin.cfg.check.bounce_spf = false

    await new Promise((resolve) => {
      plugin.bounce_spf((code, msg) => {
        assert.ok(should_skip_spy.notCalled)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will skip outbound mail', async () => {
    connection.relaying = true

    await new Promise((resolve) => {
      plugin.bounce_spf((code, msg) => {
        assert.ok(should_skip_spy.calledOnce)
        assert.ok(find_received_headers_stub.notCalled)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will skip when not a null sender', async () => {
    connection.transaction.mail_from = new Address.Address('<test@example.com>')

    await new Promise((resolve) => {
      plugin.bounce_spf((code, msg) => {
        assert.ok(should_skip_spy.calledOnce)
        assert.ok(connection.transaction.results.get(plugin, 'isa', false))
        assert.ok(find_received_headers_stub.notCalled)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will skip when hash validation passed', async () => {
    connection.transaction.results.add(plugin, {
      pass: 'validate_bounce',
    })

    await new Promise((resolve) => {
      plugin.bounce_spf((code, msg) => {
        assert.ok(should_skip_spy.calledOnce)
        assert.ok(find_received_headers_stub.notCalled)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('no IPs', async () => {
    connection.transaction.body.bodytext = ''

    find_received_headers_stub.returns(new Set())
    await new Promise((resolve) => {
      plugin.bounce_spf((code, msg) => {
        assert.ok(connection.transaction.results.get(plugin, 'isa', true))
        assert(find_received_headers_stub.calledOnce)
        assert(find_received_headers_stub.calledWith(connection.transaction.body))
        assert.ok(connection.transaction.results.has(plugin, 'skip', 'bounce_spf'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'no IP addresses found in message'))
        assert.ok(check_host_stub.notCalled)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('has multiple IPs - 1st IP fails, 2nd IP passes', async () => {
    connection.transaction.body.bodytext = 'filler'

    find_received_headers_stub.returns(new Set('1.2.3.4', '5.6.7.8'))
    check_host_stub.returns(spf.SPF_FAIL).returns(spf.SPF_PASS)

    await new Promise((resolve) => {
      plugin.bounce_spf((code, msg) => {
        assert(find_received_headers_stub.calledOnce)
        assert.ok(connection.transaction.results.get(plugin, 'isa', true))
        assert(find_received_headers_stub.calledWith(connection.transaction.body))
        assert.ok(connection.transaction.results.has(plugin, 'pass', 'bounce_spf'))
        assert.ok(check_host_stub.calledOnce)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('SPF_TEMPERROR', async () => {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_TEMPERROR)

    await new Promise((resolve) => {
      plugin.bounce_spf((code, msg) => {
        assert.ok(check_host_stub.calledOnce)
        assert.ok(connection.transaction.results.has(plugin, 'skip', 'bounce_spf'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'SPF returned TempError'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('SPF_PERMERROR', async () => {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_PERMERROR)

    await new Promise((resolve) => {
      plugin.bounce_spf((code, msg) => {
        assert.ok(check_host_stub.calledOnce)
        assert.ok(connection.transaction.results.has(plugin, 'skip', 'bounce_spf'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'SPF returned PermError'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('SPF_NONE', async () => {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_NONE)

    await new Promise((resolve) => {
      plugin.bounce_spf((code, msg) => {
        assert.ok(check_host_stub.calledOnce)
        assert.ok(connection.transaction.results.has(plugin, 'skip', 'bounce_spf'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'SPF returned None'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('SPF_PASS', async () => {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_PASS)

    await new Promise((resolve) => {
      plugin.bounce_spf((code, msg) => {
        assert.ok(check_host_stub.calledOnce)
        assert.ok(connection.transaction.results.has(plugin, 'pass', 'bounce_spf'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('SPF_NEUTRAL', async () => {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_NEUTRAL)

    await new Promise((resolve) => {
      plugin.bounce_spf((code, msg) => {
        assert.ok(check_host_stub.calledOnce)
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_spf'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'invalid bounce (spoofed sender)'))
        assert.equal(code, DENY)
        assert.equal(msg, 'Invalid bounce (spoofed sender)')
        resolve()
      }, connection)
    })
  })

  it('SPF_SOFTFAIL', async () => {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_SOFTFAIL)

    await new Promise((resolve) => {
      plugin.bounce_spf((code, msg) => {
        assert.ok(check_host_stub.calledOnce)
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_spf'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'invalid bounce (spoofed sender)'))
        assert.equal(code, DENY)
        assert.equal(msg, 'Invalid bounce (spoofed sender)')
        resolve()
      }, connection)
    })
  })

  it('skip SPF reject', async () => {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_FAIL)

    plugin.cfg.reject.bounce_spf = false

    await new Promise((resolve) => {
      plugin.bounce_spf((code, msg) => {
        assert.ok(check_host_stub.calledOnce)
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_spf'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'invalid bounce (spoofed sender)'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('SPF_FAIL', async () => {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_FAIL)

    await new Promise((resolve) => {
      plugin.bounce_spf((code, msg) => {
        assert.ok(check_host_stub.calledOnce)
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_spf'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'invalid bounce (spoofed sender)'))
        assert.equal(code, DENY)
        assert.equal(msg, 'Invalid bounce (spoofed sender)')
        resolve()
      }, connection)
    })
  })
})

describe('create_validation_hash', () => {
  let get_decoded_stub

  beforeEach(() => {
    connection.transaction.body = {
      bodytext: '',
      children: [],
    }
    connection.transaction.parse_body = true
    connection.transaction.mail_from = new Address.Address('<test@example.com>')
    connection.relaying = true
    plugin.cfg.check.hash_validation = true

    get_decoded_stub = sinon.stub(connection.transaction.header, 'get_decoded')
  })

  it('create_validation_hash - missing transaction', async () => {
    delete connection.transaction

    await new Promise((resolve) => {
      plugin.empty_return_path((code, msg) => {
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('should not create validation hash', async () => {
    plugin.cfg.check.hash_validation = false

    await new Promise((resolve) => {
      plugin.create_validation_hash((code, msg) => {
        sinon.assert.notCalled(get_decoded_stub)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('should ignore inbound mail', async () => {
    connection.relaying = false

    await new Promise((resolve) => {
      plugin.create_validation_hash((code, msg) => {
        sinon.assert.notCalled(get_decoded_stub)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('should skip outbound with null sender', async () => {
    connection.transaction.mail_from = new Address.Address('<>')
    connection.relaying = true

    await new Promise((resolve) => {
      plugin.create_validation_hash((code, msg) => {
        sinon.assert.notCalled(get_decoded_stub)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('missing Message-ID header', async () => {
    const date_header = new Date().toISOString()
    const from_header = '<test@example.com>'

    connection.transaction.add_header('From', from_header)
    connection.transaction.add_header('Date', date_header)

    await new Promise((resolve) => {
      plugin.create_validation_hash((code, msg) => {
        sinon.assert.calledThrice(get_decoded_stub)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('missing From, Date, and Message-ID headers', async () => {
    await new Promise((resolve) => {
      plugin.create_validation_hash((code, msg) => {
        sinon.assert.calledThrice(get_decoded_stub)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('should create a validation hash', async () => {
    const date_header = new Date().toISOString()
    const from_header = '<test@example.com>'
    const message_id = '<test@example.COM>'

    connection.transaction.add_header('From', from_header)
    connection.transaction.add_header('Date', date_header)
    connection.transaction.add_header('Message-ID', message_id)

    await new Promise((resolve) => {
      plugin.create_validation_hash((code, msg) => {
        sinon.assert.calledThrice(get_decoded_stub)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
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

    await new Promise((resolve) => {
      plugin.empty_return_path((code, msg) => {
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('should skip validation check', async () => {
    plugin.cfg.check.hash_validation = false

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(should_skip_spy.notCalled)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('has hash size that is too short', async () => {
    hash = '1234567890'

    const headers = create_headers(plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    plugin.cfg.reject.hash_validation = false

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash length mismatch'))
        assert(find_bounce_headers_stub.calledOnce)
        assert(find_bounce_headers_stub.calledWith(connection.transaction, connection.transaction.body))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('has hash size that is too long', async () => {
    plugin.cfg.reject.hash_validation = false

    const hash = '1234567890123456789012345678901234567890123456789012345678901234567890'

    const headers = create_headers(plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash length mismatch'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will reject if wrong hash size', async () => {
    const hash = '1234567890'

    const headers = create_headers(plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash length mismatch'))
        assert.equal(code, DENY)
        assert.equal(msg, 'invalid bounce')
        resolve()
      }, connection)
    })
  })

  it('is a valid inbound bounce', async () => {
    const headers = create_headers(plugin)
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'pass', 'validate_bounce'))
        assert(find_bounce_headers_stub.calledOnce)
        assert(find_bounce_headers_stub.calledWith(connection.transaction, connection.transaction.body))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('has incorrect hash', async () => {
    plugin.cfg.reject.hash_validation = false

    hash = crypto
      .createHmac(plugin.cfg.validation.hash_algorithm, crypto.randomBytes(32).toString('base64'))
      .update(amalgam)
      .digest('hex')

    const headers = create_headers(plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash does not match'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will deny when incorrect hash', async () => {
    hash = crypto
      .createHmac(plugin.cfg.validation.hash_algorithm, crypto.randomBytes(32).toString('base64'))
      .update(amalgam)
      .digest('hex')

    const headers = create_headers(plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash does not match'))
        assert.equal(code, DENY)
        assert.equal(msg, 'invalid bounce')
        resolve()
      }, connection)
    })
  })

  it('is missing the From header', async () => {
    plugin.cfg.reject.hash_validation = false

    const headers = create_headers(plugin)
    delete headers.from
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing headers'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('is missing the Date header', async () => {
    plugin.cfg.reject.hash_validation = false

    const headers = create_headers(plugin)
    delete headers.date
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing headers'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('is missing the Message-ID header', async () => {
    plugin.cfg.reject.hash_validation = false

    const headers = create_headers(plugin)
    delete headers.message_id
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing headers'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will deny when missing the From header', async () => {
    const headers = create_headers(plugin)
    delete headers.from
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing headers'))
        assert.equal(code, DENY)
        assert.equal(msg, 'invalid bounce')
        resolve()
      }, connection)
    })
  })

  it('will deny when missing the Date header', async () => {
    const headers = create_headers(plugin)
    delete headers.date
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing headers'))
        assert.equal(code, DENY)
        assert.equal(msg, 'invalid bounce')
        resolve()
      }, connection)
    })
  })

  it('will deny when missing the Message-ID header', async () => {
    const headers = create_headers(plugin)
    delete headers.message_id
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing headers'))
        assert.equal(code, DENY)
        assert.equal(msg, 'invalid bounce')
        resolve()
      }, connection)
    })
  })

  it('is missing hash header and address parsing fails', async () => {
    const from = 'mail delivery system <mailer-daemon@example.com>'
    const rcpt = new Address.Address('test@example.com')

    plugin.cfg.reject.hash_validation = false
    connection.transaction.rcpt_to[0] = rcpt
    connection.transaction.add_header('From', from)

    const headers = create_headers(plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing validation hash'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('is missing hash header and email address is whitelisted', async () => {
    plugin.cfg.whitelist = { 'test@example.com': ['no-reply@example.com'] }

    const from = '<no-reply@example.com>'
    const rcpt = new Address.Address('test@example.com')

    connection.transaction.rcpt_to[0] = rcpt
    connection.transaction.add_header('From', from)

    const headers = create_headers(plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'skip', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'whitelisted'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('is missing hash header and sender domain is whitelisted', async () => {
    plugin.cfg.whitelist = { 'bar@example.com': ['*@example.net'] }

    const from = '<info@example.net>'
    const rcpt = new Address.Address('bar@example.com')

    connection.transaction.rcpt_to[0] = rcpt
    connection.transaction.add_header('From', from)

    const headers = create_headers(plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'skip', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'whitelisted'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('is missing hash header and has invalid from header', async () => {
    const from = '<invalid>'
    connection.transaction.add_header('From', from)

    const headers = create_headers(plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'skip', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'invalid from header'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)

        resolve()
      }, connection)
    })
  })

  it('is missing hash header', async () => {
    const from = '<info@example.net>'
    connection.transaction.add_header('From', from)
    plugin.cfg.reject.hash_validation = false

    const headers = create_headers(plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing validation hash'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will deny when missing hash header', async () => {
    const from = '<info@example.net>'
    connection.transaction.add_header('From', from)

    const headers = create_headers(plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing validation hash'))
        assert.equal(code, DENY)
        assert.equal(msg, 'invalid bounce')
        resolve()
      }, connection)
    })
  })

  it('is missing all headers', async () => {
    const headers = {}
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'skip', 'validate_bounce'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'missing all headers'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will Deny when hash is too old', async () => {
    plugin.cfg.reject.hash_date = true
    const eightDaysAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 8)
    date_header = eightDaysAgo.toUTCString()

    const headers = create_headers(plugin, { date_header })
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_date'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash is too old'))
        assert(find_bounce_headers_stub.calledOnce)
        assert(find_bounce_headers_stub.calledWith(connection.transaction, connection.transaction.body))
        assert.equal(code, DENY)
        assert.equal(msg, 'invalid bounce')
        resolve()
      }, connection)
    })
  })

  it('hash is too old', async () => {
    plugin.cfg.reject.hash_date = false
    const eightDaysAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 8)
    date_header = eightDaysAgo.toUTCString()

    const headers = create_headers(plugin, { date_header })
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_date'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'hash is too old'))
        assert(find_bounce_headers_stub.calledOnce)
        assert(find_bounce_headers_stub.calledWith(connection.transaction, connection.transaction.body))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('has invalid date header', async () => {
    plugin.cfg.reject.hash_date = false
    date_header = 'invalid date'

    const headers = create_headers(plugin, { date_header })
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_date'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'invalid date header'))
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        resolve()
      }, connection)
    })
  })

  it('will DENY when date header is invalid', async () => {
    date_header = 'invalid date'

    const headers = create_headers(plugin, { date_header })
    find_bounce_headers_stub.returns(headers)

    await new Promise((resolve) => {
      plugin.validate_bounce((code, msg) => {
        assert.ok(connection.transaction.results.has(plugin, 'fail', 'bounce_date'))
        assert.ok(connection.transaction.results.has(plugin, 'msg', 'invalid date header'))
        assert.equal(code, DENY)
        assert.equal(msg, 'invalid bounce')
        resolve()
      }, connection)
    })
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

describe('should_skip', () => {
  let has_null_sender_spy

  beforeEach(() => {
    has_null_sender_spy = sinon.spy(plugin, 'has_null_sender')
  })

  it('is relaying and is not a bounce', () => {
    connection.transaction.mail_from = new Address.Address('<test@example.com>')
    connection.relaying = true

    const result = plugin.should_skip(connection)

    assert.equal(result, true)
    assert.ok(has_null_sender_spy.calledOnce)
    assert.ok(has_null_sender_spy.returned(false))
  })

  it('is relaying and is a bounce', () => {
    connection.relaying = true

    const result = plugin.should_skip(connection)

    assert.equal(result, true)
    assert.ok(has_null_sender_spy.calledOnce)
    assert.ok(has_null_sender_spy.returned(true))
  })

  it('is not relaying and is not a bounce', () => {
    connection.transaction.mail_from = new Address.Address('<test@example.com>')
    connection.relaying = false

    const result = plugin.should_skip(connection)

    assert.equal(result, true)
    assert.ok(has_null_sender_spy.calledOnce)
    assert.ok(has_null_sender_spy.returned(false))
  })

  it('is not relaying and is a bounce', () => {
    connection.relaying = false

    const result = plugin.should_skip(connection)

    assert.equal(result, false)
    assert.ok(has_null_sender_spy.calledOnce)
    assert.ok(has_null_sender_spy.returned(true))
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
