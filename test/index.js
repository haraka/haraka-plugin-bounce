'use strict'

const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const sinon = require('sinon')

const Address = require('address-rfc2821')
const fixtures = require('haraka-test-fixtures')

beforeEach(function () {
  this.plugin = new fixtures.plugin('bounce')
  this.connection = fixtures.connection.createConnection()
  this.connection.remote.ip = '8.8.8.8'
  this.connection.relaying = false
  this.connection.init_transaction()
  this.connection.transaction.mail_from = new Address.Address('<>')
  this.connection.transaction.rcpt_to.push(
    new Address.Address('test@example.com'),
  )

  this.plugin.register()

  this.should_skip_spy = sinon.spy(this.plugin, 'should_skip')
})

afterEach(sinon.restore)

describe('register', function () {
  it('should have register function', function () {
    const load_bounce_ini_stub = sinon.stub(this.plugin, 'load_bounce_ini')
    const load_bounce_bad_rcpt_stub = sinon.stub(
      this.plugin,
      'load_bounce_bad_rcpt',
    )
    const load_bounce_whitelist_stub = sinon.stub(
      this.plugin,
      'load_bounce_whitelist',
    )

    assert.equal('function', typeof this.plugin.register)

    this.plugin.register()

    assert.ok(load_bounce_ini_stub.calledOnce)
    assert.ok(load_bounce_bad_rcpt_stub.calledOnce)
    assert.ok(load_bounce_whitelist_stub.calledOnce)
  })

  it('registers hooks', function () {
    assert.ok(this.plugin.register_hook.called)
    let hook_count = 0
    assert.equal(this.plugin.register_hook.args[hook_count++][1], 'reject_all')
    assert.equal(this.plugin.register_hook.args[hook_count++][1], 'bad_rcpt')
    assert.equal(this.plugin.register_hook.args[hook_count++][1], 'single_recipient')
    assert.equal(this.plugin.register_hook.args[hook_count++][1], 'bounce_spf_enable')
    assert.equal(this.plugin.register_hook.args[hook_count++][1], 'empty_return_path')
    assert.equal(this.plugin.register_hook.args[hook_count++][1], 'create_validation_hash')
    assert.equal(this.plugin.register_hook.args[hook_count++][1], 'validate_bounce')
    assert.equal(this.plugin.register_hook.args[hook_count++][1], 'bounce_spf')
    assert.equal(this.plugin.register_hook.args.length, hook_count)
  })
})

describe('load_configs', function () {
  it('load_bounce_ini', function () {
    const validate_config_stub = sinon.stub(this.plugin, 'validate_config')

    this.plugin.load_bounce_ini()

    assert.ok(validate_config_stub.calledOnce)
    assert.ok(this.plugin.cfg.check)
    assert.ok(this.plugin.cfg.reject)
    assert.ok(this.plugin.cfg.validation)
  })

  it('load_bounce_bad_rcpt', function () {
    const load_bounce_bad_rcpt_stub = sinon.stub(
      this.plugin,
      'load_bounce_bad_rcpt',
    )

    this.plugin.load_bounce_bad_rcpt()

    assert.ok(load_bounce_bad_rcpt_stub.calledOnce)
    assert.ok(this.plugin.cfg.invalid_addrs)
  })

  it('load_bounce_whitelist', function () {
    const load_bounce_whitelist_stub = sinon.stub(
      this.plugin,
      'load_bounce_whitelist',
    )

    this.plugin.load_bounce_whitelist()

    assert.ok(load_bounce_whitelist_stub.calledOnce)
    assert.ok(this.plugin.cfg.whitelist)
  })
})

describe('validate_config', function () {
  let getHashes_stub, logerror_stub

  beforeEach(function () {
    this.plugin.cfg = {
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
    logerror_stub = sinon.stub(this.plugin, 'logerror')
    getHashes_stub = sinon.stub(crypto, 'getHashes')
    getHashes_stub.returns(['sha256', 'sha512', 'md5'])
  })

  it('will enable single recipient check', function () {
    this.plugin.cfg.check.single_recipient = false

    this.plugin.validate_config()

    assert.ok(getHashes_stub.notCalled)
    assert.ok(this.plugin.cfg.check.single_recipient)
  })

  it('will enable empty return path check', function () {
    this.plugin.cfg.reject.empty_return_path = true

    this.plugin.validate_config()

    assert.ok(getHashes_stub.notCalled)
    assert.ok(this.plugin.cfg.check.empty_return_path)
  })

  it('will enable bounce SPF check', function () {
    this.plugin.cfg.check.bounce_spf = false
    this.plugin.cfg.reject.bounce_spf = true

    this.plugin.validate_config()

    assert.ok(getHashes_stub.notCalled)
    assert.ok(this.plugin.cfg.check.bounce_spf)
  })

  it('will enable hash date check', function () {
    this.plugin.cfg.check.hash_validation = true
    this.plugin.cfg.check.hash_date = false
    this.plugin.cfg.reject.hash_date = true

    this.plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.ok(this.plugin.cfg.check.hash_date)
  })

  it('will not check hash validation', function () {
    this.plugin.validate_config()

    assert.ok(getHashes_stub.notCalled)
    assert.equal(this.plugin.cfg.check.hash_validation, false)
  })

  it('has invalid hash algorithm', function () {
    this.plugin.cfg.check.hash_validation = true
    this.plugin.cfg.validation.hash_algorithm = 'invalid_algorithm'

    this.plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.equal(this.plugin.cfg.check.hash_validation, false)
  })

  it('is missing the secret key', function () {
    delete this.plugin.cfg.validation.secret
    this.plugin.cfg.check.hash_validation = true

    this.plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.equal(this.plugin.cfg.check.hash_validation, false)
  })

  it('has short secret key', function () {
    this.plugin.cfg.validation.secret = 'short_key'
    this.plugin.cfg.check.hash_validation = true

    this.plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.ok(logerror_stub.calledOnce)
    assert.equal(this.plugin.cfg.check.hash_validation, false)
  })

  it('has default config settings', function () {
    this.plugin.cfg.check.hash_validation = true
    this.plugin.cfg.validation.secret = 'your_generated_secret_here'

    this.plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.ok(logerror_stub.calledOnce)
    assert.equal(this.plugin.cfg.check.hash_validation, false)
  })

  it('has valid config settings', function () {
    this.plugin.cfg.check.hash_validation = true
    this.plugin.cfg.validation.secret =
      'valid_secret_thats_at_least_32_characters_long'

    this.plugin.validate_config()

    assert.ok(getHashes_stub.calledOnce)
    assert.ok(logerror_stub.notCalled)
  })
})

describe('reject_all', function () {
  beforeEach(function () {
    this.plugin.cfg.reject.all_bounces = true
  })

  it('will allow bounces', function (done) {
    this.plugin.cfg.reject.all_bounces = false
    this.plugin.reject_all((code, msg) => {
      assert.ok(this.should_skip_spy.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('reject_all - missing transaction', function (done) {
    delete this.connection.transaction

    this.plugin.empty_return_path((code, msg) => {
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will ignore outbound mail', function (done) {
    this.connection.relaying = true

    this.plugin.reject_all((code, msg) => {
      assert.ok(this.should_skip_spy.returned(true))
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will ignore non-bounce mail', function (done) {
    this.connection.transaction.mail_from = new Address.Address(
      '<test@example.com>',
    )
    this.plugin.reject_all((code, msg) => {
      assert.ok(this.should_skip_spy.returned(true))
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will reject all bounces', function (done) {
    this.plugin.reject_all((code, msg) => {
      assert.ok(this.should_skip_spy.returned(false))
      this.connection.transaction.results.has(
        this.plugin,
        'fail',
        'bounces_accepted',
      )
      this.connection.transaction.results.has(
        this.plugin,
        'msg',
        'bounces not accepted here',
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'Bounces not accepted here')
      done()
    }, this.connection)
  })
})

describe('empty_return_path', function () {
  beforeEach(function () {
    this.plugin.cfg.check.empty_return_path = true
    this.plugin.cfg.reject.empty_return_path = true
  })

  it('empty_return_path - missing transaction', function (done) {
    delete this.connection.transaction

    this.plugin.empty_return_path((code, msg) => {
      assert.ok(this.should_skip_spy.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('should ignore empty_return_path', function (done) {
    this.plugin.cfg.check.empty_return_path = false

    this.plugin.empty_return_path((code, msg) => {
      assert.ok(this.should_skip_spy.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('missing Return-Path header', function (done) {
    this.plugin.empty_return_path((code, msg) => {
      assert.ok(this.should_skip_spy.returned(false))
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'pass',
          'empty_return_path',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('has empty Return-Path header', function (done) {
    this.connection.transaction.add_header('Return-Path', '')
    this.plugin.empty_return_path((code, msg) => {
      assert.ok(this.should_skip_spy.returned(false))
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'pass',
          'empty_return_path',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will allow non-empty Return-Path header', function (done) {
    this.connection.transaction.add_header('Return-Path', 'Hello World!')

    this.plugin.cfg.reject.empty_return_path = false

    this.plugin.empty_return_path((code, msg) => {
      assert.ok(this.should_skip_spy.returned(false))
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'empty_return_path',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'bounce with non-empty Return-Path',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will reject non-empty Return-Path header', function (done) {
    this.connection.transaction.add_header('Return-Path', 'Hello World!')

    this.plugin.empty_return_path((code, msg) => {
      assert.ok(this.should_skip_spy.returned(false))
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'empty_return_path',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'bounce with non-empty Return-Path',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'bounce with non-empty Return-Path (RFC 3834)')
      done()
    }, this.connection)
  })
})

describe('single_recipient', function () {
  it('single_recipient - missing transaction', function (done) {
    delete this.connection.transaction

    this.plugin.empty_return_path((code, msg) => {
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will not check for single recipient', function (done) {
    this.plugin.cfg.check.single_recipient = false
    this.plugin.single_recipient((code, msg) => {
      assert.ok(this.should_skip_spy.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('has single recipient', function (done) {
    this.plugin.single_recipient((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'pass',
          'single_recipient',
        ),
      )
      assert.ok(this.should_skip_spy.calledOnce)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will allow multiple recipients', function (done) {
    this.plugin.cfg.reject.single_recipient = false
    this.connection.transaction.rcpt_to.push(
      new Address.Address('test2@example.com'),
    )
    this.plugin.single_recipient((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'single_recipient',
        ),
      )
      assert.ok(this.should_skip_spy.calledOnce)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will reject multiple recipients', function (done) {
    this.connection.transaction.rcpt_to.push(
      new Address.Address('test2@example.com'),
    )
    this.plugin.single_recipient((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'single_recipient',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'too many recipients',
        ),
      )
      assert.ok(this.should_skip_spy.calledOnce)
      assert.equal(code, DENY)
      assert.equal(msg, 'this bounce message has too many recipients')
      done()
    }, this.connection)
  })
})

describe('bad_rcpt', function () {
  beforeEach(function () {
    this.plugin.cfg.invalid_addrs = ['bad1@example.com', 'bad2@example.com']
  })

  it('will not check for bad recipient', function (done) {
    this.plugin.cfg.reject.bad_rcpt = false

    this.plugin.reject_all(
      (code, msg) => {
        assert.ok(this.should_skip_spy.notCalled)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        done()
      },
      this.connection,
      [new Address.Address('<>')],
    )
  })

  it('bad_rcpt - missing transaction', function (done) {
    delete this.connection.transaction

    this.plugin.empty_return_path((code, msg) => {
      assert.ok(this.should_skip_spy.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will check for valid recipient', function (done) {
    this.plugin.cfg.invalid_addrs = []
    const rcpt = new Address.Address('test@example.com')
    this.plugin.bad_rcpt(
      (code, msg) => {
        assert.ok(
          this.connection.transaction.results.has(
            this.plugin,
            'pass',
            'bad_rcpt',
          ),
        )
        assert.ok(this.should_skip_spy.calledOnce)
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        done()
      },
      this.connection,
      rcpt,
    )
  })

  it('will check for invalid recipient', function (done) {
    const rcpt = new Address.Address('bad1@example.com')
    this.plugin.bad_rcpt(
      (code, msg) => {
        assert.ok(
          this.connection.transaction.results.has(
            this.plugin,
            'fail',
            'bad_rcpt',
          ),
        )
        assert.ok(
          this.connection.transaction.results.has(
            this.plugin,
            'msg',
            'rcpt does not accept bounces',
          ),
        )
        assert.ok(this.should_skip_spy.calledOnce)
        assert.equal(code, DENY)
        assert.equal(msg, `${rcpt.address()} does not accept bounces`)
        done()
      },
      this.connection,
      rcpt,
    )
  })
})

describe('has_null_sender', function () {
  it('has null sender', function (done) {
    assert.ok(this.plugin.has_null_sender(this.connection.transaction))

    assert.ok(
      this.connection.transaction.results.has(this.plugin, 'isa', 'yes'),
    )
    done()
  })

  it('has empty string sender', function (done) {
    this.connection.transaction.mail_from = new Address.Address('')
    assert.ok(this.plugin.has_null_sender(this.connection.transaction))
    assert.ok(
      this.connection.transaction.results.has(this.plugin, 'isa', 'yes'),
    )
    done()
  })

  it('is not a null sender', function (done) {
    this.connection.transaction.mail_from = new Address.Address(
      'user@example.com',
    )
    assert.equal(
      this.plugin.has_null_sender(this.connection.transaction),
      false,
    )
    assert.ok(this.connection.transaction.results.has(this.plugin, 'isa', 'no'))
    done()
  })
})

describe('bounce_spf_enable', function () {
  it('bounce_spf_enable - missing transaction', function (done) {
    delete this.connection.transaction

    this.plugin.empty_return_path((code, msg) => {
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('is outbound mail', function (done) {
    this.connection.relaying = true

    this.plugin.bounce_spf_enable((code, msg) => {
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      assert.equal(this.connection.transaction.parse_body, false)
      done()
    }, this.connection)
  })

  it('is inbound mail', function (done) {
    this.connection.relaying = false

    this.plugin.bounce_spf_enable((code, msg) => {
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      assert.equal(this.connection.transaction.parse_body, true)
      done()
    }, this.connection)
  })
})

describe('bounce_spf', function () {
  const { SPF } = require('haraka-plugin-spf')

  let check_host_stub, find_received_headers_stub
  let spf

  beforeEach(function () {
    this.connection.transaction.body = {
      bodytext: `Received: from example.com (example.com [96.7.128.198])`,
      children: [],
    }
    this.connection.transaction.parse_body = true
    this.connection.transaction.mail_from = new Address.Address('<>')

    this.plugin.cfg.reject.bounce_spf = true

    check_host_stub = sinon.stub(SPF.prototype, 'check_host')
    find_received_headers_stub = sinon.stub(
      this.plugin,
      'find_received_headers',
    )

    spf = new SPF()
  })

  it('bounce_spf - missing transaction', function (done) {
    delete this.connection.transaction

    this.plugin.empty_return_path((code, msg) => {
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('skip SPF check', async function () {
    this.plugin.cfg.check.bounce_spf = false

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(this.should_skip_spy.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('will skip outbound mail', async function () {
    this.connection.relaying = true

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(this.should_skip_spy.calledOnce)
      assert.ok(find_received_headers_stub.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('will skip when not a null sender', async function () {
    this.connection.transaction.mail_from = new Address.Address(
      '<test@example.com>',
    )

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(this.should_skip_spy.calledOnce)
      assert.ok(
        this.connection.transaction.results.has(this.plugin, 'isa', 'no'),
      )
      assert.ok(find_received_headers_stub.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('will skip when hash validation passed', async function () {
    this.connection.transaction.results.add(this.plugin, {
      pass: 'validate_bounce',
    })

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(this.should_skip_spy.calledOnce)
      assert.ok(find_received_headers_stub.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('no IPs', async function () {
    this.connection.transaction.body.bodytext = ''

    find_received_headers_stub.returns(new Set())
    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(this.plugin, 'isa', 'yes'),
      )
      assert(find_received_headers_stub.calledOnce)
      assert(
        find_received_headers_stub.calledWith(this.connection.transaction.body),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'skip',
          'bounce_spf',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'no IP addresses found in message',
        ),
      )
      assert.ok(check_host_stub.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('has multiple IPs - 1st IP fails, 2nd IP passes', async function () {
    this.connection.transaction.body.bodytext = 'filler'

    find_received_headers_stub.returns(new Set('1.2.3.4', '5.6.7.8'))
    check_host_stub.returns(spf.SPF_FAIL).returns(spf.SPF_PASS)

    await this.plugin.bounce_spf((code, msg) => {
      assert(find_received_headers_stub.calledOnce)
      assert.ok(
        this.connection.transaction.results.has(this.plugin, 'isa', 'yes'),
      )
      assert(
        find_received_headers_stub.calledWith(this.connection.transaction.body),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'pass',
          'bounce_spf',
        ),
      )
      assert.ok(check_host_stub.calledOnce)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('SPF_TEMPERROR', async function () {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_TEMPERROR)

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(check_host_stub.calledOnce)
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'skip',
          'bounce_spf',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'SPF returned TempError',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('SPF_PERMERROR', async function () {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_PERMERROR)

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(check_host_stub.calledOnce)
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'skip',
          'bounce_spf',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'SPF returned PermError',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('SPF_NONE', async function () {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_NONE)

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(check_host_stub.calledOnce)
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'skip',
          'bounce_spf',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'SPF returned None',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('SPF_PASS', async function () {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_PASS)

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(check_host_stub.calledOnce)
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'pass',
          'bounce_spf',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('SPF_NEUTRAL', async function () {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_NEUTRAL)

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(check_host_stub.calledOnce)
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'bounce_spf',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'invalid bounce (spoofed sender)',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'Invalid bounce (spoofed sender)')
    }, this.connection)
  })

  it('SPF_SOFTFAIL', async function () {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_SOFTFAIL)

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(check_host_stub.calledOnce)
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'bounce_spf',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'invalid bounce (spoofed sender)',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'Invalid bounce (spoofed sender)')
    }, this.connection)
  })

  it('skip SPF reject', async function () {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_FAIL)

    this.plugin.cfg.reject.bounce_spf = false

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(check_host_stub.calledOnce)
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'bounce_spf',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'invalid bounce (spoofed sender)',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('SPF_FAIL', async function () {
    find_received_headers_stub.returns(new Set().add('1.2.3.4'))
    check_host_stub.returns(spf.SPF_FAIL)

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(check_host_stub.calledOnce)
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'bounce_spf',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'invalid bounce (spoofed sender)',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'Invalid bounce (spoofed sender)')
    }, this.connection)
  })
})

describe('create_validation_hash', function () {
  let get_decoded_stub

  beforeEach(function () {
    this.connection.transaction.body = {
      bodytext: '',
      children: [],
    }
    this.connection.transaction.parse_body = true
    this.connection.transaction.mail_from = new Address.Address(
      '<test@example.com>',
    )
    this.connection.relaying = true
    this.plugin.cfg.check.hash_validation = true

    get_decoded_stub = sinon.stub(
      this.connection.transaction.header,
      'get_decoded',
    )
  })

  it('create_validation_hash - missing transaction', function (done) {
    delete this.connection.transaction

    this.plugin.empty_return_path((code, msg) => {
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('should not create validation hash', function (done) {
    this.plugin.cfg.check.hash_validation = false

    this.plugin.create_validation_hash((code, msg) => {
      sinon.assert.notCalled(get_decoded_stub)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('should ignore inbound mail', function (done) {
    this.connection.relaying = false

    this.plugin.create_validation_hash((code, msg) => {
      sinon.assert.notCalled(get_decoded_stub)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('should skip outbound with null sender', function (done) {
    this.connection.transaction.mail_from = new Address.Address('<>')
    this.connection.relaying = true

    this.plugin.create_validation_hash((code, msg) => {
      sinon.assert.notCalled(get_decoded_stub)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('missing Message-ID header', function (done) {
    const date_header = new Date().toISOString()
    const from_header = '<test@example.com>'

    this.connection.transaction.add_header('From', from_header)
    this.connection.transaction.add_header('Date', date_header)

    this.plugin.create_validation_hash((code, msg) => {
      sinon.assert.calledThrice(get_decoded_stub)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('missing From, Date, and Message-ID headers', function (done) {
    this.plugin.create_validation_hash((code, msg) => {
      sinon.assert.calledThrice(get_decoded_stub)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('should create a validation hash', function (done) {
    const date_header = new Date().toISOString()
    const from_header = '<test@example.com>'
    const message_id = '<test@example.COM>'

    this.connection.transaction.add_header('From', from_header)
    this.connection.transaction.add_header('Date', date_header)
    this.connection.transaction.add_header('Message-ID', message_id)

    this.plugin.create_validation_hash((code, msg) => {
      sinon.assert.calledThrice(get_decoded_stub)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })
})

describe('validate_bounce', function () {
  let find_bounce_headers_stub
  let hash, amalgam
  let date_header, from_header, message_id

  beforeEach(function () {
    this.plugin.cfg.check.hash_date = true
    this.plugin.cfg.check.hash_validation = true
    this.plugin.cfg.reject.hash_validation = true
    this.plugin.cfg.reject.hash_date = true
    this.plugin.cfg.validation = {
      max_hash_age_days: 6,
      hash_algorithm: 'sha256',
      secret: crypto.randomBytes(32).toString('base64'),
    }

    this.connection.transaction.body = {
      bodytext: '',
      children: [],
    }

    date_header = new Date().toISOString()
    from_header = '<test@example.com>'
    message_id = '<test@example.com>'

    amalgam = `${from_header}:${date_header}:${message_id}`
    hash = crypto
      .createHmac(
        this.plugin.cfg.validation.hash_algorithm,
        this.plugin.cfg.validation.secret,
      )
      .update(amalgam)
      .digest('hex')

    find_bounce_headers_stub = sinon.stub(this.plugin, 'find_bounce_headers')
  })

  it('validate_bounce - missing transaction', function (done) {
    delete this.connection.transaction

    this.plugin.empty_return_path((code, msg) => {
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('should skip validation check', function (done) {
    this.plugin.cfg.check.hash_validation = false

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(this.should_skip_spy.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('has hash size that is too short', function (done) {
    hash = '1234567890'

    const headers = create_headers(this.plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    this.plugin.cfg.reject.hash_validation = false

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'hash length mismatch',
        ),
      )
      assert(find_bounce_headers_stub.calledOnce)
      assert(
        find_bounce_headers_stub.calledWith(
          this.connection.transaction,
          this.connection.transaction.body,
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('has hash size that is too long', function (done) {
    this.plugin.cfg.reject.hash_validation = false

    const hash =
      '1234567890123456789012345678901234567890123456789012345678901234567890'

    const headers = create_headers(this.plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'hash length mismatch',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will reject if wrong hash size', function (done) {
    const hash = '1234567890'

    const headers = create_headers(this.plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'hash length mismatch',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'invalid bounce')
      done()
    }, this.connection)
  })

  it('is a valid inbound bounce', function (done) {
    const headers = create_headers(this.plugin)
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'pass',
          'validate_bounce',
        ),
      )
      assert(find_bounce_headers_stub.calledOnce)
      assert(
        find_bounce_headers_stub.calledWith(
          this.connection.transaction,
          this.connection.transaction.body,
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('has incorrect hash', function (done) {
    this.plugin.cfg.reject.hash_validation = false

    hash = crypto
      .createHmac(
        this.plugin.cfg.validation.hash_algorithm,
        crypto.randomBytes(32).toString('base64'),
      )
      .update(amalgam)
      .digest('hex')

    const headers = create_headers(this.plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'hash does not match',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will deny when incorrect hash', function (done) {
    hash = crypto
      .createHmac(
        this.plugin.cfg.validation.hash_algorithm,
        crypto.randomBytes(32).toString('base64'),
      )
      .update(amalgam)
      .digest('hex')

    const headers = create_headers(this.plugin, { hash })
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'hash does not match',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'invalid bounce')
      done()
    }, this.connection)
  })

  it('is missing the From header', function (done) {
    this.plugin.cfg.reject.hash_validation = false

    const headers = create_headers(this.plugin)
    delete headers.from
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'missing headers',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('is missing the Date header', function (done) {
    this.plugin.cfg.reject.hash_validation = false

    const headers = create_headers(this.plugin)
    delete headers.date
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'missing headers',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('is missing the Message-ID header', function (done) {
    this.plugin.cfg.reject.hash_validation = false

    const headers = create_headers(this.plugin)
    delete headers.message_id
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'missing headers',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will deny when missing the From header', function (done) {
    const headers = create_headers(this.plugin)
    delete headers.from
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'missing headers',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'invalid bounce')
      done()
    }, this.connection)
  })

  it('will deny when missing the Date header', function (done) {
    const headers = create_headers(this.plugin)
    delete headers.date
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'missing headers',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'invalid bounce')
      done()
    }, this.connection)
  })

  it('will deny when missing the Message-ID header', function (done) {
    const headers = create_headers(this.plugin)
    delete headers.message_id
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'missing headers',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'invalid bounce')
      done()
    }, this.connection)
  })

  it('is missing hash header and address parsing fails', function (done) {
    const from = 'mail delivery system <mailer-daemon@example.com>'
    const rcpt = new Address.Address('test@example.com')

    this.plugin.cfg.reject.hash_validation = false
    this.connection.transaction.rcpt_to[0] = rcpt
    this.connection.transaction.add_header('From', from)

    const headers = create_headers(this.plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'missing validation hash',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('is missing hash header and email address is whitelisted', function (done) {
    this.plugin.cfg.whitelist = { 'test@example.com': ['no-reply@example.com'] }

    const from = '<no-reply@example.com>'
    const rcpt = new Address.Address('test@example.com')

    this.connection.transaction.rcpt_to[0] = rcpt
    this.connection.transaction.add_header('From', from)

    const headers = create_headers(this.plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'skip',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'whitelisted',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('is missing hash header and sender domain is whitelisted', function (done) {
    this.plugin.cfg.whitelist = { 'bar@example.com': ['*@example.net'] }

    const from = '<info@example.net>'
    const rcpt = new Address.Address('bar@example.com')

    this.connection.transaction.rcpt_to[0] = rcpt
    this.connection.transaction.add_header('From', from)

    const headers = create_headers(this.plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'skip',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'whitelisted',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('is missing hash header and has invalid from header', function (done) {
    const from = '<invalid>'
    this.connection.transaction.add_header('From', from)

    const headers = create_headers(this.plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'skip',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'invalid from header',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)

      done()
    }, this.connection)
  })

  it('is missing hash header', function (done) {
    const from = '<info@example.net>'
    this.connection.transaction.add_header('From', from)
    this.plugin.cfg.reject.hash_validation = false

    const headers = create_headers(this.plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'missing validation hash',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will deny when missing hash header', function (done) {
    const from = '<info@example.net>'
    this.connection.transaction.add_header('From', from)

    const headers = create_headers(this.plugin)
    delete headers.hash
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'missing validation hash',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'invalid bounce')
      done()
    }, this.connection)
  })

  it('is missing all headers', function (done) {
    const headers = {}
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'skip',
          'validate_bounce',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'missing all headers',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will Deny when hash is too old', function (done) {
    this.plugin.cfg.reject.hash_date = true
    const eightDaysAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 8)
    date_header = eightDaysAgo.toUTCString()

    const headers = create_headers(this.plugin, { date_header })
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'bounce_date',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'hash is too old',
        ),
      )
      assert(find_bounce_headers_stub.calledOnce)
      assert(
        find_bounce_headers_stub.calledWith(
          this.connection.transaction,
          this.connection.transaction.body,
        ),
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'invalid bounce')
      done()
    }, this.connection)
  })

  it('hash is too old', function (done) {
    this.plugin.cfg.reject.hash_date = false
    const eightDaysAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 8)
    date_header = eightDaysAgo.toUTCString()

    const headers = create_headers(this.plugin, { date_header })
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'bounce_date',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'hash is too old',
        ),
      )
      assert(find_bounce_headers_stub.calledOnce)
      assert(
        find_bounce_headers_stub.calledWith(
          this.connection.transaction,
          this.connection.transaction.body,
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('has invalid date header', function (done) {
    this.plugin.cfg.reject.hash_date = false
    date_header = 'invalid date'

    const headers = create_headers(this.plugin, { date_header })
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'bounce_date',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'invalid date header',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will DENY when date header is invalid', function (done) {
    date_header = 'invalid date'

    const headers = create_headers(this.plugin, { date_header })
    find_bounce_headers_stub.returns(headers)

    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'bounce_date',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'invalid date header',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'invalid bounce')
      done()
    }, this.connection)
  })
})

describe('find_bounce_headers', function () {
  let date_header, from_header, message_id, hash, amalgam
  let msg_body, transaction

  beforeEach(function () {
    date_header = new Date().toISOString()
    from_header = '<test@EXAMPLE.com>'
    message_id = '<test@example.COM>'

    this.plugin.cfg.validation = {
      hash_algorithm: 'sha256',
      secret: crypto.randomBytes(32).toString('base64'),
    }

    amalgam = `${from_header}:${date_header}:${message_id}`
    hash = crypto
      .createHmac(
        this.plugin.cfg.validation.hash_algorithm,
        this.plugin.cfg.validation.secret,
      )
      .update(amalgam)
      .digest('hex')

    msg_body = `
X-Haraka-Bounce-Validation: ${hash}
From: ${from_header}
Date: ${date_header}
Message-ID: ${message_id}
`
    transaction = this.connection.transaction

    transaction.body = {
      bodytext: msg_body,
      children: [],
    }
  })

  it('has no body', function () {
    delete transaction.body

    const headers = this.plugin.find_bounce_headers(transaction.body)

    assert.equal(JSON.stringify(headers), '{}')
  })

  it('has all headers in body', function () {
    const headers = this.plugin.find_bounce_headers(transaction.body)

    assert.equal(headers.from, from_header)
    assert.equal(headers.date, date_header)
    assert.equal(headers.message_id, message_id)
    assert.equal(headers.hash, hash)
  })

  it('has From header in body', function () {
    transaction.body.bodytext = `From: ${from_header}\n`

    const headers = this.plugin.find_bounce_headers(transaction.body)

    assert.equal(headers.from, from_header)
    assert.equal(headers.date, undefined)
    assert.equal(headers.message_id, undefined)
    assert.equal(headers.hash, undefined)
  })

  it('has Date header in body', function () {
    transaction.body.bodytext = `Date: ${date_header}\n`

    const headers = this.plugin.find_bounce_headers(transaction.body)

    assert.equal(headers.from, undefined)
    assert.equal(headers.date, date_header)
    assert.equal(headers.message_id, undefined)
    assert.equal(headers.hash, undefined)
  })

  it('has one header in body', function () {
    transaction.body.bodytext = `Date: ${date_header}\n`

    const headers = this.plugin.find_bounce_headers(transaction.body)

    assert.equal(headers.from, undefined)
    assert.equal(headers.date, date_header)
    assert.equal(headers.message_id, undefined)
    assert.equal(headers.hash, undefined)
  })

  it('has no headers in body', function () {
    transaction.body = {
      bodytext: 'no headers in this body',
      children: [],
    }

    const headers = this.plugin.find_bounce_headers(transaction.body)

    assert.equal(headers.from, undefined)
    assert.equal(headers.date, undefined)
    assert.equal(headers.message_id, undefined)
    assert.equal(headers.hash, undefined)
  })

  it('has headers in body.children', function () {
    transaction.body = {
      bodytext: 'Hello World',
      children: [{ bodytext: msg_body }],
    }

    const headers = this.plugin.find_bounce_headers(transaction.body)

    assert.equal(headers.from, from_header)
    assert.equal(headers.date, date_header)
    assert.equal(headers.message_id, message_id)
    assert.equal(headers.hash, hash)
  })

  it('has folded headers', function () {
    from_header = `"Dr. Smith - Back & Neck Care Center of San Fransisco" <dr.smith@example.com>`
    hash = crypto
      .createHmac(
        this.plugin.cfg.validation.hash_algorithm,
        this.plugin.cfg.validation.secret,
      )
      .update(amalgam)
      .digest('hex')

    transaction.body.bodytext = `
Message-ID: ${message_id}
Date: ${date_header}
From: "Dr. Smith - Back & Neck Care Center of San Fransisco"
  <dr.smith@example.com>
X-Haraka-Bounce-Validation: ${hash}
`
    const headers = this.plugin.find_bounce_headers(transaction.body)

    assert.equal(headers.from, from_header)
    assert.equal(headers.date, date_header)
    assert.equal(headers.message_id, message_id)
    assert.equal(headers.hash, hash)
  })
})

describe('should_skip', function () {
  let has_null_sender_spy

  beforeEach(function () {
    has_null_sender_spy = sinon.spy(this.plugin, 'has_null_sender')
  })

  it('is relaying and is not a bounce', function () {
    this.connection.transaction.mail_from = new Address.Address(
      '<test@example.com>',
    )
    this.connection.relaying = true

    const result = this.plugin.should_skip(this.connection)

    assert.equal(result, true)
    assert.ok(has_null_sender_spy.calledOnce)
    assert.ok(has_null_sender_spy.returned(false))
  })

  it('is relaying and is a bounce', function () {
    this.connection.relaying = true

    const result = this.plugin.should_skip(this.connection)

    assert.equal(result, true)
    assert.ok(has_null_sender_spy.calledOnce)
    assert.ok(has_null_sender_spy.returned(true))
  })

  it('is not relaying and is not a bounce', function () {
    this.connection.transaction.mail_from = new Address.Address(
      '<test@example.com>',
    )
    this.connection.relaying = false

    const result = this.plugin.should_skip(this.connection)

    assert.equal(result, true)
    assert.ok(has_null_sender_spy.calledOnce)
    assert.ok(has_null_sender_spy.returned(false))
  })

  it('is not relaying and is a bounce', function () {
    this.connection.relaying = false

    const result = this.plugin.should_skip(this.connection)

    assert.equal(result, false)
    assert.ok(has_null_sender_spy.calledOnce)
    assert.ok(has_null_sender_spy.returned(true))
  })
})

describe('find_received_headers', function () {
  beforeEach(function () {
    this.connection.transaction.body = { bodytext: '', children: [] }
  })

  it('has no Received headers', function () {
    const ips = this.plugin.find_received_headers(
      this.connection.transaction.body,
    )

    assert.equal(ips.size, 0)
  })

  it('has one Received header', function () {
    const ip = '209.85.128.52'
    const received_headers = `Received: from example.com (example.com [${ip}])`
    this.connection.transaction.body.bodytext = received_headers

    const ips = this.plugin.find_received_headers(
      this.connection.transaction.body,
    )

    assert.equal(ips.size, 1)
    assert.ok(ips.has(ip))
  })

  it('has two Received headers with one private IP', function () {
    const ip1 = '10.10.10.10'
    const ip2 = '209.85.128.52'
    const received_headers = `
Received: from mx (mx.example.com [${ip1}])
Received: from mail.example.com (HELO mail.example.com) (${ip2})
`
    this.connection.transaction.body.bodytext = received_headers

    const ips = this.plugin.find_received_headers(
      this.connection.transaction.body,
    )

    assert.equal(ips.size, 1)
    assert.ok(ips.has(ip2))
  })

  it('has two Received headers with public IPs', function () {
    const ip1 = '108.177.12.26'
    const ip2 = '209.85.128.52'
    const received_headers = `
Received: from mx (mx.example.com [${ip1}])
Received: from mail.example.com (mail.example.com [${ip2}])
`
    this.connection.transaction.body.bodytext = received_headers

    const ips = this.plugin.find_received_headers(
      this.connection.transaction.body,
    )

    assert.equal(ips.size, 2)
    assert.ok(ips.has(ip1))
    assert.ok(ips.has(ip2))
  })

  it('has two Received headers with IPv4 and IPv6 IPs', function () {
    const ip1 = '108.177.12.26'
    const ip2 = '2603:10b6:8:189::16'
    const ip3 = '2603:10b6:303:e9::7'
    const received_headers = `
Received: from mx (mx.example.com [${ip1}])
Received: from prod.example.com
 ([${ip2}]) by prod.example.com (${ip3})
`
    this.connection.transaction.body.bodytext = received_headers

    const ips = this.plugin.find_received_headers(
      this.connection.transaction.body,
    )

    assert.equal(ips.size, 2)
    assert.ok(ips.has(ip1))
    assert.ok(ips.has(ip2))
  })

  it('has Received headers in child', function () {
    const ip1 = '108.177.12.26'
    const ip2 = '209.85.128.52'
    const received_headers = `
Received: from mx (mx.example.com [${ip1}])
Received: from mail.example.com (mail.example.com [${ip2}])
`
    this.connection.transaction.body.children[0] = {
      bodytext: received_headers,
      children: [],
    }
    const ips = this.plugin.find_received_headers(
      this.connection.transaction.body,
    )

    assert.equal(ips.size, 2)
    assert.ok(ips.has(ip1))
    assert.ok(ips.has(ip2))
  })
})

describe('is_date_valid', function () {
  beforeEach(function () {
    this.plugin.cfg.validation.max_hash_age_days = 6
  })

  it('has recent date', function (done) {
    const oneDayAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 1)
    const date_header = oneDayAgo.toUTCString()

    const result = this.plugin.is_date_valid(date_header)
    assert(result.valid)
    done()
  })

  it('has expired date', function (done) {
    const SevenDaysAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 7)
    const date_header = SevenDaysAgo.toUTCString()
    const result = this.plugin.is_date_valid(date_header)
    assert.equal(result.valid, false)
    assert.equal(result.msg, 'hash is too old')
    done()
  })

  it('has invalid date', function (done) {
    const not_a_date = 'hello world'
    const result = this.plugin.is_date_valid(not_a_date)
    assert.equal(result.valid, false)
    assert.equal(result.msg, 'invalid date header')
    done()
  })
})

describe('is_whitelisted', function () {
  it('is not whitelisted', function () {
    this.plugin.cfg.whitelist = {}

    const whitelisted = this.plugin.is_whitelisted(
      'test@example.com',
      'support@example.com',
    )

    assert.equal(whitelisted, false)
  })

  it('is whitelisted with an exact match', function () {
    this.plugin.cfg.whitelist = { 'test@example.com': ['support@example.com'] }

    const whitelisted = this.plugin.is_whitelisted(
      'test@example.com',
      'support@example.com',
    )

    assert.ok(whitelisted)
  })

  it('is whitelisted with a wildcard match', function () {
    this.plugin.cfg.whitelist = {
      'test@example.com': ['support@example.net', '*@example.com'],
    }

    const whitelisted = this.plugin.is_whitelisted(
      'test@example.com',
      'support@example.com',
    )

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
      .createHmac(
        plugin.cfg.validation.hash_algorithm,
        plugin.cfg.validation.secret,
      )
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
