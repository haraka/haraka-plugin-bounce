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
  this.connection.transaction = fixtures.transaction.createTransaction()
  this.connection.init_transaction()
  this.connection.transaction.mail_from = new Address.Address('<>')
  this.connection.transaction.rcpt_to.push(
    new Address.Address('test@example.com'),
  )

  this.validate_config_stub = sinon.stub(this.plugin, 'validate_config')

  this.plugin.register()
})

afterEach(sinon.restore)

describe('register', function () {
  it('should have register function', function () {
    assert.ok(this.plugin)
    assert.equal('function', typeof this.plugin.register)
  })

  it('registers hooks', function () {
    assert.ok(this.plugin.register_hook.called)
    assert.equal(this.plugin.register_hook.args.length, 9)
    assert.equal(this.plugin.register_hook.args[0][1], 'reject_all')
    assert.equal(this.plugin.register_hook.args[1][1], 'bad_rcpt')
    assert.equal(this.plugin.register_hook.args[2][1], 'single_recipient')
    assert.equal(this.plugin.register_hook.args[3][1], 'bounce_spf_enable')
    assert.equal(this.plugin.register_hook.args[4][1], 'empty_return_path')
    assert.equal(this.plugin.register_hook.args[5][1], 'create_validation_hash')
    assert.equal(this.plugin.register_hook.args[6][1], 'validate_bounce')
    assert.equal(this.plugin.register_hook.args[7][1], 'validate_date')
    assert.equal(this.plugin.register_hook.args[8][1], 'bounce_spf')
  })
})

describe('load_configs', function () {
  it('load_bounce_ini', function () {
    this.plugin.load_bounce_ini()
    assert.ok(this.plugin.cfg.check)
    assert.ok(this.plugin.cfg.reject)
    assert.ok(this.plugin.cfg.validation)
  })

  it('load_bounce_bad_rcpt', function () {
    this.plugin.load_bounce_bad_rcpt()
    assert.ok(this.plugin.cfg.invalid_addrs)
  })

  it('load_bounce_whitelist', function () {
    this.plugin.load_bounce_whitelist()
    assert.ok(this.plugin.cfg.whitelist)
  })
})

describe('validate_config', function () {
  beforeEach(function () {
    this.validate_config_stub.restore()

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
    sinon.stub(crypto, 'getHashes').returns(['sha256', 'sha512', 'md5'])
  })

  it('will enable single recipient check', function () {
    this.plugin.cfg.check.single_recipient = false

    this.plugin.validate_config()

    assert.ok(this.plugin.cfg.check.single_recipient)
  })

  it('will enable empty return path check', function () {
    this.plugin.cfg.reject.empty_return_path = true

    this.plugin.validate_config()

    assert.ok(this.plugin.cfg.check.empty_return_path)
  })

  it('will enable bounce SPF check', function () {
    this.plugin.cfg.check.bounce_spf = false
    this.plugin.cfg.reject.bounce_spf = true

    this.plugin.validate_config()

    assert.ok(this.plugin.cfg.check.bounce_spf)
  })

  it('will enable hash date check', function () {
    this.plugin.cfg.check.hash_date = false
    this.plugin.cfg.reject.hash_date = true

    this.plugin.validate_config()

    assert.ok(this.plugin.cfg.check.hash_date)
  })

  it('has invalid hash algorithm', function () {
    this.plugin.cfg.validation.hash_algorithm = 'invalid_algorithm'

    this.plugin.validate_config()

    assert.equal(this.plugin.cfg.check.hash_validation, false)
  })

  it('is missing the secret key', function () {
    delete this.plugin.cfg.validation.secret

    this.plugin.validate_config()

    assert.equal(this.plugin.cfg.check.hash_validation, false)
  })

  it('has short secret key', function () {
    this.plugin.cfg.validation.secret = 'short_key'

    this.plugin.validate_config()

    assert.equal(this.plugin.cfg.check.hash_validation, false)
  })

  it('has valid config settings', function () {
    this.plugin.cfg.validation.secret =
      'valid_secret_thats_at_least_32_characters_long'

    this.plugin.validate_config()

    assert.equal(this.plugin.cfg.check.hash_validation, false)
  })
})

describe('reject_all', function () {
  let should_skip_spy

  beforeEach(function () {
    this.plugin.cfg.reject.all_bounces = true
    should_skip_spy = sinon.spy(this.plugin, 'should_skip')
  })

  it('will allow bounces', function (done) {
    this.plugin.cfg.reject.all_bounces = false
    this.plugin.reject_all((code, msg) => {
      assert.ok(should_skip_spy.notCalled)
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
      assert.ok(should_skip_spy.returned(true))
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
      assert.ok(should_skip_spy.returned(true))
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will reject all bounces', function (done) {
    this.plugin.reject_all((code, msg) => {
      assert.ok(should_skip_spy.returned(false))
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
  let should_skip_spy

  beforeEach(function () {
    this.plugin.cfg.check.empty_return_path = true
    this.plugin.cfg.reject.empty_return_path = true
    should_skip_spy = sinon.spy(this.plugin, 'should_skip')
  })

  it('empty_return_path - missing transaction', function (done) {
    delete this.connection.transaction

    this.plugin.empty_return_path((code, msg) => {
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('missing Return-Path header', function (done) {
    this.plugin.empty_return_path((code, msg) => {
      assert.ok(should_skip_spy.returned(false))
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
      assert.ok(should_skip_spy.returned(false))
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
      assert.ok(should_skip_spy.returned(false))
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
      assert.ok(should_skip_spy.returned(false))
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
    const should_skip_spy = sinon.spy(this.plugin, 'should_skip')

    this.plugin.cfg.check.single_recipient = false
    this.plugin.single_recipient((code, msg) => {
      assert.ok(should_skip_spy.notCalled)
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
    const should_skip_spy = sinon.spy(this.plugin, 'should_skip')
    this.plugin.cfg.reject.bad_rcpt = false

    this.plugin.reject_all(
      (code, msg) => {
        assert.ok(should_skip_spy.notCalled)
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
  it('<>', function (done) {
    assert.ok(this.plugin.has_null_sender(this.connection.transaction))

    assert.ok(
      this.connection.transaction.results.has(this.plugin, 'isa', 'yes'),
    )
    done()
  })

  it('', function (done) {
    this.connection.transaction.mail_from = new Address.Address('')
    assert.ok(this.plugin.has_null_sender(this.connection.transaction))
    assert.ok(
      this.connection.transaction.results.has(this.plugin, 'isa', 'yes'),
    )
    done()
  })

  it('user@example.com', function (done) {
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

  let should_skip_spy, find_received_headers_spy
  let check_host_stub
  let spf

  beforeEach(function () {
    this.connection.transaction.body = {
      bodytext: `Received: from example.com (example.com [96.7.128.198])`,
      children: [],
    }
    this.connection.transaction.parse_body = true
    this.connection.transaction.mail_from = new Address.Address('<>')

    this.plugin.cfg.reject.bounce_spf = true

    should_skip_spy = sinon.spy(this.plugin, 'should_skip')
    find_received_headers_spy = sinon.spy(this.plugin, 'find_received_headers')
    check_host_stub = sinon.stub(SPF.prototype, 'check_host')

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
      assert.ok(should_skip_spy.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('will skip outbound mail', async function () {
    this.connection.relaying = true

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(should_skip_spy.calledOnce)
      assert.ok(find_received_headers_spy.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('will skip when not a null sender', async function () {
    this.connection.transaction.mail_from = new Address.Address(
      '<test@example.com>',
    )

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(should_skip_spy.calledOnce)
      assert.ok(
        this.connection.transaction.results.has(this.plugin, 'isa', 'no'),
      )
      assert.ok(find_received_headers_spy.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('will skip when hash validation passed', async function () {
    this.connection.transaction.results.add(this.plugin, {
      pass: 'validate_bounce',
    })

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(should_skip_spy.calledOnce)
      assert.ok(find_received_headers_spy.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('no IPs', async function () {
    this.connection.transaction.body.bodytext = ''

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(this.plugin, 'isa', 'yes'),
      )
      assert(find_received_headers_spy.calledOnce)
      assert(
        find_received_headers_spy.calledWith(this.connection.transaction.body),
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

  it('SPF_TEMPERROR', async function () {
    check_host_stub.returns(spf.SPF_TEMPERROR)

    await this.plugin.bounce_spf((code, msg) => {
      sinon.assert.calledOnce(check_host_stub)
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
    check_host_stub.returns(spf.SPF_PERMERROR)

    await this.plugin.bounce_spf((code, msg) => {
      sinon.assert.calledOnce(check_host_stub)
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
    check_host_stub.returns(spf.SPF_NONE)

    await this.plugin.bounce_spf((code, msg) => {
      sinon.assert.calledOnce(check_host_stub)
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
    check_host_stub.returns(spf.SPF_PASS)

    await this.plugin.bounce_spf((code, msg) => {
      sinon.assert.calledOnce(check_host_stub)
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
    check_host_stub.returns(spf.SPF_NEUTRAL)

    await this.plugin.bounce_spf((code, msg) => {
      sinon.assert.calledOnce(check_host_stub)
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
    check_host_stub.returns(spf.SPF_SOFTFAIL)

    await this.plugin.bounce_spf((code, msg) => {
      sinon.assert.calledOnce(check_host_stub)
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
    check_host_stub.returns(spf.SPF_FAIL)

    this.plugin.cfg.reject.bounce_spf = false

    await this.plugin.bounce_spf((code, msg) => {
      sinon.assert.calledOnce(check_host_stub)
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
    check_host_stub.returns(spf.SPF_FAIL)

    await this.plugin.bounce_spf((code, msg) => {
      sinon.assert.calledOnce(check_host_stub)
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
      assert.equal(this.plugin.cfg.check.hash_validation, false)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('missing From, Date, and Message-ID headers', function (done) {
    this.plugin.create_validation_hash((code, msg) => {
      sinon.assert.calledThrice(get_decoded_stub)
      assert.equal(this.plugin.cfg.check.hash_validation, false)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })
})

describe('validate_bounce', function () {
  let should_skip_spy
  let hash, amalgam
  let date_header, from_header, message_id

  beforeEach(function () {
    this.plugin.cfg.whitelist = {
      'test@example.com': ['no-reply@example.com', 'support@example.com'],
      'foo@example.com': ['sales@example.com'],
      'bar@example.com': ['*@example.net', 'office@example.com'],
    }

    this.plugin.cfg.reject.hash_validation = true
    this.plugin.cfg.check.hash_validation = true
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

    const headers = {
      from: from_header,
      date: date_header,
      message_id: message_id,
      hash: hash,
    }
    this.connection.transaction.notes.set('bounce.headers', headers)

    should_skip_spy = sinon.spy(this.plugin, 'should_skip')
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
      assert.ok(should_skip_spy.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('has hash size that is too short', function (done) {
    this.plugin.cfg.reject.hash_validation = false

    hash = '1234567890'
    this.connection.transaction.notes.set('bounce.headers.hash', hash)

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

  it('has hash size that is too long', function (done) {
    this.plugin.cfg.reject.hash_validation = false

    hash =
      '1234567890123456789012345678901234567890123456789012345678901234567890'
    this.connection.transaction.notes.set('bounce.headers.hash', hash)

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
    hash = '1234567890'
    this.connection.transaction.notes.set('bounce.headers.hash', hash)

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
    this.plugin.validate_bounce((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'pass',
          'validate_bounce',
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
    this.connection.transaction.notes.set('bounce.headers.hash', hash)

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
    this.connection.transaction.notes.set('bounce.headers.hash', hash)

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

  it('is missing a header', function (done) {
    this.plugin.cfg.reject.hash_validation = false
    delete this.connection.transaction.notes.bounce.headers.message_id

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

  it('will deny when missing a header', function (done) {
    delete this.connection.transaction.notes.bounce.headers.message_id

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

  it('is missing hash header and email address is whitelisted', function (done) {
    const from = '<no-reply@example.com>'
    const rcpt = new Address.Address('test@example.com')

    this.connection.transaction.rcpt_to[0] = rcpt
    this.connection.transaction.add_header('From', from)

    delete this.connection.transaction.notes.bounce.headers.hash

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
    const from = '<info@example.net>'
    const rcpt = new Address.Address('bar@example.com')

    this.connection.transaction.rcpt_to[0] = rcpt
    this.connection.transaction.add_header('From', from)

    delete this.connection.transaction.notes.bounce.headers.hash

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

  it('is missing hash header', function (done) {
    this.plugin.cfg.reject.hash_validation = false

    delete this.connection.transaction.notes.bounce.headers.hash

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
    delete this.connection.transaction.notes.bounce.headers.hash

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
    delete this.connection.transaction.notes.bounce.headers

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

    const headers = this.plugin.find_bounce_headers(
      transaction,
      transaction.body,
    )

    assert.equal(JSON.stringify(headers), '{}')
  })

  it('has cached headers in a transaction.note', function () {
    const headers = {
      from: from_header,
      date: date_header,
      message_id: message_id,
      hash: hash,
    }
    this.connection.transaction.notes.set('bounce.headers', headers)
    const body_headers = this.plugin.find_bounce_headers(
      transaction,
      transaction.body,
    )

    assert.equal(body_headers.from, from_header)
    assert.equal(body_headers.date, date_header)
    assert.equal(body_headers.message_id, message_id)
    assert.equal(body_headers.hash, hash)
  })

  it('has all headers in body', function () {
    const headers = this.plugin.find_bounce_headers(
      transaction,
      transaction.body,
    )

    assert.equal(headers.from, from_header)
    assert.equal(headers.date, date_header)
    assert.equal(headers.message_id, message_id)
    assert.equal(headers.hash, hash)
  })

  it('has one header in body', function () {
    transaction.body.bodytext = `Date: ${date_header}\n`

    const headers = this.plugin.find_bounce_headers(
      transaction,
      transaction.body,
    )

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

    const headers = this.plugin.find_bounce_headers(
      transaction,
      transaction.body,
    )
    assert.equal(headers.from, undefined)
    assert.equal(headers.date, undefined)
    assert.equal(headers.message_id, undefined)
    assert.equal(headers.hash, undefined)
  })

  it('saves headers in notes', function () {
    this.plugin.find_bounce_headers(transaction, transaction.body)

    assert.equal(transaction.notes.bounce.headers.from, from_header)
    assert.equal(transaction.notes.bounce.headers.date, date_header)
    assert.equal(transaction.notes.bounce.headers.message_id, message_id)
    assert.equal(transaction.notes.bounce.headers.hash, hash)
  })

  it('has headers in body.children', function () {
    transaction.body = {
      bodytext: 'Hello World',
      children: [{ bodytext: msg_body }],
    }

    const headers = this.plugin.find_bounce_headers(
      transaction,
      transaction.body,
    )

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
    const headers = this.plugin.find_bounce_headers(
      transaction,
      transaction.body,
    )

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

describe('validate_date', function () {
  let find_bounce_headers_spy
  let date_header

  beforeEach(function () {
    this.plugin.cfg.reject.hash_validation = true
    this.plugin.cfg.validation.max_hash_age_days = 6

    this.connection.transaction.body = {
      bodytext: '',
      children: [],
    }

    date_header = new Date().toISOString()

    find_bounce_headers_spy = sinon.spy(this.plugin, 'find_bounce_headers')
  })

  it('validate_date - missing transaction', function (done) {
    delete this.connection.transaction

    this.plugin.empty_return_path((code, msg) => {
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('skips when invalid date header', function (done) {
    date_header = 'invalid date'
    this.connection.transaction.body.bodytext = `Date: ${date_header}\n`

    this.plugin.validate_date((code, msg) => {
      assert.ok(find_bounce_headers_spy.calledOnce)
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'skip',
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

  it('skips when missing date header', function (done) {
    this.plugin.validate_date((code, msg) => {
      assert.ok(find_bounce_headers_spy.calledOnce)
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'skip',
          'bounce_date',
        ),
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'msg',
          'missing date header',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('has old hash', function (done) {
    const eightDaysAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 8)
    date_header = eightDaysAgo.toUTCString()

    this.connection.transaction.body.bodytext = `Date: ${date_header}\n`
    this.plugin.validate_date((code, msg) => {
      assert.ok(find_bounce_headers_spy.calledOnce)
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
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('will deny when old hash', function (done) {
    this.plugin.cfg.reject.hash_date = true
    const eightDaysAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 8)
    date_header = eightDaysAgo.toUTCString()

    this.connection.transaction.body.bodytext = `Date: ${date_header}\n`
    this.plugin.validate_date((code, msg) => {
      assert.ok(find_bounce_headers_spy.calledOnce)
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
      assert.equal(code, DENY)
      assert.equal(msg, 'invalid bounce')
      done()
    }, this.connection)
  })

  it('check valid date header', function (done) {
    const oneDayAgo = new Date(new Date() - 1000 * 60 * 60 * 24 * 1)
    date_header = oneDayAgo.toUTCString()
    this.connection.transaction.body.bodytext = `Date: ${date_header}\n`

    this.plugin.validate_date((code, msg) => {
      assert.ok(find_bounce_headers_spy.calledOnce)
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'pass',
          'bounce_date',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
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
