'use strict'
const assert = require('node:assert/strict')
const sinon = require('sinon')

const Address = require('address-rfc2821')
const fixtures = require('haraka-test-fixtures')
const message = require('haraka-email-message')
const { SPF } = require('haraka-plugin-spf')

beforeEach(function () {
  this.plugin = new fixtures.plugin('bounce')
  this.plugin.cfg = {
    main: {},
    check: {
      single_recipient: true,
      empty_return_path: true,
      non_local_msgid: true,
      bounce_spf: true,
    },
    reject: {
      all_bounces: false,
      single_recipient: true,
      empty_return_path: true,
      bad_rcpt: true,
      non_local_msgid: true,
      bounce_spf: true,
    },
    host_list: ['example.net'],
  }

  this.connection = fixtures.connection.createConnection()
  this.connection.remote.ip = '8.8.8.8'
  this.connection.transaction = {
    header: new message.Header(),
    results: new fixtures.results(this.plugin),
    mail_from: new Address.Address('<>'),
    rcpt_to: [new Address.Address('test@example.com')],
  }
})

describe('load_configs', function () {
  it('load_bounce_ini', function (done) {
    this.plugin.load_bounce_ini()
    assert.ok(this.plugin.cfg.main)
    assert.ok(this.plugin.cfg.check)
    assert.ok(this.plugin.cfg.reject)
    done()
  })

  it('load_bounce_bad_rcpt', function (done) {
    this.plugin.load_bounce_bad_rcpt()
    assert.ok(this.plugin.cfg.invalid_addrs)
    done()
  })

  it('load_host_list', function (done) {
    this.plugin.load_host_list()
    assert.ok(this.plugin.cfg.host_list)
    done()
  })

  it('load_allowed_msgid_domains', function (done) {
    this.plugin.load_allowed_msgid_domains()
    assert.ok(this.plugin.cfg.allowed_msgid_domains)
    done()
  })
})

describe('reject_all', function () {
  it('disabled', function (done) {
    this.connection.transaction.mail_from = new Address.Address(
      '<test@example.com>',
    )
    this.plugin.cfg.check.reject_all = false
    this.plugin.reject_all(
      (code, msg) => {
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        done()
      },
      this.connection,
      new Address.Address('<test@example.com>'),
    )
  })

  it('not a bounce', function (done) {
    this.connection.transaction.mail_from = new Address.Address(
      '<test@example.com>',
    )
    this.plugin.cfg.check.reject_all = true
    this.plugin.reject_all(
      (code, msg) => {
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        done()
      },
      this.connection,
      new Address.Address('<test@example.com>'),
    )
  })

  it('allow - bounces', function (done) {
    this.plugin.cfg.reject.all_bounces = false
    this.plugin.reject_all(
      (code, msg) => {
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        done()
      },
      this.connection,
      new Address.Address('<>'),
    )
  })

  it('reject - bounces', function (done) {
    this.plugin.cfg.reject.all_bounces = true
    this.plugin.reject_all(
      (code, msg) => {
        assert.equal(code, DENY)
        assert.equal(msg, 'No bounces accepted here')
        done()
      },
      this.connection,
      [new Address.Address('<>')],
    )
  })

  it('reject_all - missing transaction', function (done) {
    this.plugin.cfg.reject.all_bounces = true

    delete this.connection.transaction

    this.plugin.reject_all(
      (code, msg) => {
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        done()
      },
      this.connection,
      [new Address.Address('<>')],
    )
  })
})

describe('empty_return_path', function () {
  it('missing Return-Path header', function (done) {
    this.plugin.empty_return_path((code, msg) => {
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
    this.connection.transaction.header.add('Return-Path', '<>')
    this.plugin.empty_return_path((code, msg) => {
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

  it('allow - non-empty Return-Path header', function (done) {
    this.connection.transaction.header.add(
      'Return-Path',
      "Content doesn't matter",
    )

    this.plugin.cfg.reject.empty_return_path = false

    this.plugin.empty_return_path((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'empty_return_path',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('reject - non-empty Return-Path header', function (done) {
    this.connection.transaction.header.add(
      'Return-Path',
      "Content doesn't matter",
    )

    this.plugin.empty_return_path((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'empty_return_path',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'bounce with non-empty Return-Path (RFC 3834)')
      done()
    }, this.connection)
  })

  it('empty_return_path - missing transaction', function (done) {
    this.plugin.cfg.check.empty_return_path = true

    delete this.connection.transaction

    this.plugin.empty_return_path((code, msg) => {
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })
})

describe('non_local_msgid', function () {
  beforeEach(function (done) {
    this.plugin.load_host_list()
    this.plugin.load_allowed_msgid_domains()

    this.connection.transaction.body = { bodytext: '', children: [] }

    done()
  })

  it('no msgid in headers', function (done) {
    this.plugin.non_local_msgid((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'Message-ID',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(
        msg,
        "bounce without Message-ID in headers, I didn't send it",
      )
      done()
    }, this.connection)
  })

  it('allow - no domains in msgid', function (done) {
    this.plugin.cfg.reject.non_local_msgid = false
    this.connection.transaction.body.bodytext = 'Message-ID:<blah>'
    this.plugin.non_local_msgid((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'Message-ID',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('reject - no domains in msgid', function (done) {
    this.connection.transaction.body.bodytext = 'Message-ID:<blah>'
    this.plugin.non_local_msgid((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'Message-ID',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(
        msg,
        "bounce without Message-ID in headers, I didn't send it",
      )
      done()
    }, this.connection)
  })

  it('reject invalid msgid', function (done) {
    this.connection.transaction.body.bodytext = 'Message-ID: <@example.com>'
    this.plugin.non_local_msgid((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'Message-ID',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(
        msg,
        "bounce without Message-ID in headers, I didn't send it",
      )
      done()
    }, this.connection)
  })

  it('domain in msgid matches host_list', function (done) {
    this.plugin.cfg.host_list = 'example.net'
    this.connection.transaction.body.bodytext = 'Message-ID: <test@example.net>'
    this.plugin.non_local_msgid((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'pass',
          'Message-ID valid domain',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('domain in multiple msgids matches host_list', function (done) {
    this.plugin.cfg.host_list = 'example.net'
    this.connection.transaction.body.bodytext =
      'Message-ID: <test@example.net>\nMessage-ID: <bar@example.org>'
    this.connection.transaction.body.children[0] = {
      bodytext: 'Message-ID: <foo@example.net>',
      children: [],
    }

    this.plugin.non_local_msgid((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'pass',
          'Message-ID valid domain',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('valid domain in msgid matches recipient host', function (done) {
    this.connection.transaction.body.bodytext = 'Message-ID: <test@example.com>'
    this.plugin.non_local_msgid((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'pass',
          'Message-ID valid domain',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('allow - no valid domains in msgid', function (done) {
    this.plugin.cfg.reject.non_local_msgid = false
    this.connection.transaction.body.bodytext =
      'Message-ID: <blah@foo.cooooooom>'
    this.plugin.non_local_msgid((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'Message-ID parseable',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('reject - no valid domains in msgid', function (done) {
    this.connection.transaction.body = new message.Body()
    this.connection.transaction.body.bodytext =
      'Message-ID: <blah@foo.cooooooom>'
    this.plugin.non_local_msgid((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'Message-ID parseable',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(
        msg,
        "bounce Message-ID without valid domain, I didn't send it",
      )
      done()
    }, this.connection)
  })

  it('allow - non-local domain in msgid', function (done) {
    this.plugin.cfg.reject.non_local_msgid = false
    this.connection.transaction.body.bodytext = 'Message-ID: <blah@foo.com>'
    this.plugin.non_local_msgid((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'Message-ID non-local domain',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('reject - non-local domain in msgid', function (done) {
    this.connection.transaction.body.bodytext = 'Message-ID: <blah@foo.com>'
    this.plugin.non_local_msgid((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'Message-ID non-local domain',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(
        msg,
        "bounce Message-ID with non-local domain, I didn't send it",
      )
      done()
    }, this.connection)
  })

  it('domain in msgid matches allowed msgid', function (done) {
    this.plugin.cfg.allowed_msgid_domains = ['test.example.org']
    this.connection.transaction.body.bodytext =
      'Message-ID: <test@test.example.org>'
    this.plugin.non_local_msgid((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'pass',
          'Message-ID allowed domain',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('non_local_msgid - missing transaction', function (done) {
    this.plugin.cfg.check.non_local_msgid = true

    delete this.connection.transaction

    this.plugin.non_local_msgid((code, msg) => {
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })
})

describe('single_recipient', function () {
  it('relay', function (done) {
    this.connection.relaying = true
    this.connection.transaction.rcpt_to.push(
      new Address.Address('test2@example.com'),
    )
    this.plugin.single_recipient((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'skip',
          'single_recipient(relay)',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('private', function (done) {
    this.connection.remote.is_private = true
    this.connection.transaction.rcpt_to.push(
      new Address.Address('test2@example.com'),
    )
    this.plugin.single_recipient((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'skip',
          'single_recipient(private_ip)',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })

  it('single recipient', function (done) {
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

  it('allow - multiple recipients', function (done) {
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

  it('reject - multiple recipients', function (done) {
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
      assert.equal(code, DENY)
      assert.equal(msg, 'this bounce message has too many recipients')
      done()
    }, this.connection)
  })

  it('single_recipient - missing transaction', function (done) {
    this.plugin.cfg.check.single_recipient = true

    delete this.connection.transaction

    this.plugin.single_recipient((code, msg) => {
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })
})

describe('bad_rcpt', function () {
  beforeEach(function (done) {
    this.plugin.cfg.invalid_addrs = ['test@bad1.com', 'test@bad2.com']
    done()
  })

  it('no invalid addresses', function (done) {
    this.plugin.cfg.invalid_addrs = []
    const rcpt = new Address.Address('test@good.com')
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

  it('good recipient', function (done) {
    const rcpt = new Address.Address('test@good.com')
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

  it('bad recipient', function (done) {
    const rcpt = new Address.Address('test@bad1.com')
    this.plugin.bad_rcpt(
      (code, msg) => {
        assert.ok(
          this.connection.transaction.results.has(
            this.plugin,
            'fail',
            'bad_rcpt',
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

  it('bad_rcpt - missing transaction', function (done) {
    this.plugin.cfg.reject.bad_rcpt = true

    delete this.connection.transaction

    this.plugin.reject_all(
      (code, msg) => {
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        done()
      },
      this.connection,
      [new Address.Address('<>')],
    )
  })
})

describe('has_null_sender', function () {
  it('<>', function (done) {
    this.connection.transaction.mail_from = new Address.Address('<>')
    assert.ok(this.plugin.has_null_sender(this.connection.transaction))

    assert.ok(
      this.connection.transaction.results.has(this.plugin, 'isa', 'yes'),
    )
    done()
  })

  it(' ', function (done) {
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
    this.connection.transaction = undefined

    this.plugin.bounce_spf_enable((code, msg) => {
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })
})

describe('bounce_spf', function () {
  beforeEach(function (done) {
    this.connection.transaction.body = {
      bodytext: '',
      children: [],
    }
    this.connection.transaction.parse_body = true

    this.SPF_NONE = 1
    this.SPF_PASS = 2
    this.SPF_FAIL = 3
    this.SPF_SOFTFAIL = 4
    this.SPF_NEUTRAL = 5
    this.SPF_TEMPERROR = 6
    this.SPF_PERMERROR = 7

    this.SPF_check_host_Spy = sinon.stub(SPF.prototype, 'check_host')
    this.SPF_constructor_Spy = sinon.stub(SPF.prototype, 'constructor')

    done()
  })

  afterEach(function () {
    sinon.restore()
  })

  it('skip SPF check', async function () {
    this.plugin.cfg.check.bounce_spf = false

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(this.SPF_constructor_Spy.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('no null sender', async function () {
    this.connection.transaction.mail_from = new Address.Address(
      '<test@example.com>',
    )

    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(this.plugin, 'isa', 'no'),
      )
      assert.ok(this.SPF_constructor_Spy.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('no IPs', async function () {
    await this.plugin.bounce_spf((code, msg) => {
      assert.ok(
        this.connection.transaction.results.has(this.plugin, 'isa', 'yes'),
      )
      assert.ok(this.SPF_constructor_Spy.notCalled)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('SPF_TEMPERROR', async function () {
    this.connection.transaction.body.bodytext = 'Received: from [2001:db8::1]'
    this.connection.transaction.rcpt_to = [
      new Address.Address('test@example.com'),
    ]

    this.SPF_check_host_Spy.returns(this.SPF_TEMPERROR)

    await this.plugin.bounce_spf((code, msg) => {
      sinon.assert.calledOnceWithExactly(
        this.SPF_check_host_Spy,
        '2001:db8::1',
        'example.com',
        'test@example.com',
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'skip',
          'bounce_spf',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('SPF_PERMERROR', async function () {
    this.connection.transaction.body.bodytext = 'Received: from [2001:db8::1]'
    this.connection.transaction.rcpt_to = [
      new Address.Address('test@example.com'),
    ]

    this.SPF_check_host_Spy.returns(this.SPF_PERMERROR)

    await this.plugin.bounce_spf((code, msg) => {
      sinon.assert.calledOnceWithExactly(
        this.SPF_check_host_Spy,
        '2001:db8::1',
        'example.com',
        'test@example.com',
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'skip',
          'bounce_spf',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('SPF_NONE', async function () {
    this.connection.transaction.body.bodytext = 'Received: from [2001:db8::1]'
    this.connection.transaction.rcpt_to = [
      new Address.Address('test@example.com'),
    ]

    this.SPF_check_host_Spy.returns(this.SPF_NONE)

    await this.plugin.bounce_spf((code, msg) => {
      sinon.assert.calledOnceWithExactly(
        this.SPF_check_host_Spy,
        '2001:db8::1',
        'example.com',
        'test@example.com',
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'skip',
          'bounce_spf',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('SPF_PASS', async function () {
    this.connection.transaction.body.bodytext =
      'Received: from [10.1.1.10]\nReceived: from [2001:db8::1]'
    this.connection.transaction.rcpt_to = [
      new Address.Address('test@example.com'),
    ]

    this.SPF_check_host_Spy.returns(this.SPF_PASS)

    await this.plugin.bounce_spf((code, msg) => {
      sinon.assert.calledOnceWithExactly(
        this.SPF_check_host_Spy,
        '2001:db8::1',
        'example.com',
        'test@example.com',
      )
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
    this.connection.transaction.body.bodytext =
      'Received: from [192.0.2.1]\nReceived: from [2001:db8::1]'
    this.connection.transaction.rcpt_to = [
      new Address.Address('test@example.com'),
    ]

    this.SPF_check_host_Spy.returns(this.SPF_NEUTRAL)

    await this.plugin.bounce_spf((code, msg) => {
      sinon.assert.calledOnceWithExactly(
        this.SPF_check_host_Spy,
        '2001:db8::1',
        'example.com',
        'test@example.com',
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'bounce_spf',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'Invalid bounce (spoofed sender)')
    }, this.connection)
  })

  it('SPF_SOFTFAIL', async function () {
    this.connection.transaction.body.bodytext =
      'Received: from [192.0.2.1]\nReceived: from [2001:db8::1]'
    this.connection.transaction.rcpt_to = [
      new Address.Address('test@example.com'),
    ]

    this.SPF_check_host_Spy.returns(this.SPF_SOFTFAIL)

    await this.plugin.bounce_spf((code, msg) => {
      sinon.assert.calledOnceWithExactly(
        this.SPF_check_host_Spy,
        '2001:db8::1',
        'example.com',
        'test@example.com',
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'bounce_spf',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'Invalid bounce (spoofed sender)')
    }, this.connection)
  })

  it('skip SPF reject', async function () {
    this.connection.transaction.body.bodytext =
      'Received: from [192.0.2.1]\nReceived: from [2001:db8::1]'
    this.connection.transaction.rcpt_to = [
      new Address.Address('test@example.com'),
    ]
    this.plugin.cfg.reject.bounce_spf = false

    this.SPF_check_host_Spy.returns(this.SPF_FAIL)

    await this.plugin.bounce_spf((code, msg) => {
      sinon.assert.calledOnceWithExactly(
        this.SPF_check_host_Spy,
        '2001:db8::1',
        'example.com',
        'test@example.com',
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'bounce_spf',
        ),
      )
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
    }, this.connection)
  })

  it('SPF_FAIL', async function () {
    this.connection.transaction.body.bodytext = 'Received: from [2001:db8::1]'
    this.connection.transaction.rcpt_to = [
      new Address.Address('test@example.com'),
    ]

    this.SPF_check_host_Spy.returns(this.SPF_FAIL)

    await this.plugin.bounce_spf((code, msg) => {
      sinon.assert.calledOnceWithExactly(
        this.SPF_check_host_Spy,
        '2001:db8::1',
        'example.com',
        'test@example.com',
      )
      assert.ok(
        this.connection.transaction.results.has(
          this.plugin,
          'fail',
          'bounce_spf',
        ),
      )
      assert.equal(code, DENY)
      assert.equal(msg, 'Invalid bounce (spoofed sender)')
    }, this.connection)
  })

  it('bounce_spf - missing transaction', function (done) {
    this.plugin.cfg.check.bounce_spf = true

    delete this.connection.transaction

    this.plugin.bounce_spf((code, msg) => {
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, this.connection)
  })
})
