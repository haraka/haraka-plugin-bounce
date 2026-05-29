'use strict'

const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const { describe, it, beforeEach, afterEach } = require('node:test')
const sinon = require('sinon')

const { makeConnection, makePlugin } = require('haraka-test-fixtures')

let plugin, connection, should_skip_spy

beforeEach(() => {
  plugin = makePlugin('bounce')
  connection = makeConnection({ ip: '8.8.8.8', mailFrom: '<>', rcptTo: ['test@example.com'] })
  should_skip_spy = sinon.spy(plugin, 'should_skip')
  void should_skip_spy
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

  it.skip('registers hooks', () => {
    assert.deepEqual(plugin.hooks, {
      mail: ['check_null_sender', 'reject_all'],
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
