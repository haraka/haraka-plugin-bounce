'use strict'

const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const { describe, it, beforeEach } = require('node:test')

const { makePlugin } = require('haraka-test-fixtures')

let plugin

beforeEach(() => {
  plugin = makePlugin('bounce')
})

describe('register', () => {
  it('loads all configs', () => {
    delete plugin.cfg

    plugin.register()

    assert.ok(plugin.cfg.check) // load_bounce_ini
    assert.ok(plugin.cfg.reject)
    assert.ok(plugin.cfg.validation)
    assert.ok(plugin.cfg.invalid_addrs) // load_bounce_bad_rcpt
    assert.ok(plugin.cfg.whitelist) // load_bounce_whitelist
  })

  it('registers hooks', () => {
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
    plugin.load_bounce_ini()

    assert.ok(plugin.cfg.check)
    assert.ok(plugin.cfg.reject)
    // validate_config ran and applied its defaults
    assert.equal(plugin.cfg.validation.hash_algorithm, 'sha256')
    assert.equal(plugin.cfg.validation.max_hash_age_days, 6)
  })

  it('load_bounce_bad_rcpt', () => {
    plugin.load_bounce_bad_rcpt()

    assert.ok(Array.isArray(plugin.cfg.invalid_addrs))
  })

  it('load_bounce_whitelist', () => {
    plugin.load_bounce_whitelist()

    assert.ok(plugin.cfg.whitelist)
  })
})

describe('validate_config', () => {
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
  })

  it('will enable single recipient check', () => {
    plugin.cfg.check.single_recipient = false

    plugin.validate_config()

    assert.ok(plugin.cfg.check.single_recipient)
  })

  it('will enable empty return path check', () => {
    plugin.cfg.reject.empty_return_path = true

    plugin.validate_config()

    assert.ok(plugin.cfg.check.empty_return_path)
  })

  it('will enable bounce SPF check', () => {
    plugin.cfg.check.bounce_spf = false
    plugin.cfg.reject.bounce_spf = true

    plugin.validate_config()

    assert.ok(plugin.cfg.check.bounce_spf)
  })

  it('will enable hash date check', () => {
    plugin.cfg.check.hash_validation = true
    plugin.cfg.check.hash_date = false
    plugin.cfg.reject.hash_date = true

    plugin.validate_config()

    assert.ok(plugin.cfg.check.hash_date)
  })

  it('will not check hash validation', () => {
    plugin.validate_config()

    assert.equal(plugin.cfg.check.hash_validation, false)
  })

  it('has invalid hash algorithm', () => {
    plugin.cfg.check.hash_validation = true
    plugin.cfg.validation.hash_algorithm = 'invalid_algorithm'

    plugin.validate_config()

    assert.equal(plugin.cfg.check.hash_validation, false)
  })

  it('is missing the secret key', () => {
    delete plugin.cfg.validation.secret
    plugin.cfg.check.hash_validation = true

    plugin.validate_config()

    assert.equal(plugin.cfg.check.hash_validation, false)
  })

  it('has short secret key', () => {
    plugin.cfg.validation.secret = 'short_key'
    plugin.cfg.check.hash_validation = true

    plugin.validate_config()

    assert.equal(plugin.cfg.check.hash_validation, false)
  })

  it('has default config settings', () => {
    plugin.cfg.check.hash_validation = true
    plugin.cfg.validation.secret = 'your_generated_secret_here'

    plugin.validate_config()

    assert.equal(plugin.cfg.check.hash_validation, false)
  })

  it('has valid config settings', () => {
    plugin.cfg.check.hash_validation = true
    plugin.cfg.validation.secret = 'valid_secret_thats_at_least_32_characters_long'

    plugin.validate_config()

    assert.equal(plugin.cfg.check.hash_validation, true)
  })
})
