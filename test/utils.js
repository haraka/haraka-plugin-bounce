'use strict'

const assert = require('node:assert/strict')
const { describe, it, beforeEach } = require('node:test')

const { Address } = require('@haraka/email-address')
const { makeConnection, makePlugin } = require('haraka-test-fixtures')

let plugin, connection

beforeEach(() => {
  plugin = makePlugin('bounce')
  connection = makeConnection({ ip: '8.8.8.8', mailFrom: '<>', rcptTo: ['test@example.com'] })
})

describe('should_skip', () => {
  it('is relaying and is not a bounce', () => {
    connection.transaction.mail_from = new Address('<test@example.com>')
    connection.relaying = true
    connection.transaction.results.add(plugin, { isa: false })

    assert.equal(plugin.should_skip(connection), true)
  })

  it('is relaying and is a bounce', () => {
    connection.relaying = true
    connection.transaction.results.add(plugin, { isa: true })

    assert.equal(plugin.should_skip(connection), true)
  })

  it('is not relaying and is not a bounce', () => {
    connection.transaction.mail_from = new Address('<test@example.com>')
    connection.relaying = false
    connection.transaction.results.add(plugin, { isa: false })

    assert.equal(plugin.should_skip(connection), true)
  })

  it('is not relaying and is a bounce', () => {
    connection.relaying = false
    connection.transaction.results.add(plugin, { isa: true })

    assert.equal(plugin.should_skip(connection), false)
  })
})
