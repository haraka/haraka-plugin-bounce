const crypto = require('node:crypto')
const spfLib = require('./lib/spf')
const validationLib = require('./lib/validation')

const MAX_HASH_AGE_DAYS = 6

exports.register = function () {
  this.load_bounce_ini()
  this.load_bounce_bad_rcpt()
  this.load_bounce_whitelist()

  this.register_hook('mail', 'check_null_sender', -5)
  this.register_hook('mail', 'reject_all')
  this.register_hook('rcpt_ok', 'bad_rcpt')
  this.register_hook('data', 'single_recipient')
  this.register_hook('data', 'bounce_spf_enable')
  // must run before the Headers plugin's invalid_return_path() which removes Return-Path headers.
  this.register_hook('data_post', 'empty_return_path', -5)
  this.register_hook('data_post', 'create_validation_hash')
  this.register_hook('data_post', 'validate_bounce')
  // must run after validate_bounce
  this.register_hook('data_post', 'bounce_spf')
}

exports.load_bounce_ini = function () {
  this.cfg = this.config.get(
    'bounce.ini',
    {
      booleans: [
        '+check.single_recipient',
        '-check.empty_return_path',
        '+check.bounce_spf',
        '-check.hash_validation',
        '+check.hash_date',

        '+reject.single_recipient',
        '-reject.empty_return_path',
        '-reject.bounce_spf',
        '+reject.bad_rcpt',
        '-reject.all_bounces',
        '-reject.hash_validation',
        '-reject.hash_date',

        '-skip.remaining_plugins',
      ],
    },
    () => this.load_bounce_ini(),
  )

  this.validate_config()

  // legacy settings
  const c = this.cfg
  if (c.check.reject_all) c.reject.all_bounces = c.check.reject_all
}

exports.validate_config = function () {
  const { check, reject, validation } = this.cfg

  if (!validation.max_hash_age_days) validation.max_hash_age_days = MAX_HASH_AGE_DAYS
  if (!validation.hash_algorithm) validation.hash_algorithm = 'sha256'

  // checks need to be enabled for rejects to work
  for (const key of ['single_recipient', 'empty_return_path', 'bounce_spf', 'hash_validation']) {
    if (reject[key] && !check[key]) check[key] = true
  }

  if (!check.hash_validation) return
  if (reject.hash_date && !check.hash_date) check.hash_date = true

  // confirm that hash algorithm is supported
  const algorithms = crypto.getHashes()
  if (!algorithms.includes(validation.hash_algorithm)) {
    this.logerror(`Bounce validation disabled due to invalid hash algorithm: ${validation.hash_algorithm}`)
    check.hash_validation = false
    return
  }

  if (!validation.secret || validation.secret === 'your_generated_secret_here') {
    this.logerror(`Bounce validation disabled due to missing secret.`)
    check.hash_validation = false
    return
  }

  if (validation.secret.length < 32) {
    this.logerror('Bounce validation disabled due to secret that is too short.')
    check.hash_validation = false
    return
  }
}

exports.load_bounce_bad_rcpt = function () {
  const raw_list = this.config.get('bounce_bad_rcpt', 'list', () => {
    this.load_bounce_bad_rcpt()
  })

  this.cfg.invalid_addrs = raw_list.map((n) => n.toLowerCase())
}

exports.load_bounce_whitelist = function () {
  this.cfg.whitelist = this.config.get('bounce_whitelist.json', () => {
    this.load_bounce_whitelist()
  })
}

/*
 * Special cases:
 * - Microsoft Exchange will send mail to distribution groups using a
 *   null sender if the "report_to_originator_enabled" property is false.
 * - Some email providers (e.g., gmx.net) send DMARC reports with a null sender
 * - Some auto-responders send replies with a null sender
 */
exports.check_null_sender = function (next, connection) {
  if (!connection?.transaction?.mail_from) return next()

  const isa = connection.transaction.mail_from.isNull()
  connection.transaction.results.add(this, {
    isa,
    human: `isa: ${isa ? 'yes' : 'no'}`,
    emit: true,
  })

  next()
}

// Tri-state: true if a bounce (null sender), false if not, undefined before
// check_null_sender has run.
exports.is_a_bounce = function (connection) {
  return connection.transaction?.results?.get(this)?.isa
}

exports.reject_all = function (next, connection) {
  if (!connection?.transaction) return next()
  if (!this.cfg.reject.all_bounces) return next()
  if (this.should_skip(connection)) return next()

  const { transaction } = connection

  transaction.results.add(this, {
    fail: 'bounces_accepted',
    msg: 'Bounces not accepted here',
    emit: true,
  })

  next(DENY, 'Bounces not accepted here')
}

exports.single_recipient = function (next, connection) {
  if (!connection?.transaction) return next()
  if (!this.cfg.check.single_recipient) return next()
  if (this.should_skip(connection)) return next()

  const { transaction } = connection

  if (transaction.rcpt_to.length === 1) {
    transaction.results.add(this, { pass: 'single_recipient', emit: true })
    return next()
  }

  connection.loginfo(this, `bounce with too many recipients to: ${transaction.rcpt_to.join(',')}`)

  transaction.results.add(this, {
    fail: 'single_recipient',
    msg: 'too many recipients',
    emit: true,
  })

  if (this.cfg.reject.single_recipient) {
    return next(DENY, 'this bounce message has too many recipients')
  }

  next()
}

/*
 * Per RFC 3834, bounce messages should have an empty Return-Path header.
 * Check for presence and verify that it's missing or '<>'.
 *
 * Special cases:
 * - Microsoft Exchange distribution lists with null sender may include a Return-Path
 */
exports.empty_return_path = function (next, connection) {
  if (!connection?.transaction) return next()
  if (!this.cfg.check.empty_return_path) return next()
  if (this.should_skip(connection)) return next()

  const { transaction } = connection

  const rp = transaction.header.get('Return-Path')
  if (!rp || rp === '<>') {
    transaction.results.add(this, { pass: 'empty_return_path' })
    return next()
  }

  transaction.results.add(this, {
    fail: 'empty_return_path',
    msg: 'bounce with non-empty Return-Path',
    emit: true,
  })

  if (this.cfg.reject.empty_return_path) {
    return next(DENY, 'bounce with non-empty Return-Path (RFC 3834)')
  }

  next()
}

/*
 * Rejects bounces sent to recipients that should never receive bounces.
 * Rejects when recipient's email address is listed in 'bounce_bad_rcpt'
 */
exports.bad_rcpt = function (next, connection, rcpt) {
  if (!connection?.transaction) return next()
  if (!this.cfg.reject.bad_rcpt) return next()
  if (this.should_skip(connection)) return next()

  const { transaction } = connection

  if (this.cfg.invalid_addrs.includes(rcpt.address.toLowerCase())) {
    transaction.results.add(this, {
      fail: 'bad_rcpt',
      msg: 'rcpt does not accept bounces',
      emit: true,
    })
    return next(DENY, `${rcpt.address} does not accept bounces`)
  }

  transaction.results.add(this, { pass: 'bad_rcpt' })

  next()
}

exports.bounce_spf_enable = function (next, connection) {
  if (!connection?.transaction) return next()
  if (this.should_skip(connection)) return next()

  if (this.cfg.check.bounce_spf) connection.transaction.parse_body = true
  next()
}

/*
 * SPF validates IP addresses found in bounce message headers.
 *
 * This function:
 * 1. Extracts IP addresses from Received headers in the message body
 * 2. Performs SPF validation for each IP using the recipient's domain
 * 3. Passes when any IP passes SPF
 * 4. Fails if all IPs fail SPF
 *
 * SPF Results:
 * - PASS: Message is accepted (likely a legitimate bounce)
 * - NONE/TEMPERROR/PERMERROR: Check is skipped
 * - NEUTRAL/SOFTFAIL/FAIL: Message fails validation
 */
// Injectable SPF lookup; overridden in tests to avoid live DNS.
exports.spf_lookup = spfLib.defaultLookup

exports.bounce_spf = async function (next, connection) {
  if (!connection?.transaction?.body) return next()
  if (!this.cfg.check.bounce_spf) return next()
  if (this.should_skip(connection)) return next()
  if (connection.transaction.results.has(this, 'pass', 'validate_bounce')) return next()

  const { transaction } = connection

  // Recurse through all textual parts and store all parsed IPs in a Set
  const ips = spfLib.findReceivedHeaders(transaction.body)
  if (ips.size === 0) {
    connection.loginfo(this, 'No received headers found in message')
    transaction.results.add(this, {
      skip: 'bounce_spf',
      msg: 'no IP addresses found in message',
    })
    return next()
  }

  connection.logdebug(this, `found IPs to check: ${[...ips]}`)

  const verdict = await spfLib.evaluate(ips, transaction.rcpt_to[0], this.spf_lookup)

  if (verdict.type === 'pass') {
    connection.loginfo(this, `valid bounce originated from ${verdict.ip}`)
    transaction.results.add(this, { pass: 'bounce_spf' })
    return next()
  }

  if (verdict.type === 'skip') {
    transaction.results.add(this, { skip: 'bounce_spf', msg: verdict.msg })
    return next()
  }

  transaction.results.add(this, {
    fail: 'bounce_spf',
    msg: verdict.msg,
    emit: true,
  })
  if (this.cfg.reject.bounce_spf) {
    return next(DENY, 'Invalid bounce (spoofed sender)')
  }
  next()
}

/*
 * Adds a validation hash to outbound emails.
 * This hash will be verified when bounce messages are received.
 *
 * Security considerations:
 * - The secret key must remain confidential
 * - The same secret must be used across all servers in your infrastructure
 * - The hash is time-bound to prevent replay attacks
 * - Uses timing-safe comparison to prevent timing attacks
 *
 * Note: only applies to outbound messages.
 */
exports.create_validation_hash = function (next, connection) {
  if (!connection?.transaction) return next()
  if (!this.cfg.check.hash_validation) return next()

  const { transaction } = connection

  if (!connection.relaying || this.is_a_bounce(connection)) {
    return next()
  }

  const from_header = transaction.header.get_decoded('From')
  const date_header = transaction.header.get_decoded('Date')
  const message_id_header = transaction.header.get_decoded('Message-ID')

  // are any of these headers missing?
  if (!from_header || !date_header || !message_id_header) return next()

  const hash = validationLib.computeHash(this.cfg.validation.hash_algorithm, this.cfg.validation.secret, {
    from: from_header,
    date: date_header,
    message_id: message_id_header,
  })

  transaction.add_header('X-Haraka-Bounce-Validation', hash)

  next()
}

/*
 * Validates a bounce message using hash validation.
 *
 * Security features:
 * - Uses crypto.timingSafeEqual() to prevent timing attacks
 * - Validates bounce age to prevent replay attacks with old messages
 * - Checks that all required headers are present
 * - Ensures hash length matches to prevent buffer comparison issues
 * - Falls back to whitelist checking when hash is missing but headers are present
 *
 * Result states:
 * - pass(validate_bounce): Hash matches and date is valid, bounce is legitimate
 * - fail(validate_bounce): Hash mismatch, missing headers, or not whitelisted
 * - fail(bounce_date): Hash matches but date is expired or invalid
 * - skip(validate_bounce): Whitelisted sender, invalid from header, or missing all headers
 *
 * Special handling:
 * - When validation passes and skip.remaining_plugins is enabled, returns OK to skip remaining plugins
 * - When hash is missing but From/Date/Message-ID are present, checks whitelist
 * - Whitelist supports exact matches and domain wildcards (e.g., *@example.com)
 *
 * Note: This only applies to inbound messages with a null sender.
 */
exports.validate_bounce = function (next, connection) {
  if (!connection?.transaction?.body) return next()
  if (!this.cfg.check.hash_validation) return next()
  if (this.should_skip(connection)) return next()

  const { transaction } = connection
  const headers = validationLib.findBounceHeaders(transaction.body)

  const verdict = validationLib.verify(headers, {
    algorithm: this.cfg.validation.hash_algorithm,
    secret: this.cfg.validation.secret,
    maxAgeDays: this.cfg.validation.max_hash_age_days,
    whitelist: this.cfg.whitelist,
    rcpt: transaction.rcpt_to[0]?.address?.toLowerCase(),
    fromHeader: transaction.header.get_decoded('From')?.toLowerCase(),
  })

  if (verdict.parseError) {
    connection.loginfo(this, `@haraka/email-address parsing error: ${verdict.parseError}`)
  }

  if (verdict.type === 'pass') {
    transaction.results.add(this, { pass: 'validate_bounce' })
    if (this.cfg.skip.remaining_plugins) return next(OK)
    return next()
  }

  if (verdict.type === 'skip') {
    transaction.results.add(this, { skip: 'validate_bounce', msg: verdict.msg, emit: verdict.emit })
    return next()
  }

  transaction.results.add(this, { fail: verdict.value, msg: verdict.msg, emit: true })
  if (this.cfg.reject[verdict.rejectOn]) return next(DENY, 'invalid bounce')
  next()
}

// skip checks for outbound emails and non-bounces
exports.should_skip = function (connection) {
  if (connection.relaying) return true
  return this.is_a_bounce(connection) === false
}
