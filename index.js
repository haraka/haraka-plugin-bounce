// bounce tests
const { SPF } = require('haraka-plugin-spf')
const net_utils = require('haraka-net-utils')
const crypto = require('node:crypto')
const addrparser = require('address-rfc2822')

const MAX_HASH_AGE_DAYS = 6

exports.register = function () {
  this.load_bounce_ini()
  this.load_bounce_bad_rcpt()
  this.load_bounce_whitelist()

  this.register_hook('mail', 'reject_all')
  this.register_hook('rcpt_ok', 'bad_rcpt')
  this.register_hook('data', 'single_recipient')
  this.register_hook('data', 'bounce_spf_enable')
  // must run before the Headers plugin's invalid_return_path() which removes Return-Path headers.
  this.register_hook('data_post', 'empty_return_path', -5)
  this.register_hook('data_post', 'create_validation_hash')
  this.register_hook('data_post', 'validate_bounce')
  // must run after validate_bounce
  this.register_hook('data_post', 'validate_date')
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
  if (!this.cfg.validation.max_hash_age_days)
    this.cfg.validation.max_hash_age_days = MAX_HASH_AGE_DAYS
  if (!this.cfg.validation.hash_algorithm)
    this.cfg.validation.hash_algorithm = 'sha256'

  // checks needs to be enabled for rejects to work
  if (this.cfg.reject.single_recipient && !this.cfg.check.single_recipient) {
    this.cfg.check.single_recipient = true
  }
  if (this.cfg.reject.empty_return_path && !this.cfg.check.empty_return_path) {
    this.cfg.check.empty_return_path = true
  }
  if (this.cfg.reject.bounce_spf && !this.cfg.check.bounce_spf) {
    this.cfg.check.bounce_spf = true
  }
  if (this.cfg.reject.hash_validation && !this.cfg.check.hash_validation) {
    this.cfg.check.hash_validation = true
  }

  if (!this.cfg.check.hash_validation) return

  if (this.cfg.reject.hash_date && !this.cfg.check.hash_date) {
    this.cfg.check.hash_date = true
  }

  // confirm that hash algorithm is supported
  const algorithms = crypto.getHashes()
  if (!algorithms.includes(this.cfg.validation.hash_algorithm)) {
    this.logerror(
      `Bounce validation disabled due to invalid hash algorithm: ${this.cfg.validation.hash_algorithm}`,
    )
    this.cfg.check.hash_validation = false
    return
  }

  if (
    !this.cfg.validation.secret ||
    this.cfg.validation.secret === 'your_generated_secret_here'
  ) {
    this.logerror(`Bounce validation disabled due to missing secret.`)
    this.cfg.check.hash_validation = false
    return
  }

  if (this.cfg.validation.secret.length < 32) {
    this.logerror('Bounce validation disabled due to secret that is too short.')
    this.cfg.check.hash_validation = false
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
 * Implements complete rejection of all bounce messages.
 *
 * This function performs the most restrictive validation by rejecting
 * all messages with a null sender (bounce messages). This is typically
 * used for mail servers that never need to receive bounce messages or
 * for domains that experience high levels of backscatter.
 *
 * Configuration option: reject.all_bounces (boolean)
 *
 * Note: This only applies to inbound messages with a null sender.
 */
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

/*
 * Validates that bounce messages have exactly one recipient.
 *
 * Legitimate bounce messages should be addressed to only one recipient
 * (the original sender). Multiple recipients in a bounce message typically
 * indicate a forged message or backscatter attempt.
 *
 * Configuration options:
 * - check.single_recipient (boolean): Enable this check
 * - reject.single_recipient (boolean): Reject messages that fail this check
 *
 * Note: This only applies to inbound messages with a null sender.
 */
exports.single_recipient = function (next, connection) {
  if (!connection?.transaction) return next()
  if (!this.cfg.check.single_recipient) return next()
  if (this.should_skip(connection)) return next()

  const { transaction } = connection

  // Valid bounces have a single recipient
  if (transaction.rcpt_to.length === 1) {
    transaction.results.add(this, { pass: 'single_recipient', emit: true })
    return next()
  }

  connection.loginfo(
    this,
    `bounce with too many recipients to: ${transaction.rcpt_to.join(',')}`,
  )

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
 * Validates that bounce messages have an empty Return-Path header.
 *
 * According to RFC 3834, bounce messages should have an empty Return-Path
 * header. This function checks for the presence of this header and validates
 * that it's either missing or set to '<>'.
 *
 * Configuration options:
 * - check.empty_return_path (boolean): Enable this check
 * - reject.empty_return_path (boolean): Reject messages that fail this check
 *
 * Special cases:
 * - Microsoft Exchange distribution lists with null sender may include a Return-Path
 *
 * Note: This only applies to inbound messages with a null sender.
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
 *
 * This function checks if the recipient's email address is listed in the
 * 'bounce_bad_rcpt' configuration file. This is useful for auto-responders,
 * no-reply addresses, and system addresses that should never receive bounce
 * messages.
 *
 * Configuration:
 * - reject.bad_rcpt (boolean): When true, bounces to these addresses are rejected
 *
 * Note: This only applies to inbound messages with a null sender.
 */
exports.bad_rcpt = function (next, connection, rcpt) {
  if (!connection?.transaction) return next()
  if (!this.cfg.reject.bad_rcpt) return next()
  if (this.should_skip(connection)) return next()

  const { transaction } = connection

  if (this.cfg.invalid_addrs.includes(rcpt.address().toLowerCase())) {
    transaction.results.add(this, {
      fail: 'bad_rcpt',
      msg: 'rcpt does not accept bounces',
      emit: true,
    })
    return next(DENY, `${rcpt.address()} does not accept bounces`)
  }

  transaction.results.add(this, { pass: 'bad_rcpt' })

  next()
}

/*
 * Checks message for null sender (bounces have a null sender)
 *
 * Special cases:
 * - Microsoft Exchange will send mail to distribution groups using a
 *   null sender if the "report_to_originator_enabled" property is false.
 * - Some email providers (e.g., gmx.net) send DMARC reports with a null sender
 * - Some auto-responders send replies with a null sender
 *
 * Note: This only applies to inbound messages with a null sender.
 */
exports.has_null_sender = function (transaction) {
  // Bounces have a null sender.
  // Null sender could also be tested with mail_from.user
  // Why would isNull() exist if it wasn't the right way to test this?
  const is_null_sender = transaction.mail_from.isNull() === 1
  transaction.results.add(this, { isa: is_null_sender ? 'yes' : 'no' })
  return is_null_sender
}

/*
 * Enables message body parsing for SPF checks on bounce messages.
 *
 * This function prepares the transaction for bounce_spf by setting the
 * parse_body flag. This ensures that the message body will be available
 * for extracting headers in the bounce message.
 *
 * Configuration option: check.bounce_spf (boolean)
 *
 * Note: This only applies to inbound messages with a null sender.
 */
exports.bounce_spf_enable = function (next, connection) {
  if (!connection?.transaction) return next()
  if (this.should_skip(connection)) return next()

  if (this.cfg.check.bounce_spf) {
    connection.transaction.parse_body = true
  }
  next()
}

/*
 * Performs SPF validation on IP addresses found in bounce message headers.
 *
 * This function:
 * 1. Extracts IP addresses from Received headers in the bounce message body
 * 2. Performs SPF validation for each IP using the recipient's domain
 * 3. Passes the message if any IP passes SPF validation
 * 4. Fails if all IPs fail SPF validation (potential spoofed bounce)
 *
 * Configuration options:
 * - check.bounce_spf (boolean): Enable this check
 * - reject.bounce_spf (boolean): Reject messages that fail this check
 *
 * SPF Results:
 * - PASS: Message is accepted (likely a legitimate bounce)
 * - NONE/TEMPERROR/PERMERROR: Check is skipped
 * - NEUTRAL/SOFTFAIL/FAIL: Message fails validation (potential spoofed bounce)
 *
 * Note: This only applies to inbound messages with a null sender.
 */
exports.bounce_spf = async function (next, connection) {
  if (!connection?.transaction?.body) return next()
  if (!this.cfg.check.bounce_spf) return next()
  if (this.should_skip(connection)) return next()
  if (connection.transaction.results.has(this, 'pass', 'validate_bounce'))
    return next()

  const { transaction } = connection

  // Recurse through all textual parts and store all parsed IPs
  // in a Set to remove any duplicates which might appear.
  const ips = this.find_received_headers(transaction.body)
  if (ips.size === 0) {
    connection.loginfo(this, 'No received headers found in message')
    transaction.results.add(this, {
      skip: 'bounce_spf',
      msg: 'no IP addresses found in message',
    })
    return next()
  }

  connection.logdebug(this, `found IPs to check: ${[...ips]}`)

  const spf = new SPF()

  for (const ip of ips) {
    let result
    try {
      result = await spf.check_host(
        ip,
        transaction.rcpt_to[0].host,
        transaction.rcpt_to[0].address(),
      )
    } catch (err) {
      connection.logerror(this, err.message)
      transaction.results.add(this, {
        skip: 'bounce_spf',
        msg: err.message,
      })
      return next()
    }

    const spf_result = spf.result(result)
    connection.logdebug(this, { ip, result, spf_result })

    switch (result) {
      case spf.SPF_NONE:
      // falls through, domain doesn't publish an SPF record
      case spf.SPF_TEMPERROR:
      // falls through
      case spf.SPF_PERMERROR:
        // Abort as all subsequent lookups will return this
        connection.logdebug(this, `Aborted: SPF returned ${spf.result(result)}`)
        transaction.results.add(this, {
          skip: 'bounce_spf',
          msg: `SPF returned ${spf.result(result)}`,
        })
        return next()
      case spf.SPF_PASS:
        // Presume this is a valid bounce
        // TODO: this could be spoofed; could weight each IP to combat
        connection.loginfo(this, `Valid bounce originated from ${ip}`)
        transaction.results.add(this, { pass: 'bounce_spf' })
        return next()
      default:
        continue
    }
  }

  // We've checked all the IPs and none of them returned Pass
  transaction.results.add(this, {
    fail: 'bounce_spf',
    msg: 'invalid bounce (spoofed sender)',
    emit: true,
  })

  if (this.cfg.reject.bounce_spf) {
    return next(DENY, 'Invalid bounce (spoofed sender)')
  }

  next()
}

/*
 * Creates and adds a validation hash to outbound emails.
 * This hash will be verified when bounce messages are received.
 *
 * The hash is a HMAC based on:
 * 1. From header (sender identity)
 * 2. Date header (timestamp for expiration verification)
 * 3. Message-ID header (unique message identifier)
 *
 * The cryptographic process:
 * 1. Combines these headers in the format: `${from}:${date}:${message_id}`
 * 2. Generates an HMAC using the configured algorithm and secret key
 * 3. Adds the resulting hash as an X-Haraka-Bounce-Validation header
 *
 * Security considerations:
 * - The secret key must remain confidential
 * - The same secret must be used across all servers in your infrastructure
 * - The hash is time-bound to prevent replay attacks
 * - Uses timing-safe comparison to prevent timing attacks
 *
 * Note: This only applies to outbound messages.
 */
exports.create_validation_hash = function (next, connection) {
  if (!connection?.transaction) return next()
  if (!this.cfg.check.hash_validation) return next()

  const { transaction } = connection

  if (!connection.relaying || this.has_null_sender(transaction)) {
    return next()
  }

  const from_header = transaction.header.get_decoded('From')
  const date_header = transaction.header.get_decoded('Date')
  const message_id_header = transaction.header.get_decoded('Message-ID')

  // are any of these headers missing?
  if (!from_header || !date_header || !message_id_header) {
    return next()
  }

  const amalgam = `${from_header}:${date_header}:${message_id_header}`

  const hash = crypto
    .createHmac(this.cfg.validation.hash_algorithm, this.cfg.validation.secret)
    .update(amalgam)
    .digest('hex')

  transaction.add_header('X-Haraka-Bounce-Validation', hash)

  next()
}

/*
 * Validates a bounce message using the cryptographic hash validation system.
 *
 * Verification process:
 * 1. Extracts original message headers from the bounce message body
 * 2. Recreates the amalgamated string (from:date:message_id)
 * 3. Generates a new HMAC hash using the same algorithm and secret
 * 4. Performs a timing-safe comparison between the generated hash and the one in the bounce
 * 5. If hash matches, validates the age of the bounce using the Date header
 * 6. If no hash found but headers present, checks against whitelist
 *
 * Security features:
 * - Uses crypto.timingSafeEqual() to prevent timing attacks
 * - Validates bounce age to prevent replay attacks with old messages
 * - Checks that all required headers are present
 * - Ensures hash length matches to prevent buffer comparison issues
 * - Falls back to whitelist checking when hash is missing but headers are present
 *
 * Configuration options:
 * - check.hash_validation (boolean): Enable hash-based validation
 * - reject.hash_validation (boolean): Reject bounces that fail hash validation
 * - reject.hash_date (boolean): Reject bounces with expired or invalid dates
 * - skip.remaining_plugins (boolean): Skip remaining plugins if validation passes
 * - validation.max_hash_age_days (number): Maximum age in days for bounce messages
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

  const { from, date, message_id, hash } = this.find_bounce_headers(
    transaction,
    transaction.body,
  )

  if (hash) {
    const amalgam = `${from}:${date}:${message_id}`

    const bounce_hash = crypto
      .createHmac(
        this.cfg.validation.hash_algorithm,
        this.cfg.validation.secret,
      )
      .update(amalgam)
      .digest('hex')

    let msg
    if (from && date && message_id) {
      const buff_1 = Buffer.from(bounce_hash)
      // ensure that we are comparing with same size Buffers
      const buff_2 = Buffer.concat([Buffer.from(hash)], bounce_hash.length)

      if (crypto.timingSafeEqual(buff_1, buff_2)) {
        const result = this.is_date_valid(date)
        if (result.valid) {
          transaction.results.add(this, { pass: 'validate_bounce' })
          if (this.cfg.skip.remaining_plugins) {
            return next(OK)
          }
          return next()
        } else {
          transaction.results.add(this, {
            fail: 'bounce_date',
            msg: result.msg,
            emit: true,
          })
          if (this.cfg.reject.hash_date) {
            return next(DENY, 'invalid bounce')
          }
          return next()
        }
      }

      msg =
        bounce_hash.length === hash.length
          ? 'hash does not match'
          : 'hash length mismatch'
    } else {
      msg = 'missing headers'
    }
    if (msg) {
      transaction.results.add(this, {
        fail: 'validate_bounce',
        msg: msg,
        emit: true,
      })
      if (this.cfg.reject.hash_validation) {
        return next(DENY, 'invalid bounce')
      }
      return next()
    }
  } else if (from && date && message_id) {
    const from_header = transaction.header.get_decoded('From').toLowerCase()
    let parsed_from
    try {
      parsed_from = addrparser.parse(from_header)[0].address
    } catch (err) {
      // ignore error
      connection.loginfo(this, `address-rfc2822 parsing error: ${err.message}`)

      transaction.results.add(this, {
        skip: 'validate_bounce',
        msg: 'invalid from header',
        emit: true,
      })
      return next()
    }

    const rcpt = transaction.rcpt_to[0].address().toLowerCase()

    if (this.is_whitelisted(rcpt, parsed_from)) {
      transaction.results.add(this, {
        skip: 'validate_bounce',
        msg: 'whitelisted',
      })
      return next()
    }

    transaction.results.add(this, {
      fail: 'validate_bounce',
      msg: 'missing validation hash',
      emit: true,
    })
    if (this.cfg.reject.hash_validation) {
      return next(DENY, 'invalid bounce')
    }
    return next()
  }

  transaction.results.add(this, {
    skip: 'validate_bounce',
    msg: 'missing all headers',
  })

  next()
}

exports.is_date_valid = function (date) {
  // Parse the date that the original email was sent
  const email_date = new Date(date)
  if (isNaN(email_date.getTime())) {
    return { valid: false, msg: 'invalid date header' }
  }

  // calculate the number of days since the original email was sent
  const age = Math.floor((new Date() - email_date) / (1000 * 60 * 60 * 24))
  if (age > this.cfg.validation.max_hash_age_days) {
    return { valid: false, msg: 'hash is too old' }
  }

  return { valid: true }
}

// Lazy regexp to get IPs from Received: headers in bounces
const received_re = net_utils.get_ipany_re(
  '^Received:[\\s\\S]*?[\\[\\(](?:IPv6:)?',
  '[\\]\\)]',
)

// Extracts IP addresses from Received headers in the bounce message body
exports.find_received_headers = function (body, ips = new Set()) {
  if (!body) return ips

  let match
  while ((match = received_re.exec(body.bodytext))) {
    const ip = match[1]
    if (net_utils.is_private_ip(ip)) continue
    ips.add(ip)
  }
  for (let i = 0, l = body.children.length; i < l; i++) {
    // Recurse in any MIME children
    this.find_received_headers(body.children[i], ips)
  }
  return ips
}

exports.find_bounce_headers = function (body) {
  const headers = {}

  // Check the current body part
  if (body?.bodytext?.length) {
    headers.from = extract_header(body.bodytext, 'From')
    headers.date = extract_header(body.bodytext, 'Date')
    headers.message_id = extract_header(body.bodytext, 'Message-ID')
    headers.hash = extract_header(body.bodytext, 'X-Haraka-Bounce-Validation')

    // were any headers found?
    if (headers.from || headers.date || headers.message_id || headers.hash) {
      return headers
    }
  }

  // Recursively check children
  if (body?.children?.length) {
    for (const child of body.children) {
      const child_hdrs = this.find_bounce_headers(child)

      // were any headers found?
      if (
        child_hdrs.from ||
        child_hdrs.date ||
        child_hdrs.message_id ||
        child_hdrs.hash
      ) {
        return child_hdrs
      }
    }
  }

  return headers
}

// Determines whether validation checks should be skipped
// Skips checks for outbound emails or messages that aren't bounces
exports.should_skip = function (connection) {
  const is_relaying = connection.relaying
  const not_a_bounce = !this.has_null_sender(connection.transaction)

  return is_relaying || not_a_bounce
}

// Extracts a header value from email body text
function extract_header(bodytext, header_name) {
  if (!bodytext || typeof bodytext !== 'string') return

  // Use a regular expression with named capture group for the header value
  const header_re = new RegExp(
    `^${header_name}:(?<value>[^\r\n]*(?:[\r\n]+[ \t][^\r\n]*)*?)[\r\n]+(?:[a-z\\-]+:|$)`,
    'imu',
  )

  const match = header_re.exec(bodytext)
  if (!match?.groups?.value) return

  let { value } = match.groups

  // Split by newlines, remove leading whitespace on folded lines, and join with spaces
  value = value
    .split(/[\r\n]+/u)
    .map((line, i) => (i === 0 ? line : line.replace(/^[ \t]+/u, '')))
    .join(' ')
    .trim()

  return value
}

exports.is_whitelisted = function (rcpt, from) {
  // Check if recipient has whitelist entries
  const whitelist_entries = this.cfg.whitelist[rcpt]
  if (!whitelist_entries) return false

  // Check for exact match
  if (whitelist_entries.includes(from)) return true

  // Check for domain wildcard match
  return whitelist_entries.some(
    (addr) => addr.startsWith('*@') && from.endsWith(addr.substring(1)),
  )
}
