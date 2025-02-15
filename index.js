// bounce tests
const tlds = require('haraka-tld')
const { SPF } = require('haraka-plugin-spf')
const net_utils = require('haraka-net-utils')

exports.register = function () {
  this.load_bounce_ini()
  this.load_bounce_bad_rcpt()
  this.load_host_list()
  this.load_allowed_msgid_domains()

  this.register_hook('mail', 'reject_all')
  this.register_hook('rcpt_ok', 'bad_rcpt')
  this.register_hook('data', 'single_recipient')
  this.register_hook('data', 'bounce_spf_enable')
  this.register_hook('data_post', 'empty_return_path')
  this.register_hook('data_post', 'bounce_spf')
  this.register_hook('data_post', 'non_local_msgid')
}

exports.load_bounce_bad_rcpt = function () {
  const raw_list = this.config.get('bounce_bad_rcpt', 'list', () => {
    this.load_bounce_bad_rcpt()
  })

  this.cfg.invalid_addrs = raw_list.map((n) => n.toLowerCase())
}

exports.load_host_list = function () {
  const raw_list = this.config.get('host_list', 'list', () => {
    this.load_host_list()
  })

  this.cfg.host_list = raw_list.map((n) => n.toLowerCase())
}

exports.load_allowed_msgid_domains = function () {
  const raw_list = this.config.get('bounce_allowed_msgid_domains', 'list', () => {
    this.load_allowed_msgid_domains()
  })

  this.cfg.allowed_msgid_domains = raw_list.map((n) => n.toLowerCase())
}

exports.load_bounce_ini = function () {
  this.cfg = this.config.get(
    'bounce.ini',
    {
      booleans: [
        '+check.single_recipient',
        '-check.empty_return_path',
        '+check.bounce_spf',
        '+check.non_local_msgid',

        '+reject.single_recipient',
        '-reject.empty_return_path',
        '-reject.bounce_spf',
        '-reject.non_local_msgid',
        '+reject.bad_rcpt',
        '-reject.all_bounces',
      ],
    },
    () => {
      this.load_bounce_ini()
    },
  )

  // legacy settings
  const c = this.cfg
  if (c.check.reject_all) c.reject.all_bounces = c.check.reject_all
}

exports.reject_all = function (next, connection) {
  if (!this.cfg.reject.all_bounces) return next()

  const { transaction } = connection
  if (!transaction) return next()

  // bounce messages are from null senders
  if (!this.has_null_sender(transaction)) return next()

  transaction.results.add(this, {
    fail: 'bounces_accepted',
    emit: true,
  })
  next(DENY, 'No bounces accepted here')
}

exports.single_recipient = function (next, connection) {
  if (!this.cfg.check.single_recipient) return next()

  const { transaction, relaying, remote } = connection
  if (!transaction) return next()

  if (!this.has_null_sender(transaction)) return next()

  // Valid bounces have a single recipient
  if (transaction.rcpt_to.length === 1) {
    transaction.results.add(this, { pass: 'single_recipient', emit: true })
    return next()
  }

  // Skip this check for relays or private_ips. This is because Microsoft
  // Exchange will send mail to distribution groups using the null-sender
  // if the option 'Do not send delivery reports' is checked
  if (relaying) {
    transaction.results.add(this, {
      skip: 'single_recipient(relay)',
      emit: true,
    })
    return next()
  }
  if (remote.is_private) {
    transaction.results.add(this, {
      skip: 'single_recipient(private_ip)',
      emit: true,
    })
    return next()
  }

  connection.loginfo(
    this,
    `bounce with too many recipients to: ${transaction.rcpt_to.join(',')}`,
  )

  transaction.results.add(this, { fail: 'single_recipient', emit: true })

  if (this.cfg.reject.single_recipient) {
    return next(DENY, 'this bounce message has too many recipients')
  }

  next()
}

exports.empty_return_path = function (next, connection) {
  if (!this.cfg.check.empty_return_path) return next()

  const { transaction } = connection
  if (!transaction) return next()

  if (!this.has_null_sender(transaction)) return next()

  // Bounce messages generally do not have a Return-Path set. This checks
  // for that. But whether it should is worth questioning...

  // On Jan 20, 2014, Matt Simerson examined the most recent 50,000 mail
  // connections for the presence of Return-Path in bounce messages. I
  // found 14 hits, 12 of which were from Google, in response to
  // undeliverable DMARC reports (IE, automated messages that Google
  // shouldn't have replied to). Another appears to be a valid bounce from
  // a poorly configured mailer, and the 14th was a confirmed spam kill.
  // Unless new data demonstrate otherwise, this should remain disabled.

  // Return-Path, aka Reverse-PATH, Envelope FROM, RFC5321.MailFrom
  // validate that the Return-Path header is empty, RFC 3834

  const rp = transaction.header.get('Return-Path')
  if (!rp || rp === '<>') {
    transaction.results.add(this, { pass: 'empty_return_path' })
    return next()
  }

  transaction.results.add(this, { fail: 'empty_return_path', emit: true })

  if (this.cfg.reject.empty_return_path) {
    return next(DENY, 'bounce with non-empty Return-Path (RFC 3834)')
  }

  next()
}

exports.bad_rcpt = function (next, connection, rcpt) {
  if (!this.cfg.reject.bad_rcpt) return next()

  const { transaction } = connection
  if (!transaction) return next()

  if (!this.has_null_sender(transaction)) return next()

  if (this.cfg.invalid_addrs.includes(rcpt.address().toLowerCase())) {
    transaction.results.add(this, { fail: 'bad_rcpt', emit: true })
    return next(DENY, `${rcpt.address()} does not accept bounces`)
  }
  transaction.results.add(this, { pass: 'bad_rcpt' })

  next()
}

exports.has_null_sender = function (transaction) {
  // bounces have a null sender.
  // null sender could also be tested with mail_from.user
  // Why would isNull() exist if it wasn't the right way to test this?
  const is_null_sender = !!transaction.mail_from.isNull()
  transaction.results.add(this, { isa: is_null_sender ? 'yes' : 'no' })
  return is_null_sender
}

const message_id_re = /^Message-ID:\s*<[^@>]+@([^>]+)>/gim  // this should match on the host name

function find_message_id_headers(domains, body, connection, self) {
  if (!body) return

 const matches = body.bodytext.matchAll(message_id_re);
 for (const match of matches) {
    domains.add(match[1].toLowerCase());
  }

  for (const child of body.children) {
    // Recurse to any MIME children
    find_message_id_headers(domains, child, connection, self)
  }
}

exports.non_local_msgid = function (next, connection) {
  if (!this.cfg.check.non_local_msgid) return next()

  const { transaction } = connection
  if (!transaction) return next()

  if (!this.has_null_sender(transaction)) return next()

  // Bounce messages usually contain the headers of the original message
  // in the body. This parses the body, searching for the Message-ID header.
  // It then inspects the contents of that header, extracting the domain part,
  // and then checks to see if that domain is local to this server.

  // NOTE: this only works reliably if *every* message sent has a local
  // domain in the Message-ID. In practice, that means outbound MXes MUST
  // check Message-ID on outbound and modify non-conforming Message-IDs.
  //
  // NOTE 2: Searching the bodytext of a bounce is too simple. The bounce
  // message should exist as a MIME Encoded part.

  const domains = new Set()
  find_message_id_headers(domains, transaction.body, connection, this)
  connection.logdebug(this, `found Message-IDs: ${[...domains].join(', ')}`)

  if (domains.size === 0) {
    connection.loginfo(this, 'no Message-ID matches')
    transaction.results.add(this, { fail: 'Message-ID' })
    if (!this.cfg.reject.non_local_msgid) return next()
    return next(
      DENY,
      `bounce without Message-ID in headers, I didn't send it`,
    )
  }

  for (const domain of domains) {
    // is domain valid?
    if (!tlds.get_organizational_domain(domain)) {
      domains.delete(domain)
    }

    // is domain allowed?
    if (this.cfg.allowed_msgid_domains.includes(domain)) {
      connection.loginfo(this, `non_local_msgid: domain matches allowed msgid`)
      transaction.results.add(this, { pass: 'Message-ID allowed domain' })
      return next()
    }

    // is local domain?
    if (this.cfg.host_list.includes(domain)) {
      connection.loginfo(this, `bounce Message-ID domain matches local host`)
      transaction.results.add(this, { pass: 'Message-ID valid domain' })
      return next()
    }

    if (domain === transaction.rcpt_to[0].host) {
      connection.loginfo(
        this,
        `bounce Message-ID domain matches the recipient host`,
      )
      transaction.results.add(this, { pass: 'Message-ID valid domain' })
      return next()
    }
  }

  if (domains.size === 0) {
    connection.loginfo(this, 'no domain(s) parsed from Message-ID headers')
    transaction.results.add(this, { fail: 'Message-ID parseable' })
    if (!this.cfg.reject.non_local_msgid) return next()
    return next(DENY, `bounce Message-ID without valid domain, I didn't send it`)
  }

  transaction.results.add(this, { fail: 'Message-ID non-local domain' })

  if (this.cfg.reject.non_local_msgid) {
    return next(
      DENY,
      `bounce Message-ID with non-local domain, I didn't send it`,
    )
  }

  next()
}

// Lazy regexp to get IPs from Received: headers in bounces
const received_re = net_utils.get_ipany_re(
  '^Received:[\\s\\S]*?[\\[\\(](?:IPv6:)?',
  '[\\]\\)]',
)

function find_received_headers(ips, body, connection, self) {
  if (!body) return
  let match
  while ((match = received_re.exec(body.bodytext))) {
    const ip = match[1]
    if (net_utils.is_private_ip(ip)) continue
    ips[ip] = true
  }
  for (let i = 0, l = body.children.length; i < l; i++) {
    // Recurse in any MIME children
    find_received_headers(ips, body.children[i], connection, self)
  }
}

exports.bounce_spf_enable = function (next, connection) {
  const { transaction } = connection
  if (!transaction) return next()

  if (this.cfg.check.bounce_spf) {
    transaction.parse_body = true
  }
  next()
}

exports.bounce_spf = async function (next, connection) {
  if (!this.cfg.check.bounce_spf) return next()

  const { transaction } = connection
  if (!transaction) return next()

  if (!this.has_null_sender(transaction)) return next()

  // Recurse through all textual parts and store all parsed IPs
  // in an object to remove any duplicates which might appear.
  let ips = {}
  find_received_headers(ips, transaction.body, connection, this)
  ips = Object.keys(ips)
  if (!ips.length) {
    connection.loginfo(this, 'No received headers found in message')
    return next()
  }

  connection.logdebug(this, `found IPs to check: ${ips.join(', ')}`)

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
      return next()
    }

    connection.logdebug(this, `ip=${ip} spf_result=${spf.result(result)}`)

    switch (result) {
      case spf.SPF_NONE:
      // falls through, domain doesn't publish an SPF record
      case spf.SPF_TEMPERROR:
      // falls through
      case spf.SPF_PERMERROR:
        // Abort as all subsequent lookups will return this
        connection.logdebug(this, `Aborted: SPF returned ${spf.result(result)}`)
        transaction.results.add(this, { skip: 'bounce_spf' })
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
  transaction.results.add(this, { fail: 'bounce_spf', emit: true })

  if (this.cfg.reject.bounce_spf) {
    return next(DENY, 'Invalid bounce (spoofed sender)')
  }

  next()
}
