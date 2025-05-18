[![CI Test Status][ci-img]][ci-url]
[![Code Climate][clim-img]][clim-url]

# haraka-plugin-bounce

This plugin provides multiple configurable strategies to detect, validate, and process email bounces, helping protect your mail server from backscatter, forged bounces, and bounce-based attacks.

Key capabilities include:

- Validating bounce message authenticity using cryptographic hashes
- Filtering based on bounce characteristics (single recipient, return path)
- SPF validation for bounce messages
- Configurable whitelist for legitimate null-sender messages
- Fine-grained rejection controls for each validation method

## Configuration

Each feature can be enabled/disabled with a true/false toggle in the `[validation]`, `[check]`, or `[reject]`sections of `config/bounce.ini`:

Some features can have rejections disabled in the `[reject]` section.

The hash validation feature will automatically be disabled unless a secret key is created. You can create the secret key by running `openssl rand -base64 32`.

```ini
[validation]
max_hash_age_days=6
hash_algorithm=sha256
secret=

[check]
single_recipient=true
empty_return_path=false
bounce_spf=true
hash_validation=false
hash_date=true

[reject]
single_recipient=true
empty_return_path=false
bounce_spf=false
hash_date=false
bad_rcpt=true
all_bounces=false
hash_validation=false
hash_date=false
```

## Features

### enable_hash

Adds a X-Haraka-Bounce-Validation header to outbound emails to help verify the authenticity of bounce messages. The header contains an HMAC SHA-256 hash created using the message's From, Date, and Message-ID headers, and a configured secret key.

Create the secret key by running `openssl rand -base64 32` and adding the result to the secret setting in the config file.

This header is used to verify the authenticity of incoming bounce messages by recreating and comparing the hash. If this is enabled on one server, it should be enabled on all servers.

### hash_algorithm

The cryptographic algorithm to use for hash generation. The default is sha256. Other algorithms may be supported by Node.js crypto module (run crypto.getHashes() for options)

### secret

A cryptographic secret used for hash generation. Must be at least 32 characters long for adequate security. Create the secret key by running `openssl rand -base64 32` and adding the result to this setting in `config/bounce.ini`.
**CRITICAL:** Must be kept private and consistent across all mail servers

### single_recipient

Valid bounces have a single recipient. Assure that the message really is a bounce by enforcing bounces to be addressed to a single recipient.

This check is skipped for relays or hosts with a private IP, this is because Microsoft Exchange distribution lists will send messages to list members with a null return-path when the 'Do not send delivery reports' option is enabled (yes, really...).

### empty_return_path

Valid bounces should have an empty return path. Test for the presence of the Return-Path header in bounces and disallow.

### bounce_spf

Parses the message body and any MIME parts for Received: headers and strips out the IP addresses of each Received hop and then checks what the SPF result would have been if bounced message had been sent by that hop.

If no 'Pass' result is found, then this test will fail. If SPF returns 'None', 'TempError' or 'PermError' then the test will be skipped.

### hash_date

When enabled, verifies that the hash was created within the last config/max_hash_age_days.

### bad_rcpt

When enabled, rejects bounces to email addresses listed in `config/bounce_bad_rcpt`.

Include email addresses that should _never_ receive bounce messages. Examples of email addresses that should be listed are: autoresponders, do-not-reply@example.com, dmarc-feedback@example.com, and any other email addresses used solely for machine generated messages.

### all_bounces

When enabled, blocks all bounce messages using the simple rule of checking for `MAIL FROM:<>`.

It is generally a bad idea to block all bounces. This option can be useful for mail servers at domains with frequent spoofing and few or no human users.

## Whitelist

You can whitelist emails with null senders by adding the recipient to `config/bounce_whitelist.json` with an array of From email addresses. You can also whitelist the From domain by replacing the user portion with an asterisk, i.e. `*@example.com`.

```json
{
  "test@example.com": ["no-reply@example.com", "support@example.com"],
  "foo@example.com": ["sales@example.com"],
  "bar@example.com": ["*@example.net", "office@example.com"]
}
```

## INSTALL

cd /path/to/local/haraka
npm install haraka-plugin-bounce
echo "bounce" >> config/plugins
service haraka restart

## USAGE

Add `bounce` to Haraka's config/plugins file. If desired, install and customize a local bounce.ini.

```sh
cp node_modules/haraka-plugin-bounce/config/bounce.ini config/bounce.ini
$EDITOR config/bounce.ini
```

<!-- leave these buried at the bottom of the document -->

[ci-img]: https://github.com/haraka/haraka-plugin-bounce/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/haraka/haraka-plugin-bounce/actions/workflows/ci.yml
[clim-img]: https://codeclimate.com/github/haraka/haraka-plugin-bounce/badges/gpa.svg
[clim-url]: https://codeclimate.com/github/haraka/haraka-plugin-bounce
[npm-img]: https://nodei.co/npm/haraka-plugin-bounce.png
[npm-url]: https://www.npmjs.com/package/haraka-plugin-bounce
