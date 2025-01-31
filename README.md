[![CI Test Status][ci-img]][ci-url]
[![Code Climate][clim-img]][clim-url]

# haraka-plugin-bounce

# bounce

Provide options for bounce processing.

## Configuration

Each feature can be enabled/disabled with a true/false toggle in the `[check]`
section of `config/bounce.ini`:

Some features can have rejections disabled in the [reject] section.

```ini
[check]
reject_all=false
single_recipient=true
empty_return_path=true
bad_rcpt=true
bounce_spf=true
non_local_msgid=true

[reject]
single_recipient=true
empty_return_path=true
bounce_spf=false
non_local_msgid=false
```

## Features

### reject_all

When enabled, blocks all bounce messages using the simple rule of checking for `MAIL FROM:<>`.

It is generally a bad idea to block all bounces. This option can be useful for mail servers at domains with frequent spoofing and few or no human users.

### single_recipient

Valid bounces have a single recipient. Assure that the message really is a bounce by enforcing bounces to be addressed to a single recipient.

This check is skipped for relays or hosts with a private IP, this is because Microsoft Exchange distribution lists will send messages to list members with a null return-path when the 'Do not send delivery reports' option is enabled (yes, really...).

### empty_return_path

Valid bounces should have an empty return path. Test for the presence of the Return-Path header in bounces and disallow.

### bad_rcpt

Disallow bounces to email addresses listed in `config/bounce_bad_rcpt`.

Include email addresses in that file that should _never_ receive bounce messages. Examples of email addresses that should be listed are: autoresponders, do-not-reply@example.com, dmarc-feedback@example.com, and any other email addresses used solely for machine generated messages.

### bounce_spf

Parses the message body and any MIME parts for Received: headers and strips out the IP addresses of each Received hop and then checks what the SPF result would have been if bounced message had been sent by that hop.

If no 'Pass' result is found, then this test will fail. If SPF returns 'None', 'TempError' or 'PermError' then the test will be skipped.

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
