# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).

### Unreleased

### [2.1.1] - 2025-10-28

- Remove hook registration for 'validate_date' #16
- update changes and prettier #14
- style: expand line width to 120

### [2.1.0] - 2025-10-22

- optionally skip if bounce is validated, #13

### [2.0.1] - 2025-06-02

- empty_return_path must run before the Headers plugin #11
- Fixed From header parsing error #10

### [2.0.0] - 2025-05-20

Changes to config/bounce.ini

- removed check.non_local_msgid
- removed reject.non_local_msgid
- added check.hash_validation
- added check.hash_date
- added reject.hash_validation
- added reject.hash_date
- added validation.max_hash_age_days
- added validation.hash_algorithm
- added validation.secret

Added config/bounce_whitelist.json

- combinations of sender/recipient that should skip validation

Changes to test/index.js

- removed tests for non_local_msgid
- added tests for create_validation_hash
- added tests for validate_bounce
- added tests for get_bounce_headers
- added tests for should_skip
- added tests for find_received_headers
- added tests for validate_hash_date
- replaced most sinon.stub with sinon.spy to better monitor code behavior
- refactored many tests to make better use of sinon spies and assertions

Changes to index.js

- removed load_host_list()
- removed load_allowed_msgid_domains()
- removed non_local_msgid()
- removed find_message_id_headers()
- added create_validation_hash - creates a cryptographic validation hash
  for outbound emails
- added validate_date - reject if original email was sent before the
  configured number of days
- added validate_bounce - validates the bounce by comparing the hash
  created on the original email
- added find_bounce_headers - grab Date, From, Message-ID, and hash
  headers from the body of the bounce
- added should_skip - determines whether validation checks should be
  skipped
- added is_whitelisted - checks to see if a From:To pair is whitelisted
- added checks to only register a hook if it is configured
- added descriptive messages to all transaction.results

Changes to package.json

- added devDependencies (mocha and prettier)
- removed dependency for haraka-tld
- removed dependency for haraka-email-message

Changes to README.md

- removed documentation for non_local_msgid
- added documentation for the validation header
- added documentation for the validation_date
- Removed single_recipient checks for relaying and private IPs (#6)

### [1.0.5] - 2025-02-15

#### Added

- ci(GHA): added prettier config
- check host_list to confirm if local domain
- added config file for allowed Message-IDs
- added tests for bounce_spf()
- added Sinon for creating mocks
- Message-ID header regex to check for required angle brackets

#### Fixed

- fixed bug where config key reject.empty_return_path was ignored
- fixed timeout bug in bounce_spf()

#### Changed

- test: due to loading assert/strict..., replace strictEqual with equal
- renamed config key check.reject_all to reject.all_bounces
- moved bad_rcpt function from hook_data to hook_rcpt_ok
- moved config key check.bad_rcpt to reject.bad_rcpt
- refactored most of the existing tests to be more thorough
- moved reject_all from [check] to [reject] and renamed to all_bounces
- updated bounce_spf to use promises

### [1.0.4] - 2025-02-06

- results.isa: change from yes/no to boolean true/false

### [1.0.3] - 2025-01-30

- dep(all): bump to latest
- dep(eslint): upgrade to v9
- doc(CONTRIBUTORS): added

### [1.0.2] - 2024-04-29

- repackaged from haraka/Haraka as NPM module

[1.0.1]: https://github.com/haraka/haraka-plugin-bounce/releases/tag/1.0.1
[1.0.2]: https://github.com/haraka/haraka-plugin-bounce/releases/tag/v1.0.2
[1.0.3]: https://github.com/haraka/haraka-plugin-bounce/releases/tag/v1.0.3
[1.0.4]: https://github.com/haraka/haraka-plugin-bounce/releases/tag/v1.0.4
[1.0.5]: https://github.com/haraka/haraka-plugin-bounce/releases/tag/v1.0.5
[2.0.0]: https://github.com/haraka/haraka-plugin-bounce/releases/tag/v2.0.0
[2.0.1]: https://github.com/haraka/haraka-plugin-bounce/releases/tag/v2.0.1
[2.1.1]: https://github.com/haraka/haraka-plugin-bounce/releases/tag/v2.1.1
[2.1.0]: https://github.com/haraka/haraka-plugin-bounce/releases/tag/v2.1.0
