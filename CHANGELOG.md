# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).

### Unreleased

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
