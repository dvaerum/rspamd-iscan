# rspamd-iscan

rspamd-iscan is a daemon that monitors IMAP mailboxes and sends new mails to
[Rspamd](https://rspamd.com) for spam analysis and training.
It decouples spam filtering from mail delivery - allowing the MDA,
Rspamd and rspamd-iscan to run on totally different hosts.
For example, you can filter mails on the IMAP server of your third-party
provider with your self-hosted Rspamd instance.
It is similar to [isbg](https://gitlab.com/isbg/isbg) but uses Rspamd instead of
SpamAssassin.

rspamd-iscan continuously monitors the IMAP `ScanMailbox` for new mails with
_IMAP IDLE_. \
When a new mail arrives, it is sent to Rspamd's HTTP interface for
scanning. The scan result is added as headers to the e-mail and the modified
mail is uploaded to either the `SpamMailbox` or the `InboxMailbox`, depending on
its classification. \
The unmodified original mail is moved from the `ScanMailbox` to the
`BackupMailbox`.

Mails in the `HamMailbox` and `UndetectedMailbox` are periodically processed and
submitted to Rspamd to be learned as ham or spam. Mails learned as ham are
moved to `InboxMailbox`, learned Spam mails are moved to `SpamMailbox`.

## Installation

### From Binaries

Download and extract the binary from a [Release](https://github.com/fho/rspamd-iscan/releases).

### From Source

`go install github.com/fho/rspamd-iscan@latest`

### Docker Image & Helm Chart

A Docker image and a Helm Chart is kindly provided by
[@JustinGuese](https://github.com/JustinGuese) and can be found
[here](https://github.com/JustinGuese/rspamd-iscan/pkgs/container/rspamd-iscan).

## Configuration

### Rspamd

A Rspamd instance must have been set up and it's controller HTTP interface must
be reachable.

### IMAP Server

It is recommended to use your `INBOX` mailbox to store scanned HAM mails and
reconfigure your mail-server to store new incoming mails in another mailbox,
e.g. named `Unprocessed`. This does not require changing your mail-clients'
configuration.
If that is not possible, rspamd-iscan can monitor `INBOX` instead and move
filtered Ham mails to another mailbox (e.g. named `Scanned`).
Your mail-clients would then be configured to use `HAM` as inbox.

- Ensure that you have the following mailboxes created on your IMAP server:
  - One to store mails classified as Spam (`SpamMailbox`),
  - One to store mails classified as Spam that was not detected
    (`UndetectedMailbox`),
  - One to store mails that have been wrongly classified as Spam (`HamMailbox`),
  - One to store unprocessed new mails (`ScanMailbox`),
  - One to store scanned mails classified as HAM (`InboxMailbox`)
  - Optionally, one to hold mails with an unsure score (`WaitMailbox`, see
    [Unsure Mails](#unsure-mails-optional))

### rspamd-iscan

rspamd-iscan is configured via a TOML configuration file.
By default, it is read from `/etc/rspamd-iscan/config.toml`, another location
can be specified by the `--cfg-file` command line parameter.

Create a new configuration file with the following content and adapt it to your
setup:

```toml
RspamdURL               = "http://192.168.178.2:11334"
RspamdPassword          = "iwonttellyou"
ImapAddr                = "my-imap-server:993"
ImapUser                = "rickdeckard"
ImapPassword            = "zhora"
InboxMailbox            = "INBOX"
SpamMailbox             = "Spam"
HamMailbox              = "Ham"
UndetectedMailbox       = "Undetected"
BackupMailbox           = "Backup"
# TempDir stores downloaded mails and their modified variants with added spam
# headers
TempDir                 = "/tmp"
# Set KeepTempFiles to false to delete temporary files after use immediately
KeepTempFiles           = false
ScanMailbox             = "Unscanned"
# Mails with a higher or equal rspamd score than SpamThreshold are moved to
# SpamMailbox, others to HamMailbox
SpamThreshold           = 10.0
# Minimal severity of log messages to be printed,
# supported levels: debug, info, warn, error
LogLevel                = "info"
# Raw incoming and outgoing IMAP data is logged with debug log level.
# The logged data can contain sensitive information, like credentials.
LogIMAPData             = false
# Mark mails in UndetectedMailbox as read when moving them to SpamMailbox.
MarkLearnedAsSpamAsRead = true
# Optional unsure/wait band, disabled when WaitMailbox is empty or unset.
# Mails with a score >= UnsureThreshold and < SpamThreshold are moved to
# WaitMailbox (which must already exist) instead of InboxMailbox. After
# WaitDuration they are scanned again: mails with a score >= SpamThreshold are
# then moved to SpamMailbox, all others to InboxMailbox.
# WaitMailbox must differ from all other mailboxes.
#WaitMailbox             = "Wait"
# Required when WaitMailbox is set: 0 < UnsureThreshold < SpamThreshold
#UnsureThreshold         = 5.0
# Optional, how long mails are held in WaitMailbox, a Go duration like "90m" or
# "6h", default: "6h"
#WaitDuration            = "6h"
```

### Unsure Mails (optional)

By default a mail is either Spam (score >= `SpamThreshold`) or Ham. With a
`WaitMailbox` configured, mails with a score in the grey zone between
`UnsureThreshold` and `SpamThreshold` are held back and scanned a second time
after `WaitDuration`. Rspamd's score for the same mail can change over time,
e.g. once blocklists or the Bayes classifier know the sender or content.

```
score >= SpamThreshold                      -> SpamMailbox
UnsureThreshold <= score < SpamThreshold    -> WaitMailbox (held for WaitDuration)
score < UnsureThreshold                     -> InboxMailbox

after WaitDuration, second scan (final, a mail never waits twice):
score >= SpamThreshold                      -> SpamMailbox
otherwise                                   -> InboxMailbox
```

- The feature is **off by default**; it is enabled by setting `WaitMailbox`.
  `UnsureThreshold` is then required, `WaitDuration` defaults to `6h`.
- The `WaitMailbox` must be created manually on the IMAP server and must differ
  from all other mailboxes. rspamd-iscan checks that it and the `BackupMailbox`
  exist at startup and refuses to start otherwise.
- The held copy is the unmodified original (original subject, no scan result
  headers) plus one header, `X-rspamd-iscan-First-Score`, with the score of the
  first scan. The original in `ScanMailbox` is moved to `BackupMailbox` as usual.
- The age of a held mail is measured from its IMAP internal date, which is set
  to the time it was put on hold. Held mails are checked at startup and every
  30 minutes. Mails you delete from the `WaitMailbox` are simply gone.
- After the second scan the usual scan result headers are added and the subject
  is rewritten if Rspamd asks for it, exactly once.
  `X-rspamd-iscan-First-Score` is kept on the delivered mail. The held copy is
  moved to `BackupMailbox`. One log line (`event=iscan.wait_decision`) per
  decision records first score, final score, destination and held duration.
- If Rspamd is unreachable or fails, behavior is unchanged: the error is
  handled as without this feature, nothing is held or released on a failed
  scan. If Rspamd is unreachable during the second scan, held mails are treated
  like any other failed scan (released with score 0), so monitor Rspamd's
  availability.

### Credentials Directory

Instead of storing sensitive credentials directly in the config file, you can use
the `--credentials-directory` flag to specify a directory containing credential
files. This is compatible with [systemd credentials](https://systemd.io/CREDENTIALS/).

If the credentials directory is set, rspamd-iscan looks for files named after the
config fields: `RspamdURL`, `RspamdPassword`, `ImapUser`, `ImapPassword`. If a file
exists, its content overwrites the corresponding value from the TOML config.

The `--credentials-directory` flag defaults to the `CREDENTIALS_DIRECTORY` environment
variable if not specified.

Example directory structure:
```
/run/credentials/rspamd-iscan/
├── RspamdPassword
├── ImapUser
└── ImapPassword
```

## Running

```bash
rspamd-iscan --cfg-file /etc/rspamd-iscan/config.toml 
```

better run it via systemd though :-)

## Project Status

The application is work-in-progress, the documented functionality works and is
in use, tests are missing.

## License

[EUPL](LICENSE)
