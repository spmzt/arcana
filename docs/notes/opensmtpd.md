# OpenSMTPD: a plan

Asked for on 2026-10-20 ("Plan integration support for opensmtpd
too"), then built the same day (agent 0.162.0, console 0.236.0):
phases 1, 2, 4 (filters as installed, the smart host) and the queue's
actions of 3; left: the counters as graphs, a fault when the queue
grows, and phase 5's restart on a renewed certificate. FreeBSD 16.0 and later only; Arcana
installs nothing by itself (a button the admin presses is fine).

## What there is today

- **Mail out of the console** (mail.c): alerts and the workflow notify
  step go by `sendmail -t -i` on the console's host, or by the agent of
  the host Settings' `mail_via` names, which runs the same. Whatever
  `mailer.conf(5)` points `sendmail` at does the sending: the base
  system's sendmail, dma(8), or OpenSMTPD's `smtpctl` in its sendmail
  shape once the admin installs it.
- **Services** (ira/services.c): any rc.d script, so `smtpd` can be
  enabled, started and stopped already; its rc.conf variables set by
  service-config.
- **Files** (superbia/sysfiles.c): a table of system files written
  whole, each with its daemon and the action that makes it read the
  file. The same shape fits `smtpd.conf`.
- **Plugins** (luxuria/plugins.c): a program is a plugin when it is
  there (`bird`, `squid`, `suricata`, `poudriere`, `clamav`); the page
  shows its section only then and says what to install otherwise.
- **The lesson of 2026-10-20**: a daemon's configuration is rendered on
  the agent from the typed form, not written by the console and filled
  in by the agent, so that what is checked is what runs.

## What OpenSMTPD is, on FreeBSD

The port `mail/opensmtpd` (7.x): `smtpd(8)` with its one file
`/usr/local/etc/mail/smtpd.conf`, `smtpctl(8)` for everything live
(the queue, the statistics, `show status`, `pause`/`resume`, `schedule`,
`remove`, `update table`, a sendmail-compatible shape when run as
`sendmail`), tables (`table <name> file:/path`, `db:` made by
`makemap(8)`), `pki` for TLS, `listen on` per interface, `action` and
`match` rules, filters (`filter-rspamd`, `filter-dnsbl`,
`filter-senderscore` as ports; the built-in `filter check-rdns`,
`check-fcrdns` and `phase connect disconnect`), and an rc.d script that
takes `smtpd_flags`. Its base-system cousins: sendmail (default), dma.
`newaliases` is smtpctl's too (`mailer.conf`).

## What was tried on the lab VM (2026-10-20, opensmtpd-7.8.0,1)

- `smtpctl` answers root only ("smtpd doesn't seem to be running"
  otherwise); the agent is root.  `smtpd -n -f FILE` says
  "configuration OK" or the first error ("invalid virtual ip or
  interface: bogus0").  There is no reload: a changed file needs
  `service smtpd restart` (the rc script runs `smtpd -n` first);
  tables are reread by `smtpctl update table NAME` ("Table
  \"aliases\" successfully updated" in maillog).
- `show status`: three lines, "MDA running", "MTA running", "SMTP
  running" (or "paused").  `show stats`: `key=value` lines
  (scheduler.delivery.ok/tempfail/permfail, smtp.session,
  smtp.session.local, mta.*, mda.*, queue.bounce, uptime).
- `show queue`: a line per envelope, `|`-separated: evpid, source,
  type (mta/mda/bounce), flags, sender, rcpt, dest, ctime, expire,
  retries, last try, state (pending/inflight), next try, error.
  `show envelope EVPID`: `key: value` lines (dispatcher, type, sender,
  rcpt, dest, ctime, last-try, retry, flags, errorline when failed).
  `show message EVPID` the headers.  `schedule EVPID|all`, `remove
  EVPID|all` ("1 envelope scheduled/removed"), `pause|resume
  mta|mda|smtp` ("command succeeded").
- Credentials for `auth` and the relay's secrets are hashed by
  `/usr/local/libexec/opensmtpd/encrypt` (crypt(3) SHA-512); tables are
  made `db:` by `makemap` beside it; `mail.maildir`, `mail.lmtp`,
  `mail.mboxfile` are the delivery agents.  The spool is
  `/var/spool/smtpd`, the log `/var/log/maillog`, the pid
  `/var/run/smtpd.pid`.  The filter ports here: `opensmtpd-filter-
  rspamd`, `-dkimsign`, `-senderscore` (each a `filter-NAME` in the
  libexec directory).
- The port's own `smtpd.conf`: `table aliases file:/etc/mail/aliases`,
  `listen on localhost`, `action "local" maildir alias <aliases>`,
  `action "relay" relay`, `match for local action "local"`, `match
  from local for any action "relay"`.

## Design

**Reviewed 2026-10-20, before building it.** Smaller than first
planned: one job kind and one read, no graphs in the first cut (the
counters are shown; a ring for graphs can come as Suricata's did), no
`db:` tables (`file:` tables are reread by `update table`, which is
all a form needs), passwords hashed on the agent by `encrypt` and never
stored by the console, and the form kept by the agent
(`/usr/local/etc/arcana/smtpd.json`) so the panel refills it from the
host rather than from the console's memory.

**Rendered by the agent.** A new job kind, `smtpd`, in Luxuria
(luxuria/smtpd.c), takes the form the console sends (`spec`) and
renders `smtpd.conf`, checks it with `smtpd -n -f FILE`, writes it,
and restarts the service (smtpd has no reload), as sdids.c does for
Suricata. The form's parts:

- **Listeners**: each an interface or address, a port, `tls`/`tls-require`/
  `smtps`, `auth` with a credentials table, `pki` naming a certificate
  (Arcana's own host certificate, or one the admin names), `filter`s.
- **Domains**: local domains (`match from any for domain <domains>`),
  virtual users (`table virtual`), aliases (`table aliases`), and the
  mailbox action (`mbox`, `maildir`, `lmtp`, `relay`).
- **Relay out**: `match from local for any action relay`, with a smart
  host (`relay host smtp+tls://label@host:587`, the label in a
  `secrets` table, root's alone, as suricata-update's source codes are).
- **Policy**: `check-rdns`/`check-fcrdns`, `max-message-size`, queue
  `compression`/`encryption`, `smtp max-rcpt`, `ttl`, `bounce warn-interval`.
- **Filters**: the ports the host has (`pkg info -e`), each a
  `filter <name> proc-exec`; rspamd with its own section only when
  installed.
- **Its own lines**: text appended, as Suricata's "own YAML", the keys
  the form owns refused.

**Tables as their own files.** `aliases`, `virtual`, `credentials`,
`secrets`, `domains`, `senders`: each a sysfile-like write of
`/usr/local/etc/mail/<table>`, mode 0600 for the two with secrets,
followed by `makemap` where the table is `db:` and `smtpctl update
table <name>`. The agent, never the console, holds the secrets' text
after the job; the panel shows the names of credentials, not the
passwords.

**Read**: a `smtpd` operation (JSON): `smtpctl show status`, `show
stats` (the counters, for graphs as Suricata's: delivered, bounced,
rejected, queue size over time, kept in a ring), `show queue` (each
envelope: id, from, to, size, age, state, last error), `show hosts`,
`show relays`, the listeners as the file says, the tables and their
sizes, the log's tail (`/var/log/maillog`, by the Logs tab), and the
TLS certificate's dates.

**Queue actions**: a `smtpd` job's verbs `pause`, `resume` (mta, mda,
smtp), `schedule <id|all>`, `remove <id|all>`, `discover`, and `update
table <name>` — smtpctl's words, checked against a table as geom's
verbs are, an envelope id letters and digits alone.

**TLS**: the listener's `pki` from the host's own certificate (the
agent's `-C`/`-K` pair, which Arcana's CA issues and renews) when the
form says "Arcana's", else a path the admin names; the renew path
(superbia/tlsfiles.c) restarts smtpd when it serves the renewed file.

**Mail out of the console**: Settings gain "sendmail is OpenSMTPD's"
as a check only (`mailer.conf` read); nothing changes in mail.c. A
mail-test button exists already.

**The panel**: a Mail tab on the host (beside System and Security),
shown when `smtpd` is installed, else the install line: Status,
Queue (a table: sort, filter, select, Schedule/Remove with confirm),
Graphs, Configuration (the form), Tables (each editable as text, the
secret ones write-only), Log. A fleet view is not needed first.

**FreeBSD facility named in the panel and the book**: OpenSMTPD is a
port; `mailer.conf(5)` is FreeBSD's way of choosing the sender; the
host's certificate is Arcana's PKI over FreeBSD's OpenSSL.

## Phases

1. **Read** (agent operation `smtpd`, console route
   `/api/servers/{id}/smtpd`, arcanactl `smtpd`): status, stats,
   queue, listeners, tables; tests with a fake `smtpctl` (its outputs
   as the real one prints them, captured on the lab VM once the port
   is installed there). The panel's Mail tab with Status, Queue, Log.
2. **Configuration**: the `smtpd` job's `conf` verb from the form,
   rendered and checked on the agent (`smtpd -n`), the tables as
   files, `makemap`, restart. The form in the panel. The book page.
3. **Queue and statistics**: the queue's actions with confirms; the
   counters kept and graphed; faults when the queue grows past a size
   or smtpd stops (hostwatch).
4. **Filters and relay**: rspamd/dnsbl filters when installed, the
   smart host with its secret, `check-rdns`, size limits.
5. **TLS from Arcana's PKI**: the host certificate as the listener's
   pki; restart on renew; the dates shown.

Each phase its own commit with tests; the agent's version bumped per
commit; a fake `smtpctl`/`smtpd`/`makemap` in the agent test and the
console harness; the real daemon tried on the lab VM for phase 2
(`pkg install opensmtpd` there, as Suricata was).

## Decisions for the user

- **D-1** Replace or beside? Keep the base sendmail/dma untouched and
  run OpenSMTPD only where the admin installed it (recommended), or
  offer to switch `mailer.conf` to it from the panel (a button; it
  changes what every program on the host sends with).
- **D-2** Tables as `file:` (plain, no makemap, smtpd reads them at
  start and on `update table`) or `db:` (makemap, faster for large
  aliases). Recommended: `file:` first; `db:` when a table is large.
- **D-3** Secrets' editing: write-only in the panel (recommended), or
  shown to an operator with the admin role.
- **D-4** Whether the console's own alerts should be made to go through
  a host's OpenSMTPD by a `mail_via` of that host (works today) or
  stay with the console host's sender.
