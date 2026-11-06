# Configuration files: Arcana's own or the system's

A host's rc.conf(5) variables and loader tunables, as a commit writes
them, go to one of two places, arcana-agent's `config-files`:

| mode     | rc.conf variables                                   | loader tunables                    | kept firewall rules                      |
|----------|-----------------------------------------------------|------------------------------------|------------------------------------------|
| `arcana` (default) | `/usr/local/etc/rc.conf.d/arcana`, named last in `rc_conf_files` | `/boot/loader.conf.d/arcana.conf` | `/usr/local/etc/arcana/ipfw.rules` (+ `.sh`) |
| `system` | the last of the admin's files rc(8) reads that sets it, else `/etc/rc.conf` | the last loader file that sets it, else `/boot/loader.conf` | `/etc/ipfw.rules` and `/etc/ipfw.sh`, unless they are the admin's |

The mode is kept in `/usr/local/etc/arcana/config-files.conf`
(`config_files="system"`, and `config_files_ipfw_rules` when the
firewall files moved), read at the agent's start, and changed by the
`switch` action alone, since it moves files. State and actions:
`/arcana-agent:agent/config-files` (`mode`, `rc-file`, `loader-file`,
`firewall-rules`, `pending`, `ledger`; actions `switch` and `resolve`,
`nacm:default-deny-all`, an admin's).

## A variable the admin's files set too

Both modes. A commit that changes a variable the admin's own files
set, to something else, is a warning first: `rc-conf-conflict`
(`loader-conf-conflict` for a tunable). Nothing of the admin's is
commented out any more. Accepted:

- A word list (the table in `invidia/cfgfiles.c`, `cf_lists`) is merged
  additively: the admin's words in their order, then the commit's that
  are not there, as `sysrc var+=` adds each. A word the commit takes
  out (one Arcana had, by the ledger, or one the caller read and left
  out) comes out of the list.
  - `arcana`: the merge is written to Arcana's file, the admin's line
    untouched; rc(8) reads Arcana's file last, so it wins without
    hiding the admin's words.
  - `system`: the merge is written where the admin's line is.
- A value (a scalar, or anything a merge of words cannot express) is
  not written: the commit is refused again with `rc-conf-merge`, the
  rows kept as `pending` (file, line, the admin's value, Arcana's).
  The page's merge editor shows both side by side, the words each has
  that the other has not marked, and an editable result; `resolve`
  gives the host the results, and the commit is sent again accepting
  `rc-conf-merge`: a resolved row's value is written, any other row's
  Arcana's (accepting `rc-conf-merge` without `resolve` takes Arcana's
  value). In `arcana` mode the value goes to Arcana's file, the
  admin's line untouched; in `system` mode in place.

  Why `resolve` and not the value in the commit: a variable's value is
  derived by the module that writes it (an interface's `ifconfig_<if>`,
  `jail_list` from the jails), so the candidate cannot carry an
  arbitrary rc.conf value; cblink's accept list carries tags, not
  values. `resolve` keeps the values with the pending rows in the
  agent until the next commit takes them.

A tunable's value is the candidate's own (arcana-sysctl's boot list),
so `loader-conf-conflict` needs no merge editor: the admin edits the
value in the page and accepts the warning.

The ledger, `/var/db/arcana/config-ledger` (a line a variable: kind,
name, file, value before, value Arcana wrote, Arcana's own), records
what Arcana changed of a variable the admin's files set. A variable
whose current value is what the ledger says Arcana merged is not
asked about again (in `system` mode every variable Arcana writes is
in it: it is Arcana's file there). It is kept for `rca_undo()` with
every other file a commit changes.

Release (arcana-services' `release`), both modes, gives back what
Arcana added: in `arcana` mode Arcana's lines out (the admin's never
changed), the ledger's entries with them; in `system` mode, by the
ledger, Arcana's added words out of a merged list, a value back to
what it was where it is still what Arcana wrote, a variable Arcana
added alone taken out. Lines an older agent commented out as
`# taken by Arcana` are still read and put back by release and by the
switch; new code never writes them. `convert` copies a service's
variables into Arcana's file (the same values: nothing to warn of);
in `system` mode it has nothing to do and says so.

## The switch

`arcana` to `system`, a dry run first (the page's first call): a row
for each variable of Arcana's files (`rc_conf_files` itself aside),
with the admin's value from an active line or a `# taken by Arcana`
one, Arcana's, whether it is a word list, the file it ends in, a
choice and the result:

- the admin's files set nothing: Arcana's value, in `/etc/rc.conf`
  (`/boot/loader.conf` for a tunable);
- both set it: `additive` (a word list's alone; its default),
  `arcana` (what boots now), `yours`, or `edit` with a value. A value
  that differs has no default: a real run without a choice for it is
  refused with `config-merge`, naming them;
- a line taken by Arcana is put back where it is, then the result
  written there: no taken comment is left anywhere.

Then Arcana's files are removed, Arcana's path taken out of
`rc_conf_files` (the line taken out where what is left is the
defaults' list), the firewall moved, the ledger written (every row:
before, after, Arcana's), the mode file written. Before anything is
written every file it changes or removes is copied into
`/var/db/arcana/config-switch/<UTC time>/` (paths kept under it, modes
kept) and named in the output; a failure puts every file back
(`rca_undo()`), the mode as it was, the copies left. Nothing is loaded
live: rc(8) reads rc.conf at each service's start and at boot, the
loader at the next boot.

The firewall's kept rules and boot script move to `/etc/ipfw.rules`
and `/etc/ipfw.sh` (the script rewritten to name the new rules, its
"Written by arcana-agent" line kept, `firewall_script` following it),
unless `/etc/ipfw.rules` is there with other bytes than Arcana's kept
rules, or `/etc/ipfw.sh` without Arcana's line: then nothing of the
firewall moves, `firewall_script` keeps naming Arcana's script, and
the output says so. The admin's firewall files are never written. The
feeds stay in Arcana's directory. A jail's firewall and a jail's
rc.conf are not the host's mode's.

`system` to `arcana`: a clone. Every variable the admin's
`rc_conf_files` files set (the last value of each; `rc.conf.d/<svc>`
fragments are read after Arcana's file by rc(8) anyway) is copied into
Arcana's file, every tunable of the loader's files into
`arcana.conf`; Arcana's file is added to `rc_conf_files` in
`/etc/rc.conf`, the one line of the admin's that changes. rc(8) and
the loader read Arcana's files last, so what boots is the same. The
ledger is emptied: its merges are the admin's lines now. The firewall
files move back to Arcana's directory only if they are Arcana's (its
script's line), `firewall_script` in Arcana's file following them.

## Decisions

- The paths of the mode file, the ledger and the backups are fixed,
  under `--root` for the tests; no option.
- The switch reads the `rc_conf_files` set (vc_rc_files for a service
  of no name), not every `rc.conf.d/<svc>`: Arcana's file is global.
- Equal values are no conflict; a drop in `arcana` mode is no conflict
  (the admin's value applies again), but a word list whose words of
  the admin's the commit took out too is written to Arcana's file as
  what is left (an empty list overrides).
- A `system` mode drop of a value the admin set, not Arcana, is
  `rc-conf-conflict`, then taken out of every file that sets it.
- `ifconfig_<if>_aliases` is no word list (its entries are two words).
- The page's switch is a plain action and a task of the console's own
  (`op_begin`): the console's socket carries reads alone.
- arcanactl's `action` takes an input list's entry as
  `list=leaf:value,...` (the tests' merge rows).
- The System files' entry for the tunables is `loader.conf` in
  `system` mode (`loader.conf.d` in `arcana`); a read of the other's
  name finds none rather than failing. The sysfile job's verb list has
  `loader.conf` appended.
- Pre-1.0, no compatibility: an older agent does not know `loader.conf`
  as a file's name; the map's tunables read both names.
