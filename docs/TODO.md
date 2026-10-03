# TODO

## Waiting for approval before any work

- Managing interfaces and their addresses.
- BIRD: neighbours and protocols, status, restart, clear.
- Route management, possibly through netlink with its attributes mapped
  to CBOR.
- A safe mode that rolls a configuration change back when the agent
  loses the console, for the changes that can be rolled back.

## Planned

- A section for the network, once interfaces and routes are managed: the
  servers as nodes of a graph, joined as their configuration joins them.
  The console works out which interface or tunnel of one server leads
  to which other, and draws a link if and only if the far end is a
  server on its own list.

## To fix

- The queue belongs to no host: what waits is sent to the host selected
  when **Run** is pressed, also when it was queued while another host
  was selected. It should hold each change with its host, and send each
  host its own batch.

## Not yet verified

Written and tested with stand-ins, never run for real:

- Building the agent as `nobody` when `arcana-agent` runs as root
  (`chroot -u nobody`); only the unprivileged build was run with the
  real git and make.
- The agent's restart after an update against a real rc(8)-managed
  service; the tests use a stand-in for service(8).
- The agent's tests that need root, since the rename to Arcana.
- Firefox: the console is tested in headless Chromium only.
- The install offer on a real phone: Chrome's prompt on Android, the
  wording for Safari on iOS and for Firefox.
- Desktop notifications in a real browser; headless Chromium has no
  permission prompt.
- `arcana-enrol -s` on a real host, the container image since the
  rename, and the update check against GitHub's live feed.

## Known limits

- EC keys for the console's own HTTPS certificate: Kore's key manager
  signs with RSA only, so `console.pem` must be RSA until Kore (or a
  patch like the one in `port/www/kore/files`) handles ECDSA.
- A web terminal in the console: it could not be built.
- Luxuria has nothing in the agent yet: what reaches outside (the
  release check, notifications) is the console's.
