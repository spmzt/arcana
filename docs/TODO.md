# TODO

## Waiting for approval before any work

- Interfaces, the rest: what is there lists them and changes them live
  (an address on or off, up or down). Not yet: keeping a change in
  `rc.conf` (`ifconfig_<if>_alias<n>`, whose numbers must stay without
  gaps), MTU and description, creating and destroying cloned interfaces,
  and refusing a change that would cut off the address the console
  comes in by.
- BIRD: neighbours and protocols, status, restart, clear.
- Routes, the rest: static routes are added and deleted live with
  route(8). Not yet: keeping one in `rc.conf` (`static_routes`), FIBs,
  and doing it through netlink with its attributes mapped to CBOR
  instead of running a program.
- Safe mode, the rest: changes to interfaces and routes are undone by
  the host when the console does not reach it again within a minute.
  Not yet: the same for a jail's address, for services and for what is
  kept in configuration files.

## Planned

- A section for the network, once interfaces and routes are managed: the
  servers as nodes of a graph, joined as their configuration joins them.
  The console works out which interface or tunnel of one server leads
  to which other, and draws a link if and only if the far end is a
  server on its own list.

- After the network section: creating interfaces, epair(4) and the
  tunnels (gif, gre, wg and the like), not only changing the ones that
  are there.

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
