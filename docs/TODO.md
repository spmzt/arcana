# TODO

## To do

- BIRD: neighbours and protocols, status, restart, clear.
- Routes through netlink, with its attributes mapped to CBOR, instead of
  running route(8) and netstat(1).
- WireGuard: `wg` interfaces are made, but their keys and peers are not
  set.

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
- Notifications on a real phone. A message sent with the console's code
  was delivered to headless Firefox through Mozilla's push service and
  shown; Google's service accepts the console's signature, but the
  Chromium build the tests run cannot receive from it.
- `arcana-enrol -s` on a real host, the container image since the
  rename, and the update check against GitHub's live feed.

## Known limits

- EC keys for the console's own HTTPS certificate: Kore's key manager
  signs with RSA only, so `console.pem` must be RSA until Kore (or a
  patch like the one in `port/www/kore/files`) handles ECDSA.
- A web terminal in the console: it could not be built.
- Luxuria has nothing in the agent yet: what reaches outside (the
  release check, notifications) is the console's.
