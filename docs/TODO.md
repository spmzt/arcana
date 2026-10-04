# TODO

## To do

- Routes through netlink, with its attributes mapped to CBOR, instead of
  running route(8) and netstat(1).
- WireGuard: preshared keys; a peer's key rotated.
- BIRD: its routes, and a protocol's details (`show protocols all`).

## Not yet verified

Written and tested with stand-ins, never run for real:

- Building the agent as `nobody` when `arcana-agent` runs as root
  (`chroot -u nobody`); only the unprivileged build was run with the
  real git and make.
- The agent's restart after an update against a real rc(8)-managed
  service; the tests use a stand-in for service(8).
- The agent's tests that need root, since the rename to Arcana.
- Creating, setting and destroying interfaces, routing tables, what is
  kept in rc.conf, and netgraph, against a real ifconfig(8), route(8),
  sysrc(8) and ngctl(8) as root; the tests use stand-ins. The interfaces
  themselves and the route lookup's parsing were checked against this
  machine's real output.
- The network map with real tunnels between real hosts: the test has two
  names for one agent, so its links are the networks they share.
- WireGuard and BIRD against the real wg(8), wg-quick(8) and birdc(8):
  the tests use stand-ins. The format of `wg show all dump` is the one
  wg(8) documents; BIRD is not installed on the machine this was written
  on, and what birdc prints was written from its documentation.
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

From a review of the whole code for flaws of security and design; what
it found and could be fixed was, and this is what stays:

- The build of the agent on a host runs as `nobody`, in a directory
  `nobody` owns and that outlives the build, and `make install` of a
  console update then runs as root from that tree. Any other process
  running as `nobody` on that host can change what is built. A user of
  its own for the build, a fresh directory for each, and the host keys
  and deploy key kept where the build cannot write would close it.
- A security key is asked for its owner's presence, not for a PIN or a
  fingerprint: keys without either still work, and a key found works
  for whoever found it. Sessions are not tied to the key they were made
  with: one made with a key since removed lasts until it ends.
- Somebody who can log in can make the console connect to port 443 of
  any host by naming it as a push service's address; the certificate
  must be valid for the name, and nothing of the answer is shown but a
  status and the start of an error.
- A change made in safe mode that fails half way (the MTU set, the
  description refused) reports the failure and leaves what was done.

- EC keys for the console's own HTTPS certificate: Kore's key manager
  signs with RSA only, so `console.pem` must be RSA until Kore (or a
  patch like the one in `port/www/kore/files`) handles ECDSA.
- A web terminal in the console: it could not be built.
- Luxuria has nothing in the agent yet: what reaches outside (the
  release check, notifications) is the console's.
