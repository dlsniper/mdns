## Unreleased

### Improvements

- server: announce the zone's records when the server starts and send goodbyes (TTL 0) on `Shutdown` (RFC 6762 sections 8.3 and 10.1). A `Zone` may implement the new optional `Announcer` interface to list them; `MDNSService` does.

### Changes

- server: `Shutdown` waits for the announce routine and sends the goodbyes before it closes the sockets.
- server: the listeners have multicast loopback enabled, and send multicast from `Config.Iface` when it is set.
- server: messages with the QR (response) bit set are ignored.

### Fixed

- server: responses to multicast queries are sent to the multicast group instead of the querier's address; unicast is kept for QU questions and for legacy queriers (source port other than 5353), whose response now repeats the question (RFC 6762 sections 5.4, 6 and 6.7).

### Security
