<img src="kls_logo.png" alt="kirblasnoop" width="300" align="right">

# kirblasnoop

Binds tcp and udp ports, swallows whatever arrives, and logs it byte-exact. Optionally
answers back well enough to keep the peer talking.

Built for reverse engineering an unknown program: point it at kirblasnoop instead of the
network and read what it tried to say. The binary is `kls`.

## build

```sh
cargo build --release      # target/release/kls
cargo test                 # 37 unit tests
```

Linux only. No runtime dependencies; the socket options are called directly rather than
linking a libc crate.

To install:

```sh
sudo install -m 0755 target/release/kls /usr/local/bin/kls
sudo install -d -m 0755 /usr/local/share/kirblasnoop/profiles
sudo install -m 0644 profiles/*.toml /usr/local/share/kirblasnoop/profiles/
sudo setcap cap_net_bind_service=+ep /usr/local/bin/kls   # optional, for ports below 1024
```

Profiles are looked up in `--profile-dir`, then `./profiles`, then
`$XDG_DATA_HOME/kirblasnoop/profiles`, `~/.local/share/kirblasnoop/profiles`,
`/usr/local/share/kirblasnoop/profiles` and `/usr/share/kirblasnoop/profiles`. A checkout
wins when you are standing in one. The `setcap` line is what lets an unprivileged `kls`
bind 53, 80 or 443, which also keeps capture files out of root ownership.

## quick start

Bind both transports on one port when you do not yet know which one a program uses:

```
$ kls tcp:9000 udp:9000
[23:41:49.939] listen  tcp/0.0.0.0:9000  listener=tcp:0 profile=none
[23:41:50.566] open    #1 tcp 127.0.0.1:58540 -> 0.0.0.0:9000
[23:41:50.567] --> #1 tcp 127.0.0.1:58540 317 bytes  TLS 1.3 ClientHello sni=api.vendor.example ciphers=31
  00000000  16 03 01 01 38 01 00 01  34 03 03 7f da ac 56 d8  |....8...4.....V.|
```

A listener spec is `proto:port`, `proto:addr:port`, with an optional `=profile` suffix:

```sh
kls tcp:9000 udp:9000              # pure vacuum, both transports
kls tcp:80=http udp:53             # a different fake service per port
kls udp:127.0.0.1:9000             # bind one address
kls udp:53 --iface eth0            # bind one interface by name
kls -c capture.toml                # listeners from a config file
kls profiles                       # list available profiles
```

`--iface` pins listeners with `SO_BINDTODEVICE`, which needs no privileges. It is steadier
than binding an address when the interface has several: ipv6 privacy addressing rotates
them, so an address-bound listener on a wireless interface is aimed at a moving target. A
name that does not exist is an error, not a silent no-op.

The default posture is silence. Nothing is sent back unless a profile says so, because
anything you send changes the target's behaviour and contaminates the capture.

## what gets written

Each run creates `captures/<timestamp>/` holding three independent sinks:

- `events.jsonl`, one json object per open, data, close and truncation event. Carries the
  connection id, direction, true length, matched rule, protocol hint, and the first 256
  bytes of payload as base64. This is an index, not a second copy: embedding whole
  payloads made it 1.34x the size of the raw files it duplicated.
- `NNNN-proto-peer.rx.bin` and `.tx.bin`, byte-exact streams per connection and direction,
  suitable for diffing, replaying, or feeding to a parser.
- The console, as a hexdump (`--console hex`), one escaped line (`ascii`), a counter
  (`summary`), or nothing (`none`).

Use `--no-files` to keep everything in the terminal.

## transparent capture

A single listener can catch every connection a program makes, on any port, to any host,
without being told any of them in advance. Netfilter redirects the traffic and kirblasnoop
recovers the pre-NAT destination from conntrack via `SO_ORIGINAL_DST`:

```
[23:45:46.346] open    #1 tcp 10.0.2.15:34960 WANTED 192.0.2.44:8883
[23:45:46.346] --> #1 tcp 10.0.2.15:34960 49 bytes  HTTP GET /beacon host=c2.vendor.example
```

`kls transparent` prints the rules to install. It never touches the firewall itself:

```sh
kls transparent --port 9999 --uid snoop
sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner snoop ! -d 127.0.0.0/8 \
  -j REDIRECT --to-ports 9999
sudo -u snoop ./the-unknown-binary
```

Scoping by `--uid-owner` is what keeps the rule off your own traffic. Only locally
originated connections are affected; to catch another host, the rule belongs in
PREROUTING on the box that routes for it.

Udp gets no `WANTED` line. REDIRECT does not carry the original destination for datagrams,
which needs TPROXY. Udp listeners still capture normally.

## protocol hints

Inbound messages are classified from their opening bytes and the guess is printed beside
the hexdump and stored in `events.jsonl`. Verified against real clients:

| client | reported |
|---|---|
| `openssl s_client -servername api.vendor.example` | `TLS 1.3 ClientHello sni=api.vendor.example alpn=h2,http/1.1 ciphers=31` |
| `curl` to a bare ip | `TLS 1.3 ClientHello alpn=h2,http/1.1 ciphers=31` (no sni, correctly) |
| `curl http://host/v1/telemetry` | `HTTP GET /v1/telemetry host=... ua=curl/8.5.0` |
| `dig AAAA telemetry.vendor.example` | `DNS query AAAA telemetry.vendor.example` |
| `ssh` | `SSH banner SSH-2.0-OpenSSH_9.6p1` |
| opaque binary | nothing |

The sni extraction is the useful part: an unknown binary names the host it wanted before
any key exchange, so its destination is readable without terminating tls. Tls version comes
from the `supported_versions` extension rather than the legacy field, and GREASE values are
skipped.

## profiles

A profile is a toml file with an optional connect-time banner and an ordered rule list.
First match wins; no match means stay silent.

```toml
name = "smtp"

on_connect = { text = "220 mail.example.com ESMTP Postfix\r\n" }

[[rule]]
name = "ehlo"
when = { starts_with = "EHLO", ignore_case = true }
respond.text = "250 mail.example.com\r\n"

[[rule]]
name = "quit"
when = { starts_with = "QUIT", ignore_case = true }
respond = { text = "221 2.0.0 Bye\r\n", close = true }
```

### answering dns

Fixed bytes cannot answer a dns query, because the reply has to echo the transaction id
and question section. `respond.dns` builds the reply from the request instead:

```toml
[[rule]]
when = { any = true }
respond.dns = { a = "192.0.2.10", ttl = 60 }
```

Point a device's resolver at that listener and every name resolves to the address you
chose, so the device keeps working while you watch, and the connections it then makes
arrive at your other listeners with the hostname already known. A query type with no
address configured gets NOERROR and zero answers rather than NXDOMAIN, which stops the
client retrying without telling it the name is absent. Works over udp and over tcp, where
the 2-byte length prefix is handled.

### matchers and responses

Matchers: `starts_with`, `ends_with`, `contains`, `prefix_hex`, `contains_hex`, `len`,
`min_len`, `max_len`, `first_only`, `ignore_case`, `any`. Every field present must hold.
Responses carry `text` (with `\r`, `\n`, `\xNN` escapes), `hex`, `file`, `echo`, `dns`,
`delay_ms`, `repeat` and `close`. Payloads are resolved once at load time, so the hot path never
touches the filesystem.

Shipped: `silent`, `echo`, `ack`, `dns`, `http`, `smtp`, `ftp`, `ssh`. Adding one is adding a file
to `profiles/`.

## capture limits

Raw dumps and the event log are both capped so an unattended run cannot fill a disk.
Truncation is always announced, on the console and in `events.jsonl`, because a capture
that quietly dropped bytes reads as complete and will be believed.

```sh
kls tcp:9000 --ring 4M              # keep the first 4M and last 4M of each stream
kls tcp:9000 --stream-head 8M       # keep only the front
kls tcp:9000 --max-run-bytes 200M   # stop writing to disk after 200M
```

The two ends go to `.bin` and `.tail.bin` and are never concatenated. A single file with a
silent hole in it would be parsed as contiguous and would invent a protocol layout out of
bytes that were never adjacent.

## known limits

Rules match per tcp read, not per protocol message. Tcp has no message boundaries, so a
client that batches two commands into one segment gets one reply, and a message split
across two reads may not match at all. Profiles need a framing layer (delimiter or length
prefix) before this is trustworthy on a binary protocol.

A udp profile that responds answers forged source addresses, because udp has no handshake
and the source in the header is whatever the sender wrote. On a non-loopback bind that
makes kirblasnoop a reflector, and an amplifier whenever the reply exceeds what triggered
it. Measured against a 1-byte datagram: `smtp` returns 50 bytes and `ftp` 49, since their
connect banners fire on a peer's first message and a rule replies to the same message.
`echo` and `ack` are 1x and uninteresting to an attacker.

kirblasnoop warns at startup when a responding profile binds a non-loopback address, and
caps tracked sources at `--udp-max-peers` (4096). Past the cap, datagrams are still
captured under a single overflow stream but sources are untracked and unanswered, which
bounds both memory and reflection. The warning is not a substitute for binding loopback or
an isolated interface.

No icmp, and no tls termination. Icmp needs raw sockets and `CAP_NET_RAW`; the logo is
aspirational. Tls connections are captured as ciphertext, with the ClientHello readable.

All disk writes serialise on one mutex and the event log flushes per event. That is a
deliberate trade for crash safety and it caps throughput well below a saturated link.
