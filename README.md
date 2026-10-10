# Secure Inline Channel (Linux prototype in C)

A Linux prototype of a secure inline communication channel between two hosts:

```
PC1 ──── Device1 ════════════ Device2 ──── PC2
       (encrypt/decrypt)    (encrypt/decrypt)
            └── DH handshake → shared AES-256 key ──┘
```

Device1 and Device2 are Linux routers placed in the path. They intercept selected
TCP/IPv4 traffic with **netfilter NFQUEUE** (`libnetfilter_queue`), agree on a
session key with **Diffie–Hellman**, and protect each TCP payload with
**AES-GCM** (OpenSSL). The original IP and TCP headers are kept, and the modified
packet is forwarded directly to the peer device, with **no UDP encapsulation and
no custom protocol header**.

## How it works

### 1. Handshake (before any protected data)

Each device daemon (`bin/secure_device`) first runs the handshake over a short TCP
control connection between Device1 (initiator) and Device2 (responder). It binds
to NFQUEUE only after the session is established. Until then the iptables
`NFQUEUE` rule has no listener, so selected traffic is dropped (fail closed: no
`--queue-bypass`).

| Step | Message | Content |
|---|---|---|
| 1 | Device1 → Device2 `HELLO_I` | type, version, 32-byte random `r_i`, DH public value `g^a mod p` |
| 2 | Device2 → Device1 `HELLO_R` | type, version, random `r_r`, `g^b mod p`, `MAC_r` |
| 3 | Device1 → Device2 `FINISH` | type, `MAC_i` |

* DH group: **RFC 3526 2048-bit MODP group 14** (`g = 2`), computed with OpenSSL
  `BIGNUM` (`BN_mod_exp_mont_consttime`, constant time). Private exponents come
  from `BN_priv_rand_range`.
* Peer public values are validated: `1 < y < p-1` and `y^q mod p = 1`.
* Key derivation: `session_key ‖ confirm_key = HKDF-SHA256(salt = r_i ‖ r_r, ikm = g^ab ‖ PSK)`.
* Key confirmation: `MAC = HMAC-SHA256(confirm_key, label ‖ SHA256(transcript))`,
  compared in constant time (`CRYPTO_memcmp`).
* Optional **pre-shared key (`--psk`)** authenticates the exchange. Plain DH alone
  is vulnerable to man-in-the-middle; with a PSK, an attacker cannot produce valid MACs.
* Secrets (DH exponent, shared secret, keys) are wiped with `OPENSSL_cleanse` after use.

### 2. Packet protection (Device on the sending side)

For each selected TCP packet **with a payload** coming from its own LAN:

```
original:   [ IP header ][ TCP header ][ payload ]
protected:  [ IP header ][ TCP header ][ AES-GCM ciphertext ][ tag 16B ][ counter 8B ]
                 kept         kept         same length as payload
```

* Cipher: **AES-256-GCM** (OpenSSL EVP), payload only.
* The authentication tag is appended directly to the ciphertext.
* **AAD (authenticated, not encrypted):** source/destination IP, ports, sequence and
  acknowledgement numbers. Moving an encrypted payload into another connection or
  stream position makes the tag check fail.
* IP Total Length grows by 24 bytes; the **IPv4 header checksum and TCP checksum are
  recalculated** (RFC 1071, `src/packet.c`) so the packet is valid on the
  Device1↔Device2 link.
* SYN, pure ACK and FIN segments have no payload and pass unchanged.

### 3. Verification and restore (Device on the receiving side)

1. Read the counter, rebuild the nonce, **verify the AES-GCM tag** (failed → packet dropped,
   decrypted bytes wiped).
2. Check the anti-replay window (duplicate or too old → dropped).
3. Decrypt, put the original payload back, restore the original Total Length.
4. **Recalculate the IPv4 and TCP checksums** and forward the packet to the destination host.

The destination host receives exactly the bytes the source host sent (the unit tests
check this byte-for-byte).

### 4. Nonce uniqueness

The 96-bit GCM nonce is built as

```
nonce = direction prefix (4 bytes) ‖ packet counter (8 bytes)
        0x00000001 = sent by Device1 (initiator)
        0x00000002 = sent by Device2 (responder)
```

* The counter starts at 0 in every session and is incremented under a mutex for
  **every** encrypted packet, so a nonce can never repeat within a session.
* Each new handshake creates a fresh key (new random values and DH exponents), so
  counters starting again at 0 never reuse a (key, nonce) pair.
* The two directions share one session key but use different prefixes, so their
  nonces can never collide.
* TCP retransmissions are encrypted again with a **new** counter value.
* If the 64-bit counter ever wrapped, the session refuses to encrypt (a new
  handshake is needed).

**Why the counter is carried in the packet:** the receiver needs the nonce, and
the task forbids a custom header. The counter is therefore an 8-byte trailer after
the tag. Deriving the nonce from the TCP sequence number was rejected: a
retransmitted or re-segmented packet can reuse a sequence number with different
data, which would repeat a nonce and break GCM security.

### 5. MTU

Protected packets are 24 bytes larger. The setup script clamps the TCP MSS to
1400 on the devices (`iptables ... TCPMSS --set-mss 1400`), so encrypted packets
never exceed a 1500-byte MTU and are never fragmented.

## Repository layout

```
Makefile
src/
  secure_device.c    device daemon: handshake, then NFQUEUE loop
  crypto.c/.h        DH group 14, HKDF, AES-GCM session, nonce counter, replay window
  handshake.c/.h     DH handshake protocol with key confirmation
  packet.c/.h        IPv4/TCP parsing, length update, checksum calculation
  processor.c/.h     per-packet decision: encrypt / decrypt / pass / drop
  log.c/.h           timestamped logging
tools/echo_test.c    end-to-end integrity test (server on PC2, client on PC1)
tests/test_channel.c 16 unit tests (no root needed)
scripts/
  setup_topology.sh  builds PC1–Device1–Device2–PC2 with network namespaces + iptables
  run_demo.sh        full end-to-end demo with traffic capture
  teardown.sh        removes the lab
```

## Requirements

```bash
sudo apt install build-essential libssl-dev libnetfilter-queue-dev iproute2 iptables tcpdump ethtool
```

Tested with GCC 13, OpenSSL 3.0, libnetfilter_queue 1.0.5 (Ubuntu 24.04).

## Building and running

```bash
make            # builds bin/secure_device and bin/echo_test
make test       # unit tests, no root needed
sudo ./scripts/run_demo.sh
```

Unit tests cover: DH safe prime and key agreement, invalid DH values, checksum
correctness, encrypt/decrypt round trip, byte-exact packet restoration, header and
payload tampering, replay, reflection, counter uniqueness, out-of-order delivery,
retransmissions, handshake key agreement and wrong-PSK rejection.

Expected demo output:

```
INFO  handshake complete (initiator), key id 4fe190cf8873
INFO  handshake complete (responder), key id 4fe190cf8873
OK: 40 messages, 372060 bytes echoed intact
INFO  final stats: encrypted=335 decrypted=335 pass_no_payload=348 ... drop_auth=0 drop_replay=0
```

`logs/wan.pcap` contains the Device1↔Device2 traffic: IP and TCP headers are the
original ones, payloads are ciphertext + tag + counter, and all checksums are valid.

### Manual run (or on real machines / VMs)

```bash
sudo ./scripts/setup_topology.sh 8080

# Device2
sudo ip netns exec dev2 ./bin/secure_device --role responder \
     --peer 10.0.12.1 --lan 10.0.2.0/24 --tcp-port 8080 --psk lab-secret
# Device1
sudo ip netns exec dev1 ./bin/secure_device --role initiator \
     --peer 10.0.12.2 --lan 10.0.1.0/24 --tcp-port 8080 --psk lab-secret

# PC2 / PC1
sudo ip netns exec pc2 ./bin/echo_test server 8080
sudo ip netns exec pc1 ./bin/echo_test client 10.0.2.2 8080

# watch the encrypted link
sudo ip netns exec dev2 tcpdump -i wan0 -X tcp port 8080
```

On real machines, run the same iptables rules from `setup_topology.sh` on each
device and drop the `ip netns exec` prefix.

## Limitations and possible extensions

* No automatic re-keying (would trigger a new handshake after N packets or T seconds).
* IP fragments of protected traffic are not supported (MSS clamping prevents them).
* Single-threaded NFQUEUE loop; multiple queues (`--queue-balance`) could scale it.
* Only IPv4 + TCP, as required by the task.
