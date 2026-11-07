# Secure Inline Channel

A small Linux prototype that encrypts TCP traffic between two hosts as it passes through two devices in the middle:

```
PC1 → Device1 → Device2 → PC2
```

Device1 and Device2 agree on a shared key with Diffie–Hellman, then encrypt the payload of every selected TCP packet with AES-GCM. The IP and TCP headers stay as they are, so the packets travel normally, with no tunnel or extra header. The receiving device checks the authentication tag, decrypts the payload, fixes the checksums and delivers the original packet.

## How it works

**Handshake.** Before any data is protected, the two devices exchange Diffie–Hellman values (RFC 3526, 2048-bit group) over a short TCP connection. Both derive the same session key with HKDF-SHA256 and confirm it with an HMAC. An optional pre-shared key (`--psk`) protects the exchange from man-in-the-middle attacks.

**Encryption.** Packets are captured with netfilter NFQUEUE. For each packet with data, only the payload is encrypted:

```
[ IP header ][ TCP header ][ encrypted payload ][ tag 16B ][ counter 8B ]
```

The IP addresses, ports and sequence numbers are also covered by the tag, so a payload can't be moved into another connection. Packets without data (SYN, ACK, FIN) pass through unchanged.

**Decryption.** The receiving device verifies the tag, decrypts, removes the 24 extra bytes, recalculates the IP and TCP checksums and forwards the packet. Tampered or replayed packets are dropped.

**Unique nonces.** Each nonce is a 4-byte direction ID plus an 8-byte counter that increases with every packet and resets only with a new key. The counter is sent at the end of the packet so the receiver can rebuild the nonce. It isn't taken from the TCP sequence number, because a retransmitted packet can reuse a sequence number and that would repeat a nonce.

## Project structure

```
src/crypto.c         Diffie–Hellman, key derivation, AES-GCM, nonce counter
src/handshake.c      handshake between the two devices
src/packet.c         IP/TCP parsing and checksums
src/processor.c      decides to encrypt, decrypt, pass or drop each packet
src/secure_device.c  the program that runs on each device
tools/echo_test.c    end-to-end test client and server
tests/               unit tests
scripts/             builds the 4-node test network and runs the demo
```

## Running it

You need Linux (or a Linux VM) with:

```bash
sudo apt install build-essential libssl-dev libnetfilter-queue-dev iproute2 iptables tcpdump
```

Then:

```bash
make                       # build
make test                  # unit tests, no root needed
sudo ./scripts/run_demo.sh # full demo
```

The demo creates PC1, Device1, Device2 and PC2 as Linux network namespaces, runs the handshake, sends data from PC1 to PC2 and checks that it arrives intact. Traffic between the two devices is saved to `logs/wan.pcap`; open it in Wireshark to see that the headers are unchanged and the payload is encrypted.

## Limitations

- No automatic re-keying
- IPv4 and TCP only
- IP fragments aren't supported (the TCP MSS is lowered to 1400 so packets aren't fragmented)
