# rookd on FreeBSD (plan §7)

One unprivileged service, bound to 80/443 through `mac_portacl`, supervised
by `daemon(8)`, config-validated before every start. No root worker, no
setcap (FreeBSD has none); the kernel's port ACL is the privilege boundary.

## Install

```
# binary
install -m 0755 rookd /usr/local/sbin/rookd

# user (no login, no home write access)
pw useradd -n rookd -c "Rook HTTP reverse proxy" -d /nonexistent -s /usr/sbin/nologin

# config
install -d -m 0750 -o root -g rookd /usr/local/etc/rook
install -m 0640 -o root -g rookd rookd.example.toml /usr/local/etc/rook/rookd.toml   # then edit
# TLS material: 0600 rookd:rookd — the daemon rejects a key with any
# group or other bit set. The key never leaves the box and never
# enters chat, a ticket, or a repo.

# service + log rotation
install -m 0555 deploy/freebsd/rc.d/rookd /usr/local/etc/rc.d/rookd
install -d /usr/local/etc/newsyslog.conf.d
install -m 0644 deploy/freebsd/newsyslog.d/rookd.conf /usr/local/etc/newsyslog.conf.d/rookd.conf

# ACME state (account key, certificates): 0700 rookd:rookd
install -d -m 0700 -o rookd -g rookd /var/db/rookd

# let the rookd uid bind 80/443 (persistent)
UID_ROOKD=$(id -u rookd)
printf 'security.mac.portacl.rules=uid:%s:tcp:80,uid:%s:tcp:443\n' "$UID_ROOKD" "$UID_ROOKD" >> /etc/sysctl.conf
printf 'security.mac.portacl.enabled=1\nsecurity.mac.portacl.port_high=1023\nnet.inet.ip.portrange.reservedhigh=0\n' >> /etc/sysctl.conf
printf 'mac_portacl_load="YES"\n' >> /boot/loader.conf
service sysctl start   # or reboot once; loader.conf applies at boot

sysrc rookd_enable=YES
service rookd start
```

Verified pattern: this is the arrangement rook-test-01 has run since
11 Nov (mac_portacl uid rule, daemon-supervised, unprivileged).

## Properties

- **Config gate:** `start_precmd` runs `rookd --check`; a bad edit never
  replaces a running service. Certificate replacement needs no restart —
  rookd polls and reloads, keeping the last valid certificate on failure.
- **Logs:** daemon(8) `-o` appends the child's output to
  `/var/log/rookd.log`; newsyslog rotates at 1 MiB and HUPs the
  supervisor, whose `-H` flag reopens the file. Both failure modes were
  verified on rook-test-01 before choosing this: a logger pipeline made
  the child /bin/sh and orphaned rookd on stop, and `-o` without `-H`
  strands the stream in the rotated file.
- **No reload command:** rookd reloads replaced certificates on its own
  2s poll; daemon(8) forwards HUP to the child, which has no HUP handler,
  so a reload alias would kill the service.
- **Rollback:** keep the previous binary as `/usr/local/sbin/rookd.bak`;
  stop, swap, start. `install` is atomic on the same filesystem, so the
  running path never sees a partial binary.
