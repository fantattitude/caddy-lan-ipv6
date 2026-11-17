# caddy-lan-ipv6

A Caddy matcher for active public IPv6 /64 prefixes on Linux interfaces.

```caddyfile
@home lan_ipv6
handle @home {
    respond "Hello from home"
}
```

The matcher checks the direct peer. Use `lan_ipv6 client` to check Caddy's resolved client IP, respecting its trusted proxy configuration.

It discovers active, non-temporary global /64 addresses on all up interfaces and caches the resulting prefixes for five seconds. If discovery fails, it matches nothing. Changes take effect without reloading Caddy. IPv4, ULAs and temporary or tentative server addresses are ignored; clients can use temporary addresses within a discovered prefix.

This trusts every discovered prefix, including those on WAN, tunnel and container interfaces. An interface prefix is not proof that a client is on your home LAN; review the host's addresses before enabling it.

Build Caddy with the matcher:

```sh
xcaddy build --with github.com/fantattitude/caddy-lan-ipv6
```
