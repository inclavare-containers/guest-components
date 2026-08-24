# KBS Resource URI

## Format

A Resource URI identifies a path exposed by a Trustee plugin:

```text
kbs[+<plugin>]://<kbs-host>:<kbs-port>/<segment>[/<segment>...][?<query>]
```

- `kbs://` is the canonical shorthand for Trustee's default `resource` plugin.
- `kbs+<plugin>://` selects another plugin, for example `kbs+pkcs11://`.
- The host and port are optional because the active KBC configuration selects
  the Trustee endpoint. Omitting them produces three slashes, such as
  `kbs:///default/key/1`.
- A path has one or more non-empty slash-separated segments. It is not limited
  to the three `repository/type/tag` segments used by the default resource
  plugin.
- An optional query string is forwarded unchanged to Trustee.

`kbs+resource://` and `kbs://` have identical meaning. Serialization uses the
shorter `kbs://` form for the default plugin.

## Examples

```text
kbs:///default/key/1
kbs://example.cckbs.org:8081/alice/decryption-key/1
kbs+pkcs11:///slot/token/private-key/version
kbs+nebula-ca:///cluster/node?duration=3600
```

## Trustee request mapping

The KBS client maps a Resource URI to the OpenAnolis Trustee route:

```text
<trustee-base-url>/kbs/v0/<plugin>/<segment1>/<segment2>/...
```

For example:

```text
kbs://example.cckbs.org:8081/alice/decryption-key/1
```

maps to:

```text
http://example.cckbs.org:8081/kbs/v0/resource/alice/decryption-key/1
```

and:

```text
kbs+pkcs11:///slot/token/private-key/version?pin-source=file
```

maps to:

```text
<trustee-base-url>/kbs/v0/pkcs11/slot/token/private-key/version?pin-source=file
```

Offline, sample, and online-SEV KBC implementations only understand the
three-segment default `resource` plugin path. They reject other plugins or path
shapes explicitly instead of silently routing them incorrectly.
