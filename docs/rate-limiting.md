# API rate limiting

The service applies a shared per-client token bucket to requests whose paths
are `/analyze`, `/analyze/permissions`, or `/replay`. All methods to those paths
consume a token. `/health` is excluded.

Configure positive integer environment variables:

| Variable | Default | Supported range | Meaning |
| --- | ---: | ---: | --- |
| `AEGISMESH_RATE_LIMIT_BURST` | 10 | 1–10,000 | Token capacity per bucket |
| `AEGISMESH_RATE_LIMIT_REFILL_PER_MINUTE` | 60 | 1–100,000 | Continuous refill rate |
| `AEGISMESH_RATE_LIMIT_MAX_CLIENT_BUCKETS` | 10,000 | 1–100,000 | Maximum total bucket objects, including overflow |

Each admitted request consumes one token. A full bucket permits the configured
burst and refills continuously (one token per second by default). A request
without a token gets HTTP 429 and a `Retry-After` duration rounded up to whole
seconds. Invalid, non-integer, non-positive, or out-of-range settings stop app
initialization with an error naming the setting.

The configured maximum counts every bucket object, including the shared overflow
bucket. When capacity is reached, existing per-client buckets are retained and
new or otherwise untracked clients share one overflow bucket with the same
burst and refill settings. One capacity slot is therefore reserved for overflow
once it is needed. With a capacity of one, all clients use that shared bucket.
This avoids evicting an active client's state and prevents high-cardinality
addresses from growing bucket storage without limit. Overflow clients share an
allowance and may throttle one another until the overflow bucket expires after a
full idle refill interval. Expired client buckets are reclaimed from the
least-recently-used end; pruning does not scan active entries.

The client identity is the peer IP in the ASGI connection's `client` field.
Forwarding headers such as `X-Forwarded-For` are ignored. Missing or invalid
peer addresses share a fallback bucket, so one such client can consume the
allowance for all requests without a usable peer IP. Clients behind the same
NAT address also share an individual bucket. IP-based limits do not prevent
distributed abuse.

The request-body middleware checks rate admission before reading the body, then
continues the existing bounded body read. Declared oversized bodies still
return 413 immediately; chunked bodies are read only up to the existing body
limit and return 413 when they exceed it. These 400/413 body errors take
precedence over 429, but the attempt has already consumed a token. A well-sized
request that lacks a token returns 429 after its body has been read, so rate
limiting avoids downstream validation and analysis but does not avoid the
bounded body-buffering cost. The read remains capped by
`AEGISMESH_MAX_REQUEST_BODY_BYTES` (1 MiB by default); this middleware does not
add a request-duration timeout, so deploy an appropriate server/proxy timeout
for slow clients.

Bucket state is in memory, local to one process, and cleared on restart. It is
not shared between workers or hosts. Multiple workers or hosts need a shared
store such as Redis for consistent limits. If proxy-aware identity is added,
configure trusted proxy addresses explicitly and accept forwarded identity only
from those proxies; arbitrary client-supplied forwarding headers can be
spoofed.
