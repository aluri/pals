# AI Usage

AI assistance was used to design, implement, correct, and validate this project.
The implementation was kept intentionally small, local, and explainable.

## Prompts Used

Initial build prompt:

```text
Build a small virtual DNS resolver CLI that reads zone_records.json and
queries.json, supports A, AAAA, CNAME, MX, and NS records, implements an
in-memory cache with TTL expiry, follows CNAME chains, returns NXDOMAIN for
missing records, and provides resolve, show-cache, flush-cache, show-stats,
explain-resolution, and replay-queries commands.
```

Correction prompt:

```text
Make one-shot CLI commands able to demonstrate cache behavior without requiring
a daemon. Keep the resolver core in-memory, but let the CLI persist cache and
stats in a small local state file. Add an option to disable persistence.
```

Bonus prompt:

```text
Add bonus DNS behaviors while preserving readability: negative caching,
controllable time for TTL expiry demonstrations, CNAME loop detection, wildcard
records, and an interactive shell with simulated time advancement.
```

Validation prompt:

```text
Create focused unit tests for direct record resolution, cache hits, TTL expiry,
CNAME chaining, negative caching, CNAME loop detection, wildcard expansion, and
the exact-name rule that prevents wildcard substitution.
```

## AI Corrections Made

- The cache design was adjusted so the core resolver remains in-memory while
  the CLI can persist state between short-lived terminal commands.
- CNAME resolution was corrected to cache both the alias query and the target
  query, while still checking for loops before following a target.
- CNAME loops return `CNAME_LOOP` instead of recursing forever or incorrectly
  reporting a normal NXDOMAIN.
- Negative responses are cached with a shorter configurable TTL so repeated
  unknown-name lookups hit cache but later re-resolution is possible.
- Wildcard handling was made DNS-like: wildcard records apply only when the
  exact queried owner name does not exist.
- TTL output from cached answers was corrected to show remaining TTL rather
  than the original authoritative TTL.

## Validation Performed

Validation used unit tests and manual CLI runs:

```bash
python3 -m unittest discover -s tests
./dns-basic flush-cache --input-dir ./sample --now 100
./dns-basic resolve www.example.com A --input-dir ./sample --now 100
./dns-basic resolve www.example.com A --input-dir ./sample --now 125
./dns-basic explain-resolution blog.example.com A --input-dir ./sample --now 100 --no-persist-cache
./dns-basic explain-resolution loop1.example.com A --input-dir ./sample --now 100 --no-persist-cache
./dns-basic replay-queries --input-dir ./sample --now 100 --show-cache --show-stats
```

The tests verify the main resolver algorithm, cache expiry, negative caching,
CNAME recursion, loop handling, wildcard behavior, and cache-hit accounting.
