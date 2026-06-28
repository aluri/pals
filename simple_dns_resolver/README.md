# Simple DNS Resolver with Caching and Record Types

This is a small terminal DNS resolver simulator. It reads local JSON files,
resolves common DNS record types, follows CNAME chains, caches responses with
TTL expiry, and explains each lookup step.

The implementation uses only the Python standard library.

## Quick Start

From this folder:

```bash
./dns-basic resolve www.example.com A --input-dir ./sample
./dns-basic explain-resolution blog.example.com A --input-dir ./sample
./dns-basic show-cache --input-dir ./sample
./dns-basic show-stats --input-dir ./sample
./dns-basic replay-queries --input-dir ./sample --show-cache --show-stats
```

If the wrapper is not executable on your system:

```bash
python3 dns_basic.py resolve www.example.com A --input-dir ./sample
```

## Input Files

The input directory must contain:

- `zone_records.json`: authoritative local records
- `queries.json`: simulated DNS queries for `replay-queries`

Supported record types:

- `A`
- `AAAA`
- `CNAME`
- `MX`
- `NS`

MX records require `priority`. All records require `name`, `type`, `value`, and
`ttl`.

## Commands

```text
resolve <name> <type>              Resolve one DNS query
explain-resolution <name> <type>   Print cache, zone, and CNAME steps
show-cache                         Show valid cache entries and remaining TTL
flush-cache                        Clear cached answers
show-stats                         Show cache hits, misses, NXDOMAINs, loops
replay-queries                     Resolve every query in queries.json
shell                              Run an interactive resolver shell
```

The CLI stores cache and stats in `INPUT_DIR/.dns_basic_state.json` so repeated
one-shot commands can demonstrate cache behavior. The resolver core still uses
an in-memory cache; the state file is only a small CLI convenience. Use
`--no-persist-cache` for a fresh process-local cache.

## Bonus Features

- TTL expiry:

```bash
./dns-basic flush-cache --input-dir ./sample --now 100
./dns-basic resolve api.example.com A --input-dir ./sample --now 100
./dns-basic resolve api.example.com A --input-dir ./sample --now 103
./dns-basic resolve api.example.com A --input-dir ./sample --now 106
```

- Negative caching:

```bash
./dns-basic resolve unknown.example.com A --input-dir ./sample
./dns-basic resolve unknown.example.com A --input-dir ./sample
```

- CNAME loop detection:

```bash
./dns-basic explain-resolution loop1.example.com A --input-dir ./sample
```

- Wildcard records:

```bash
./dns-basic resolve host.wild.example.com A --input-dir ./sample
```

- Interactive simulated time:

```text
./dns-basic shell --input-dir ./sample --now 100
dns-basic# resolve api.example.com A
dns-basic# show-cache
dns-basic# advance-time 10
dns-basic# resolve api.example.com A
```

## Validation

```bash
python3 -m unittest discover -s tests
./dns-basic flush-cache --input-dir ./sample --now 100
./dns-basic replay-queries --input-dir ./sample --now 100 --show-cache --show-stats
./dns-basic explain-resolution blog.example.com A --input-dir ./sample --now 100 --no-persist-cache
./dns-basic explain-resolution loop1.example.com A --input-dir ./sample --now 100 --no-persist-cache
```
