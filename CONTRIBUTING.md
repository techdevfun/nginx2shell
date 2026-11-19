# Contributing

## Development

```sh
npm install
npm run build
npm test        # unit + e2e (fixture JDKs built in tmp)
npm run test:live  # live smoke; soft-skips on network failure
npm run lint    # eslint + prettier
node scripts/preflight.js  # ASCII-only + no-internal-names scan
```

## Rules

- Zero runtime dependencies. TypeScript strict, Node 20+.
- Every figure cited in the README must come from a live source fetched
  during the build or a recorded fixture labelled as such. No invented
  numbers.
- All public content is English only (ASCII). No em dash anywhere. The
  preflight script blocks anything else, including text inside the demo
  transcript.
- The tool reports; it never deletes or changes anything on the host.
  Never add a mode that edits a JDK install or a JVM launcher.
- The tool reads only `java -version` output, /proc/cpuinfo (or the
  --cpuinfo file), JVM flag sources, and the code tree the user points
  at. Never add a network call to scan/check.
- Never add exploit code, a crashing input, or a mode that sends the
  malformed Base64 string to a JVM. Verdicts come from version + CPU +
  flags only.
- The demo fixtures are labelled recorded / representative / synthetic
  in the transcript, the GIF title card, and examples/README.md. Never
  present fixture numbers as measurements of a real machine. Live
  checks against real sources go in the build note and README, with the
  date recorded.
- A version the comparator cannot place is UNKNOWN, never SAFE.
