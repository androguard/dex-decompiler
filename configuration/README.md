# Taint solver configuration

`dex-decompile --taint-solve` loads models from:

1. Embedded defaults (`default_config()`), or
2. `--taint-config PATH` (see [`default_taint.json`](default_taint.json)), plus optional
3. `--taint-config-extra PATH` merged on top (append sources/sinks/rules)

## Example overlays

```bash
# Strict PII / storage focus
cargo run --release --bin dex-decompile -- -i app.apk --taint-solve \
  --taint-config-extra configuration/taint_strict_pii.json \
  --taint-output /tmp/issues.json

# Deeplink / WebView focus
cargo run --release --bin dex-decompile -- -i app.apk --taint-solve \
  --taint-config-extra configuration/taint_deeplink_heavy.json \
  --taint-output /tmp/issues.json
```

Lifecycle callback seeds live in [`lifecycles.json`](lifecycles.json) (also embedded in the binary).

Prioritize exported entry points with `--taint-priority-entry com.example.MainActivity`
(repeatable). When the input is an APK with a **decoded text** `AndroidManifest.xml`,
exported component class names are auto-seeded when no CLI entries are given.

## Schema

```json
{
  "sources": [{"patterns": ["getIntent"], "port": "return", "kind": "ActivityUserInput", "features": ["user-controlled"]}],
  "sinks": [{"patterns": ["Runtime.exec"], "port": {"argument": {"index": 0}}, "kind": "CodeExecution"}],
  "propagations": [
    {"patterns": ["StringBuilder.append"], "from": {"argument": {"index": 1}}, "to": {"argument": {"index": 0}}}
  ],
  "sanitizers": [{"patterns": ["MessageDigest.digest"], "kinds": ["*"]}],
  "rules": [{
    "name": "RCE",
    "code": 1,
    "description": "...",
    "sources": ["ActivityUserInput"],
    "sinks": ["CodeExecution"]
  }]
}
```

Ports: `"return"`, `"this"`, or `{"argument": {"index": N}}` (0 = `this` for instance invokes).

Kinds are free-form strings; rules match source-kind → sink-kind like Mariana Trench.
Source `features` flow into issue trace frames for triage.
