# Precision-2 live DEX demos

Java sources under this directory compile to a checked-in `classes.dex` used by
`tests/mariana_trench_solver.rs` (`precision2_*` tests).

| Demo method | Feature under test |
|-------------|--------------------|
| `directFlow` / `oneHopFlow` / `twoHopFlow` | Local + 1-hop + 2-hop (`mid`→`leafSink`) traces |
| `aliasFieldFlow` | ObjectId alias + instance field path |
| `strongUpdateClean` | Strong update clears path (negative control) |
| `mapTokenFlow` / `mapOtherKeyClean` | `map:<key>` path sensitivity |
| `StaticHolder.writeSource` / `readToSink` | Cross-method static field heap |
| `DeeplinkActivity.onNewIntent` | Lifecycle seed → `Origin.sink` / `startActivity` |
| `RedirectReceiver.onReceive` | Receiver seed → sink / launch |
| `clickShimFlow` + `TaintedClick.onClick` | `setOnClickListener` → `onClick` (`shim:` edge) |
| `executorShimFlow` + `TaintedRun.run` | `Executor.execute` → `run` shim |
| `smsPiiFlow` | `SmsPii` → `SmsSend` (rule 23) |

Models: [`models.json`](models.json) (AndroHunt `TaintConfig` schema).

Rebuild:

```bash
./build.sh
```
