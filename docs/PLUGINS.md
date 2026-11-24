# AlterChat Plugins

AlterChat plugins are WebAssembly modules. They run inside a
[wasmi](https://github.com/wasmi-labs/wasmi) interpreter sandbox in
`alterchat-core::plugin::PluginHost`. A plugin has no ambient authority. It
can only touch its own linear memory and the host functions that its granted
capabilities link in. There is no WASI, so plugins get no filesystem, network,
environment, clock or randomness unless a capability below grants it.

> Status: experimental. Treat third-party plugins as untrusted code, and only
> grant the capabilities a plugin really needs.

## Lifecycle of a run

1. **Verify.** `verify_plugin` checks the Ed25519 manifest signature and that
   the SHA-256 hash of the WASM binary matches `manifest.wasm_hash`. A
   tampered binary or manifest is rejected before anything is parsed.
2. **Policy.** The user policy (the `enabled` flag and granted capabilities,
   stored in the `plugin_registry` table) must be enabled and must belong to
   the same plugin id.
3. **Import check (fail closed).** Every import must be a *function* in the
   `alterchat` module and must appear in the ABI table below. If its
   capability is not effective, the run is refused with
   `CapabilityNotGranted` before instantiation. Imports from other modules
   (for example `wasi_snapshot_preview1`) and memory, table or global imports
   are refused with `UnknownImport`.
4. **Link.** Only the host functions the module actually imports, and is
   allowed to import, are linked.
5. **Instantiate and call.** The module is instantiated under the memory limit
   with no `start` function allowed. The manifest's `entrypoint` export, of
   type `() -> i32`, is then called with the fuel budget.
6. **Apply effects.** Messages and notifications that the plugin requested are
   returned as data. The host application applies them after the run, outside
   the sandbox. A run that traps returns an error and has no effects.

A capability is **effective** only when it is both requested in the signed
manifest (`manifest.capabilities`) and granted by the user
(`PluginPolicy::granted_capabilities` with `enabled = true`).

## Capabilities

| Capability      | Host functions                              |
| --------------- | ------------------------------------------- |
| *(none)*        | `log`, `input_len`, `input_read`, `output_write` |
| `ReadMessages`  | `room_messages_len`, `read_room_messages`   |
| `SendMessages`  | `send_room_message`                         |
| `Notify`        | `notify`                                    |
| `Clock`         | `now_ms`                                    |
| `FileAccess`, `NetworkAccess`, `StorageAccess`, `ManageRooms` | reserved, no host functions (granting them links nothing) |

## ABI

All host functions live in the import module `alterchat`. Pointers and lengths
are `i32` values that are read as unsigned wasm32 offsets. Functions that take
a pointer require the plugin to export its linear memory as `memory`. Only one
memory is allowed.

Every `(ptr, len)` pair is checked against the current memory size, with
overflow detection, and against a per-call size cap. A bad pointer, an
oversized buffer, invalid UTF-8 where text is required, or an exceeded quota
makes the call trap with a `SandboxViolation`, which aborts the run. The host
never panics on guest input. Each byte copied across the boundary also costs
1 unit of fuel.

| Import | Signature | Semantics |
| ------ | --------- | --------- |
| `log` | `(ptr, len) -> ()` | Append a log line (lossy UTF-8). Each entry is capped at 1 KiB. Lines past 64 entries are dropped and counted. |
| `input_len` | `() -> i32` | Length of the event payload in bytes. |
| `input_read` | `(ptr, cap) -> i32` | Copy up to `cap` bytes of the payload to `ptr`. Returns the number of bytes copied. |
| `output_write` | `(ptr, len) -> i32` | Append bytes to the output. The total is capped at 64 KiB. Returns 0. |
| `room_messages_len` | `() -> i32` | Length of the room snapshot JSON. |
| `read_room_messages` | `(ptr, cap) -> i32` | Copy up to `cap` bytes of the snapshot JSON. Returns the number of bytes copied. |
| `send_room_message` | `(ptr, len) -> i32` | Queue a room message. It must be UTF-8 and at most 4 KiB, with at most 8 per run. Returns 0. |
| `notify` | `(ptr, len) -> i32` | Queue a local notification. It must be UTF-8 and at most 256 B, with at most 4 per run. Returns 0. |
| `now_ms` | `() -> i64` | Unix time in milliseconds. |

The entrypoint is `() -> i32`. The return value is passed back as `status`.
The convention is that 0 means success.

### Room snapshot format

With `ReadMessages`, the desktop app passes the 50 most recent indexed
messages of the room named in the `run_plugin` call, oldest first:

```json
[{ "sender": "alice", "text": "hi", "timestamp": 1764000000000 }]
```

## Limits (`PluginLimits::default()`)

| Limit | Default |
| ----- | ------- |
| Fuel (instruction budget) | 10,000,000 |
| Linear memory | 16 pages (1 MiB), covering both the initial size and growth |
| WASM binary size | 4 MiB |
| Output | 64 KiB |
| Log | 64 entries × 1 KiB |
| Outgoing messages | 8 × 4 KiB |
| Notifications | 4 × 256 B |

Additional engine hardening:

- `memory.grow` past the limit traps instead of returning -1.
- `start` functions are refused.
- Multi-memory is disabled.
- wasmi's `EnforcedLimits::strict()` guards against parser and compiler DoS.
- Each store allows a single instance, at most 1 table and at most 10,000
  table elements.

Running out of fuel returns `PluginError::OutOfFuel`. Exceeding the memory
limit returns `PluginError::MemoryLimit`.

## Manifest signing

```rust
use alterchat_core::plugin::{create_plugin_manifest, PluginCapability};

let manifest = create_plugin_manifest(
    &author_keypair,          // libp2p Ed25519 keypair
    "org.example.echo".into(),
    "Echo".into(),
    "1.0.0".into(),
    "on_event".into(),        // exported entrypoint
    vec![],                   // requested capabilities
    &wasm_bytes,
)?;
```

The signature covers the bincode encoding of every manifest field except
`signature`: id, name, version, author peer id and public key, entrypoint,
capabilities, and the WASM hash. Changing any of these, or the binary itself,
invalidates the plugin. Because the encoding uses each capability's variant
index, new `PluginCapability` variants are only ever appended.

## Running a plugin from the desktop app

1. Install the plugin with `save_plugin`, passing the manifest, the `enabled`
   flag and the granted capabilities.
2. Run it with the Tauri command
   `run_plugin({ pluginId, wasm, eventJson, roomId? })`. The manifest, the
   enabled flag and the grants are always loaded from the DB, never taken from
   the caller. `wasm` must hash to the signed `wasm_hash`.

Execution happens on a blocking worker thread (`spawn_blocking`), never on the
async event loop. The command returns
`{ status, output, log, sentMessages, notifications, fuelConsumed }`. Queued
room messages go through the normal send path, with the plugin's name as the
nick. Notifications are emitted as `plugin-notification` events of the form
`(plugin_id, text)`.

## Minimal example plugin

This example is `alterchat-core/tests/fixtures/plugins/echo.wat`, which is
compiled with the `wat` crate in the unit tests. It needs no capabilities.

```wat
(module
  (import "alterchat" "log" (func $log (param i32 i32)))
  (import "alterchat" "input_read" (func $input_read (param i32 i32) (result i32)))
  (import "alterchat" "output_write" (func $output_write (param i32 i32) (result i32)))

  (memory (export "memory") 1 1)

  (data (i32.const 0) "echo: ")
  (data (i32.const 16) "echo plugin started")

  (func (export "on_event") (result i32)
    (local $n i32)
    (call $log (i32.const 16) (i32.const 19))
    (local.set $n (call $input_read (i32.const 1024) (i32.const 4096)))
    (drop (call $output_write (i32.const 0) (i32.const 6)))
    (drop (call $output_write (i32.const 1024) (local.get $n)))
    (i32.const 0)))
```

Build it to a binary with `wat2wasm echo.wat -o echo.wasm` (from wabt), or
with `wasm-tools parse`. You can also write plugins in Rust, targeting
`wasm32-unknown-unknown` with `#![no_std]`, or in any language that emits a
plain wasm32 module without WASI imports.
