;; Minimal AlterChat plugin: logs a line and echoes the event payload back
;; prefixed with "echo: ". Needs no capabilities (log/input/output are
;; always linked). See docs/PLUGINS.md for the full ABI.
(module
  (import "alterchat" "log" (func $log (param i32 i32)))
  (import "alterchat" "input_read" (func $input_read (param i32 i32) (result i32)))
  (import "alterchat" "output_write" (func $output_write (param i32 i32) (result i32)))

  ;; One 64 KiB page, not growable.
  (memory (export "memory") 1 1)

  (data (i32.const 0) "echo: ")               ;; 6 bytes
  (data (i32.const 16) "echo plugin started") ;; 19 bytes

  ;; Entrypoint named in the manifest: () -> i32 status (0 = ok).
  (func (export "on_event") (result i32)
    (local $n i32)
    (call $log (i32.const 16) (i32.const 19))
    ;; Copy up to 4 KiB of the event payload to offset 1024.
    (local.set $n (call $input_read (i32.const 1024) (i32.const 4096)))
    (drop (call $output_write (i32.const 0) (i32.const 6)))
    (drop (call $output_write (i32.const 1024) (local.get $n)))
    (i32.const 0)))
