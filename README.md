# go runtime hardware breakpoint extensions

modified go runtime (1.24.11) with native hardware breakpoint support and import-free windows api resolution.

## features

### hardware breakpoint api

native cpu debug register (dr0-dr3) manipulation exposed through go api:

```go
import "runtime"

// set a hardware breakpoint on any address
runtime.SetHardwareBreakpoint(address, slot, func(ctx *runtime.HWBPContext) bool {
    // access/modify cpu registers
    fmt.Printf("rip: 0x%x, rcx: 0x%x\n", ctx.RIP(), ctx.RCX())
    
    // modify execution
    ctx.SetRAX(0)           // set return value
    ctx.SetRIP(ctx.RIP()+5) // skip instruction
    
    return true // exception handled
})

// clear when done
runtime.ClearHardwareBreakpoint(slot)
```

### hwbpcontext methods

| method | description |
|--------|-------------|
| `RIP()`, `SetRIP()` | instruction pointer |
| `RSP()`, `SetRSP()` | stack pointer |
| `RAX()`, `SetRAX()` | return value register |
| `RCX()`, `SetRCX()` | 1st argument (windows x64 abi) |
| `RDX()`, `SetRDX()` | 2nd argument |
| `R8()`, `SetR8()` | 3rd argument |
| `R9()`, `SetR9()` | 4th argument |
| `R10()`-`R15()` | additional registers |
| `ReadMemory(addr, size)` | read memory at address |
| `WriteMemory(addr, data)` | write memory at address |

### import-free api resolution

resolve windows api addresses without syscall imports or iat entries:

```go
// get module base by hash (walks peb->ldr)
kernel32 := runtime.GetModuleHandleReplacement(runtime.Hash_kernel32)

// get function address by hash (parses eat)
procAddr := runtime.GetProcAddressReplacement(kernel32, runtime.Hash_GetCurrentThreadId)
```

## implementation

### veh integration

hardware breakpoint system integrates with windows vectored exception handling:

1. veh handler (`hwbpExceptionHandlerTrampoline`) registered with priority to intercept `EXCEPTION_SINGLE_STEP`
2. vch coordination - sets `hwbpHandled` flag so go's continue handlers skip non-go exceptions
3. context modification - direct manipulation of exception context (dr6, dr7, eflags rf bit)

### debug register management

- uses `GetThreadContext`/`SetThreadContext` for cross-thread breakpoint propagation
- direct context modification within exception handler for current thread
- resume flag (rf) handling to prevent re-trigger on same instruction

### files modified

| file | changes |
|------|---------|
| `src/runtime/os_windows.go` | veh handler, debug register management, `hwbpHooks` registry |
| `src/runtime/signal_windows.go` | vch coordination (`firstcontinuehandler` checks `hwbpHandled`) |
| `src/runtime/sys_windows_amd64.s` | assembly trampoline with abi switching |
| `src/runtime/hwbp_api.go` | public api (`SetHardwareBreakpoint`, `ClearHardwareBreakpoint`, `HWBPContext`) |

## example

intercept a windows api call:

```go
package main

import (
    "fmt"
    "runtime"
)

func main() {
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()

    // resolve GetCurrentThreadId
    kernel32 := runtime.GetModuleHandleReplacement_API(runtime.Hash_kernel32)
    addr := runtime.GetProcAddressReplacement_API(kernel32, runtime.Hash_GetCurrentThreadId)

    hitCount := 0
    runtime.SetHardwareBreakpoint(addr, 0, func(ctx *runtime.HWBPContext) bool {
        hitCount++
        fmt.Printf("intercepted GetCurrentThreadId, rip=0x%x\n", ctx.RIP())
        runtime.ClearHardwareBreakpoint(0)
        return true
    })

    tid := runtime.Stdcall0Test(runtime.GetCurrentThreadId_fn())
    fmt.Printf("thread id: %d, intercepted %d time(s)\n", tid, hitCount)
}
```

## build

```bash
cd src
./make.bat  # or ./all.bash on unix
```

## test

```bash
cd src/runtime
go test -v -run TestHardwareBreakpoint
```

## use cases

- api hooking without inline hooks
- dll injection via ntopensection interception
- syscall monitoring on ntdll stubs
- anti-debug evasion

## credits

- [evil-go](https://github.com/almounah/evil-go) by almounah - original `GetModuleHandleReplacement` and `GetProcAddressReplacement` implementations (peb walking, eat parsing). adapted here with hash-based lookups.

- [go-wincall](https://github.com/carved4/go-wincall) - companion library for import-free windows api calling.

## references

- intel sdm vol. 3 - debug registers
- windows veh documentation
- x64 calling convention

## license

bsd-3-clause (same as go)
