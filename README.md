# go runtime hardware breakpoint extensions

modified go runtime (1.24.11) with native hardware breakpoint support via cpu debug registers.

## api

### sethardwarebreakpoint

```go
runtime.SetHardwareBreakpoint(address uintptr, slot int, handler func(*runtime.HWBPContext) bool)
```

sets a hardware breakpoint on the given address using debug register slot 0-3. handler is called when the breakpoint fires. return true to mark exception as handled, false to pass to next handler.

### clearhardwarebreakpoint

```go
runtime.ClearHardwareBreakpoint(slot int)
```

removes breakpoint from the given slot.

### hwbpcontext

context passed to handler with register access:

```go
// read registers
ctx.RIP() uint64   // instruction pointer
ctx.RSP() uint64   // stack pointer  
ctx.RAX() uint64   // return value
ctx.RCX() uint64   // 1st arg (win x64)
ctx.RDX() uint64   // 2nd arg
ctx.R8()  uint64   // 3rd arg
ctx.R9()  uint64   // 4th arg
ctx.R10() - ctx.R15()

// write registers
ctx.SetRIP(val uint64)
ctx.SetRSP(val uint64)
ctx.SetRAX(val uint64)
ctx.SetRCX(val uint64)
ctx.SetRDX(val uint64)
ctx.SetR8(val uint64)
ctx.SetR9(val uint64)

// memory
ctx.ReadMemory(addr uintptr, size int) []byte
ctx.WriteMemory(addr uintptr, data []byte)
```

## usage

```go
package main

import (
    "fmt"
    "runtime"
    
    "github.com/carved4/go-wincall"
)

// handler vars - set before hwbp, read after
var (
    hitRIP uint64
    hitRCX uint64
    wasHit bool
)

//go:nosplit
func hwbpHandler(ctx *runtime.HWBPContext) bool {
    // cannot use fmt or any allocating functions here
    hitRIP = ctx.RIP()
    hitRCX = ctx.RCX()
    wasHit = true
    
    ctx.SetRAX(0)
    runtime.ClearHardwareBreakpoint(0)
    return true
}

func main() {
    // resolve target address
    ntdllBase := wincall.GetModuleBase(wincall.GetHash("ntdll.dll"))
    targetAddr := wincall.GetFunctionAddress(ntdllBase, wincall.GetHash("NtOpenSection"))

    fmt.Printf("setting hwbp on 0x%x\n", targetAddr)

    // set breakpoint
    runtime.SetHardwareBreakpoint(targetAddr, 0, hwbpHandler)

    // trigger the function
    amsi, _ := wincall.UTF16ptr("amsi.dll")
    wincall.Call("kernel32.dll", "LoadLibraryW", amsi)

    // print results after handler ran
    if wasHit {
        fmt.Printf("hit at rip=0x%x, rcx=0x%x\n", hitRIP, hitRCX)
    }

    // cleanup
    runtime.ClearHardwareBreakpoint(0)
}

```

## notes

- call `runtime.LockOSThread()` before setting breakpoints
- handlers run on system stack - avoid allocations
- 4 slots available (dr0-dr3)
- breakpoints are per-thread, propagated via GetThreadContext/SetThreadContext

## build

```bash
cd src
./make.bat
```

## test

```bash
cd src/runtime
go test -v -run TestHardwareBreakpoint
```

## credits

- [evil-go](https://github.com/almounah/evil-go) by almounah - original peb walking and eat parsing used internally
- [go-wincall](https://github.com/carved4/go-wincall) - recommended for import-free api resolution

## license

bsd-3-clause

