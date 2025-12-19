// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows && amd64

package runtime

import "unsafe"

// HardwareBreakpointHandler is the function signature for hardware breakpoint callbacks.
// The handler receives the CPU context when the breakpoint is hit.
// Return true to mark the exception as handled and continue execution.
// Return false to pass the exception to the next handler.
type HardwareBreakpointHandler func(regs *HWBPContext) bool

// HWBPContext provides access to CPU registers when a hardware breakpoint is hit.
type HWBPContext struct {
	ctx *context
}

// RIP returns the instruction pointer
func (h *HWBPContext) RIP() uint64 { return h.ctx.rip }

// RSP returns the stack pointer
func (h *HWBPContext) RSP() uint64 { return h.ctx.rsp }

// RBP returns the base pointer
func (h *HWBPContext) RBP() uint64 { return h.ctx.rbp }

// RAX returns register RAX
func (h *HWBPContext) RAX() uint64 { return h.ctx.rax }

// RBX returns register RBX
func (h *HWBPContext) RBX() uint64 { return h.ctx.rbx }

// RCX returns register RCX (1st argument in Windows x64 calling convention)
func (h *HWBPContext) RCX() uint64 { return h.ctx.rcx }

// RDX returns register RDX (2nd argument)
func (h *HWBPContext) RDX() uint64 { return h.ctx.rdx }

// R8 returns register R8 (3rd argument)
func (h *HWBPContext) R8() uint64 { return h.ctx.r8 }

// R9 returns register R9 (4th argument)
func (h *HWBPContext) R9() uint64 { return h.ctx.r9 }

// RSI returns register RSI
func (h *HWBPContext) RSI() uint64 { return h.ctx.rsi }

// RDI returns register RDI
func (h *HWBPContext) RDI() uint64 { return h.ctx.rdi }

// R10-R15 getters
func (h *HWBPContext) R10() uint64 { return h.ctx.r10 }
func (h *HWBPContext) R11() uint64 { return h.ctx.r11 }
func (h *HWBPContext) R12() uint64 { return h.ctx.r12 }
func (h *HWBPContext) R13() uint64 { return h.ctx.r13 }
func (h *HWBPContext) R14() uint64 { return h.ctx.r14 }
func (h *HWBPContext) R15() uint64 { return h.ctx.r15 }

// SetRIP sets the instruction pointer
func (h *HWBPContext) SetRIP(val uint64) { h.ctx.rip = val }

// SetRSP sets the stack pointer
func (h *HWBPContext) SetRSP(val uint64) { h.ctx.rsp = val }

// SetRAX sets register RAX (return value)
func (h *HWBPContext) SetRAX(val uint64) { h.ctx.rax = val }

// SetRCX sets register RCX
func (h *HWBPContext) SetRCX(val uint64) { h.ctx.rcx = val }

// SetRDX sets register RDX
func (h *HWBPContext) SetRDX(val uint64) { h.ctx.rdx = val }

// SetR8 sets register R8
func (h *HWBPContext) SetR8(val uint64) { h.ctx.r8 = val }

// SetR9 sets register R9
func (h *HWBPContext) SetR9(val uint64) { h.ctx.r9 = val }

// ReadMemory reads memory at the given address
func (h *HWBPContext) ReadMemory(addr uintptr, size int) []byte {
	if size <= 0 || size > 4096 {
		return nil
	}
	data := make([]byte, size)
	src := (*[4096]byte)(unsafe.Pointer(addr))
	copy(data, src[:size])
	return data
}

// WriteMemory writes data to memory at the given address
func (h *HWBPContext) WriteMemory(addr uintptr, data []byte) {
	if len(data) == 0 || len(data) > 4096 {
		return
	}
	dst := (*[4096]byte)(unsafe.Pointer(addr))
	copy(dst[:len(data)], data)
}

// Internal handler registry to avoid closures
var userHandlers [4]HardwareBreakpointHandler

// SetHardwareBreakpoint registers a hardware breakpoint on the given address .
// slot must be 0-3 (corresponding to DR0-DR3 debug registers).
// The handler will be called when the breakpoint is hit.
func SetHardwareBreakpoint(address uintptr, slot int, handler HardwareBreakpointHandler) {
	if slot < 0 || slot > 3 {
		return
	}
	
	// Store user handler
	userHandlers[slot] = handler
	
	// Register internal handler that wraps context
	RegisterHardwareBreakpoint(address, slot, hwbpInternalHandler)
}

// hwbpInternalHandler is the internal handler that converts context to HWBPContext
//
//go:nosplit
func hwbpInternalHandler(ctx *context) bool {
	// Determine which slot triggered by checking DR6
	slot := -1
	if ctx.dr6&0x1 != 0 {
		slot = 0
	} else if ctx.dr6&0x2 != 0 {
		slot = 1
	} else if ctx.dr6&0x4 != 0 {
		slot = 2
	} else if ctx.dr6&0x8 != 0 {
		slot = 3
	}
	
	if slot < 0 || slot > 3 || userHandlers[slot] == nil {
		return false
	}
	
	hwbpCtx := &HWBPContext{ctx: ctx}
	return userHandlers[slot](hwbpCtx)
}

// ClearHardwareBreakpoint removes a hardware breakpoint from the given slot.
func ClearHardwareBreakpoint(slot int) {
	if slot >= 0 && slot <= 3 {
		userHandlers[slot] = nil
	}
	UnregisterHardwareBreakpoint(slot)
}

// Expose hash constants for testing
const (
	Hash_kernel32           = hash_kernel32
	Hash_GetCurrentThreadId = hash_GetCurrentThreadId
)

// GetCurrentThreadId_fn returns the _GetCurrentThreadId function pointer
func GetCurrentThreadId_fn() stdFunction {
	return _GetCurrentThreadId
}

// Stdcall0Test wraps stdcall0 for testing
func Stdcall0Test(fn stdFunction) uintptr {
	return stdcall0(fn)
}

// GetModuleHandleReplacement_API exposes GetModuleHandleReplacement for testing
func GetModuleHandleReplacement_API(hash uint32) uintptr {
	return uintptr(GetModuleHandleReplacement(hash))
}

// GetProcAddressReplacement_API exposes GetProcAddressReplacement for testing
func GetProcAddressReplacement_API(hModule uintptr, hash uint32) uintptr {
	return GetProcAddressReplacement(HANDLE(unsafe.Pointer(hModule)), hash)
}

