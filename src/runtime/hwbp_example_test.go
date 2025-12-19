// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows && amd64

package runtime_test

import (
	"runtime"
	"testing"
	"unsafe"
)

// Test 1: Verify hardware breakpoint registration doesn't crash
func TestHardwareBreakpoint_register(t *testing.T) {
	t.Log("Testing breakpoint registration...")
	
	testFunc := func() int {
		return 42
	}
	
	// Get function address via reflection
	funcAddr := *(*uintptr)(unsafe.Pointer(&testFunc))
	t.Logf("Function address: 0x%x", funcAddr)
	
	handler := func(ctx *runtime.HWBPContext) bool {
		t.Log("Handler called")
		return true
	}
	
	t.Log("Registering breakpoint...")
	runtime.SetHardwareBreakpoint(funcAddr, 0, handler)
	
	t.Log("Unregistering breakpoint...")
	runtime.ClearHardwareBreakpoint(0)
	
	t.Log("Registration test passed")
}

// Test 2: Call function WITHOUT breakpoint to ensure it works
func TestHardwareBreakpoint_noBreakpoint(t *testing.T) {
	t.Log("Testing function call without breakpoint...")
	
	testFunc := func() int {
		return 42
	}
	
	result := testFunc()
	
	if result != 42 {
		t.Errorf("Expected 42, got %d", result)
	}
	
	t.Log("Function call succeeded:", result)
}

// Test 3: Verify breakpoint can be set and cleared without crash
func TestHardwareBreakpoint_SetClear(t *testing.T) {
	t.Log("Testing hardware breakpoint set/clear cycle...")
	
	// Get address of a Windows function
	kernel32 := runtime.GetModuleHandleReplacement_API(runtime.Hash_kernel32)
	if kernel32 == 0 {
		t.Fatal("Failed to get kernel32 handle")
	}
	
	getCurrentThreadIdAddr := runtime.GetProcAddressReplacement_API(kernel32, runtime.Hash_GetCurrentThreadId)
	if getCurrentThreadIdAddr == 0 {
		t.Fatal("Failed to get GetCurrentThreadId address")
	}
	
	t.Logf("GetCurrentThreadId address: 0x%x", getCurrentThreadIdAddr)
	
	callCount := 0
	handler := func(ctx *runtime.HWBPContext) bool {
		callCount++
		// Clear breakpoint after first hit to prevent re-triggering
		// (Cannot use t.Logf here - we're on exception handler stack)
		if callCount == 1 {
			runtime.ClearHardwareBreakpoint(0)
		}
		// Safety limit
		if callCount > 10 {
			return false
		}
		return true
	}
	
	t.Log("Setting breakpoint...")
	runtime.SetHardwareBreakpoint(getCurrentThreadIdAddr, 0, handler)
	
	t.Log("Calling GetCurrentThreadId (should trigger breakpoint once)...")
	threadId := runtime.Stdcall0Test(runtime.GetCurrentThreadId_fn())
	t.Log("GetCurrentThreadId returned!")
	
	t.Logf("Thread ID: %d", threadId)
	t.Logf("Breakpoint was triggered %d time(s)", callCount)
	
	if callCount == 1 {
		t.Log("SUCCESS: Hardware breakpoint triggered exactly once and was cleared!")
	} else if callCount > 1 {
		t.Errorf("Breakpoint triggered %d times (expected 1) - clear didn't work", callCount)
	} else {
		t.Error("Breakpoint was not triggered")
	}
	
	// Clean up
	runtime.ClearHardwareBreakpoint(0)
}


