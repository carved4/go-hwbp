// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"internal/runtime/atomic"
	"internal/runtime/sys"
	"unsafe"
)

// TODO(brainman): should not need those
const (
	_NSIG = 65
)

// API and DLL name hashes - precomputed FNV-1a hashes
const (
	// DLL name hashes (Unicode)
	hash_ntdll    = 0xa62a3b3b // ntdll.dll
	hash_kernel32 = 0xa3e6f6c3 // kernel32.dll

	// API name hashes (ASCII)
	hash_RtlAddVectoredContinueHandler  = 0xa8a49095 // RtlAddVectoredContinueHandler
	hash_RtlAddVectoredExceptionHandler = 0xfd25be65 // RtlAddVectoredExceptionHandler
	hash_CloseHandle                    = 0x8285aca5 // CloseHandle
	hash_CreateEventA                   = 0x1c6cdd42 // CreateEventA
	hash_CreateIoCompletionPort         = 0x2f9e5b2c // CreateIoCompletionPort
	hash_CreateThread                   = 0x63464b39 // CreateThread
	hash_CreateWaitableTimerExW         = 0x96092761 // CreateWaitableTimerExW
	hash_CreateWaitableTimerA           = 0x51047eb0 // CreateWaitableTimerA
	hash_DuplicateHandle                = 0x87315870 // DuplicateHandle
	hash_ExitProcess                    = 0x52a4cf3a // ExitProcess
	hash_FreeEnvironmentStringsW        = 0x7993f06f // FreeEnvironmentStringsW
	hash_GetConsoleMode                 = 0xcd91fa4f // GetConsoleMode
	hash_GetCurrentThreadId             = 0x218694d5 // GetCurrentThreadId
	hash_GetEnvironmentStringsW         = 0xd294512b // GetEnvironmentStringsW
	hash_GetErrorMode                   = 0xad594280 // GetErrorMode
	hash_GetProcAddress                 = 0xb8e4e945 // GetProcAddress
	hash_GetProcessAffinityMask         = 0xe9dae1b0 // GetProcessAffinityMask
	hash_GetQueuedCompletionStatusEx    = 0xc07129e3 // GetQueuedCompletionStatusEx
	hash_GetStdHandle                   = 0xd7bec4ca // GetStdHandle
	hash_GetSystemDirectoryA            = 0xc6e40c14 // GetSystemDirectoryA
	hash_GetSystemInfo                  = 0xb7389886 // GetSystemInfo
	hash_GetThreadContext               = 0x5b087f5e // GetThreadContext
	hash_SetThreadContext               = 0xc68775f2 // SetThreadContext
	hash_LoadLibraryExW                 = 0x554c4fc2 // LoadLibraryExW
	hash_LoadLibraryW                   = 0x3bbc54d9 // LoadLibraryW
	hash_PostQueuedCompletionStatus     = 0x8d4ec1c6 // PostQueuedCompletionStatus
	hash_RaiseFailFastException         = 0x450dc0ea // RaiseFailFastException
	hash_ResumeThread                   = 0x7ca66aee // ResumeThread
	hash_RtlLookupFunctionEntry         = 0xf555014d // RtlLookupFunctionEntry
	hash_RtlVirtualUnwind               = 0x7c033891 // RtlVirtualUnwind
	hash_QueryPerformanceCounter        = 0xd7a2f461 // QueryPerformanceCounter
	hash_QueryPerformanceFrequency      = 0x757a0dd7 // QueryPerformanceFrequency
	hash_SetConsoleCtrlHandler          = 0xa5ff68b7 // SetConsoleCtrlHandler
	hash_SetErrorMode                   = 0xb1d3c5d4 // SetErrorMode
	hash_SetEvent                       = 0xfd87b071 // SetEvent
	hash_SetProcessPriorityBoost        = 0x0775728b // SetProcessPriorityBoost
	hash_SetThreadPriority              = 0x467e11d3 // SetThreadPriority
	hash_SetUnhandledExceptionFilter    = 0x8b519c0d // SetUnhandledExceptionFilter
	hash_SetWaitableTimer               = 0x67c4163f // SetWaitableTimer
	hash_SwitchToThread                 = 0x45508980 // SwitchToThread
	hash_SuspendThread                  = 0x2a6cb66b // SuspendThread
	hash_VirtualAlloc                   = 0x0700da41 // VirtualAlloc
	hash_VirtualFree                    = 0x6bcbc4b2 // VirtualFree
	hash_VirtualQuery                   = 0xee64f538 // VirtualQuery
	hash_WaitForSingleObject            = 0x93fae264 // WaitForSingleObject
	hash_WaitForMultipleObjects         = 0x259043a9 // WaitForMultipleObjects
	hash_WerGetFlags                    = 0xa4251eaa // WerGetFlags
	hash_WerSetFlags                    = 0x439f4dfe // WerSetFlags
	hash_WriteConsoleW                  = 0x6aa01176 // WriteConsoleW
	hash_WriteFile                      = 0x84aec1ca // WriteFile
	hash_TlsAlloc                       = 0xddf1729b // TlsAlloc
)

func GetPEB() uintptr
func fnv1aHash(str *byte) uint32
func fnv1aHashUnicode(buffer *uint16, length uint16) uint32

// hashString is a Go wrapper to hash a string using the assembly function
func hashString(s string) uint32 {
	if len(s) == 0 {
		return 0
	}
	// Create null-terminated byte array
	b := make([]byte, len(s)+1)
	copy(b, s)
	b[len(s)] = 0
	return fnv1aHash(&b[0])
}

func hashEqual2(pBase uintptr, rva DWORD, targetHash uint32) bool {
	addr := uintptr(pBase + uintptr(rva))
	hash := fnv1aHash((*byte)(unsafe.Pointer(addr)))
	return hash == targetHash
}

func hashEqualUnicode(uniStr *UNICODE_STRING, targetHash uint32) bool {
	hash := fnv1aHashUnicode(uniStr.Buffer, uint16(uniStr.Length))
	return hash == targetHash
}

func areEqual(uniStr *UNICODE_STRING, target string) bool {
	numChars := int(uniStr.Length / 2)
	if numChars != len(target) {
		return false
	}

	for i := 0; i < numChars; i++ {
		s := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(uniStr.Buffer)) + uintptr(i*2)))
		if ToLower(string(UTF16Decode(s))) != ToLower(string(target[i])) {
			return false
		}
	}

	return true
}

func ToLower(s string) string {
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		if runes[i] >= 'A' && runes[i] <= 'Z' {
			runes[i] = runes[i] + 32
		}
	}
	return string(runes)
}

func UTF16Decode(c uint16) rune {
	if c < 0xD800 || c > 0xDFFF {
		return rune(c)
	}

	if c >= 0xD800 && c <= 0xDBFF {
		return rune(0)
	}

	return rune(0)
}

func GetProcAddressReplacement(hModule HANDLE, lpApiNameHash uint32) uintptr {
	pBase := unsafe.Pointer(hModule)
	pImgDosHeader := PIMAGE_DOS_HEADER(pBase)
	if pImgDosHeader.E_magic != IMAGE_DOS_SIGNATURE {
		println("Messed Up Getting the DosHeader")
	}

	pImgNtHdrs := PIMAGE_NT_HEADERS32(unsafe.Pointer(uintptr(pBase) + uintptr(pImgDosHeader.E_lfanew)))
	if pImgNtHdrs.Signature != IMAGE_NT_SIGNATURE {
		return 0
	}

	if pImgNtHdrs.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 {
		pImgNtHdrs64 := PIMAGE_NT_HEADERS64(unsafe.Pointer(pImgNtHdrs))
		ImgOptHdr := pImgNtHdrs64.OptionalHeader
		if ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
			return 0
		}
		pImgExportDir := PIMAGE_EXPORT_DIRECTORY(unsafe.Pointer(uintptr(pBase) + uintptr(ImgOptHdr.DataDirectory.VirtualAddress)))

		numFunction := pImgExportDir.NumberOfFunctions

		AddressOfFuntionArray := unsafe.Slice((*DWORD)(unsafe.Pointer(uintptr(pBase)+uintptr(pImgExportDir.AddressOfFunctions))), pImgExportDir.NumberOfFunctions)
		AddressOfNamesArray := unsafe.Slice((*DWORD)(unsafe.Pointer(uintptr(pBase)+uintptr(pImgExportDir.AddressOfNames))), pImgExportDir.NumberOfFunctions)
		AddressOfNameOrdinalArray := unsafe.Slice((*WORD)(unsafe.Pointer(uintptr(pBase)+uintptr(pImgExportDir.AddressOfNameOrdinals))), pImgExportDir.NumberOfFunctions)

		for i := DWORD(0); i < numFunction; i++ {
			functionNameRVA := AddressOfNamesArray[i]

			if hashEqual2(uintptr(pBase), functionNameRVA, lpApiNameHash) {
				return uintptr(pBase) + uintptr(AddressOfFuntionArray[AddressOfNameOrdinalArray[i]])
			}
		}

	}
	return 0
}

func GetModuleHandleReplacement(wantedModuleHash uint32) (e HANDLE) {
	ppeb_uintptr := GetPEB()

	ppeb := PPEB64(unsafe.Pointer(uintptr(ppeb_uintptr)))

	pLdr := ppeb.LoaderData
	pListEntry := pLdr.InMemoryOrderModuleList.Flink
	pListEntryStart := pLdr.InMemoryOrderModuleList.Blink

	for pListEntry != pListEntryStart {
		pDte := PLDR_DATA_TABLE_ENTRY(unsafe.Pointer(pListEntry))
		if hashEqualUnicode(&pDte.FullDllName, wantedModuleHash) {
			return HANDLE(unsafe.Pointer(pDte.InInitializationOrderLinks.Flink))
		}

		pListEntry = pListEntry.Flink
	}
	pDte := PLDR_DATA_TABLE_ENTRY(unsafe.Pointer(pListEntry))
	if hashEqualUnicode(&pDte.FullDllName, wantedModuleHash) {
		return HANDLE(unsafe.Pointer(pDte.InInitializationOrderLinks.Flink))
	}
	return 0
}


//go:cgo_import_dynamic runtime._TlsAlloc TlsAlloc%0 "kernel32.dll"

type stdFunction unsafe.Pointer

var (
	// Following syscalls are available on every Windows PC.
	// All these variables are set by the Windows executable
	// loader before the Go program starts.
	_AddVectoredContinueHandler,
	_AddVectoredExceptionHandler,
	_CloseHandle,
	_CreateEventA,
	_CreateIoCompletionPort,
	_CreateThread,
	_CreateWaitableTimerA,
	_CreateWaitableTimerExW,
	_DuplicateHandle,
	_ExitProcess,
	_FreeEnvironmentStringsW,
	_GetConsoleMode,
	_GetCurrentThreadId,
	_GetEnvironmentStringsW,
	_GetErrorMode,
	_GetProcAddress,
	_GetProcessAffinityMask,
	_GetQueuedCompletionStatusEx,
	_GetStdHandle,
	_GetSystemDirectoryA,
	_GetSystemInfo,
	_GetThreadContext,
	_SetThreadContext,
	_LoadLibraryExW,
	_LoadLibraryW,
	_PostQueuedCompletionStatus,
	_QueryPerformanceCounter,
	_QueryPerformanceFrequency,
	_RaiseFailFastException,
	_ResumeThread,
	_RtlLookupFunctionEntry,
	_RtlVirtualUnwind,
	_SetConsoleCtrlHandler,
	_SetErrorMode,
	_SetEvent,
	_SetProcessPriorityBoost,
	_SetThreadPriority,
	_SetUnhandledExceptionFilter,
	_SetWaitableTimer,
	_SuspendThread,
	_SwitchToThread,
	_TlsAlloc,
	_VirtualAlloc,
	_VirtualFree,
	_VirtualQuery,
	_WaitForSingleObject,
	_WaitForMultipleObjects,
	_WerGetFlags,
	_WerSetFlags,
	_WriteConsoleW,
	_WriteFile,
	_ stdFunction

	// Use ProcessPrng to generate cryptographically random data.
	_ProcessPrng stdFunction

	// Load ntdll.dll manually during startup, otherwise Mingw
	// links wrong printf function to cgo executable (see issue
	// 12030 for details).
	_NtCreateWaitCompletionPacket    stdFunction
	_NtAssociateWaitCompletionPacket stdFunction
	_NtCancelWaitCompletionPacket    stdFunction
	_RtlGetCurrentPeb                stdFunction
	_RtlGetVersion                   stdFunction

	// These are from non-kernel32.dll, so we prefer to LoadLibraryEx them.
	_timeBeginPeriod,
	_timeEndPeriod,
	_ stdFunction
)

var (
	bcryptprimitivesdll = [...]uint16{'b', 'c', 'r', 'y', 'p', 't', 'p', 'r', 'i', 'm', 'i', 't', 'i', 'v', 'e', 's', '.', 'd', 'l', 'l', 0}
	ntdlldll            = [...]uint16{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0}
	powrprofdll         = [...]uint16{'p', 'o', 'w', 'r', 'p', 'r', 'o', 'f', '.', 'd', 'l', 'l', 0}
	winmmdll            = [...]uint16{'w', 'i', 'n', 'm', 'm', '.', 'd', 'l', 'l', 0}
)

// Function to be called by windows CreateThread
// to start new os thread.
func tstart_stdcall(newm *m)

// Init-time helper
func wintls()

type mOS struct {
	threadLock mutex   // protects "thread" and prevents closing
	thread     uintptr // thread handle

	waitsema   uintptr // semaphore for parking on locks
	resumesema uintptr // semaphore to indicate suspend/resume

	highResTimer   uintptr // high resolution timer handle used in usleep
	waitIocpTimer  uintptr // high resolution timer handle used in netpoll
	waitIocpHandle uintptr // wait completion handle used in netpoll

	// preemptExtLock synchronizes preemptM with entry/exit from
	// external C code.
	//
	// This protects against races between preemptM calling
	// SuspendThread and external code on this thread calling
	// ExitProcess. If these happen concurrently, it's possible to
	// exit the suspending thread and suspend the exiting thread,
	// leading to deadlock.
	//
	// 0 indicates this M is not being preempted or in external
	// code. Entering external code CASes this from 0 to 1. If
	// this fails, a preemption is in progress, so the thread must
	// wait for the preemption. preemptM also CASes this from 0 to
	// 1. If this fails, the preemption fails (as it would if the
	// PC weren't in Go code). The value is reset to 0 when
	// returning from external code or after a preemption is
	// complete.
	//
	// TODO(austin): We may not need this if preemption were more
	// tightly synchronized on the G/P status and preemption
	// blocked transition into _Gsyscall/_Psyscall.
	preemptExtLock uint32
}

// Stubs so tests can link correctly. These should never be called.
func open(name *byte, mode, perm int32) int32 {
	throw("unimplemented")
	return -1
}
func closefd(fd int32) int32 {
	throw("unimplemented")
	return -1
}
func read(fd int32, p unsafe.Pointer, n int32) int32 {
	throw("unimplemented")
	return -1
}

type sigset struct{}

// Call a Windows function with stdcall conventions,
// and switch to os stack during the call.
func asmstdcall(fn unsafe.Pointer)

var asmstdcallAddr unsafe.Pointer

type winlibcall libcall

func windowsFindfunc(lib uintptr, name []byte) stdFunction {
	if name[len(name)-1] != 0 {
		throw("usage")
	}
	f := stdcall2(_GetProcAddress, lib, uintptr(unsafe.Pointer(&name[0])))
	return stdFunction(unsafe.Pointer(f))
}

const _MAX_PATH = 260 // https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation
var sysDirectory [_MAX_PATH + 1]byte
var sysDirectoryLen uintptr

func initSysDirectory() {
	l := stdcall2(_GetSystemDirectoryA, uintptr(unsafe.Pointer(&sysDirectory[0])), uintptr(len(sysDirectory)-1))
	if l == 0 || l > uintptr(len(sysDirectory)-1) {
		throw("Unable to determine system directory")
	}
	sysDirectory[l] = '\\'
	sysDirectoryLen = l + 1
}

//go:linkname windows_GetSystemDirectory internal/syscall/windows.GetSystemDirectory
func windows_GetSystemDirectory() string {
	return unsafe.String(&sysDirectory[0], sysDirectoryLen)
}

func windowsLoadSystemLib(name []uint16) uintptr {
	return stdcall3(_LoadLibraryExW, uintptr(unsafe.Pointer(&name[0])), 0, _LOAD_LIBRARY_SEARCH_SYSTEM32)
}

//go:linkname windows_QueryPerformanceCounter internal/syscall/windows.QueryPerformanceCounter
func windows_QueryPerformanceCounter() int64 {
	var counter int64
	stdcall1(_QueryPerformanceCounter, uintptr(unsafe.Pointer(&counter)))
	return counter
}

//go:linkname windows_QueryPerformanceFrequency internal/syscall/windows.QueryPerformanceFrequency
func windows_QueryPerformanceFrequency() int64 {
	var frequency int64
	stdcall1(_QueryPerformanceFrequency, uintptr(unsafe.Pointer(&frequency)))
	return frequency
}

func loadOptionalSyscalls() {
	bcryptPrimitives := windowsLoadSystemLib(bcryptprimitivesdll[:])
	if bcryptPrimitives == 0 {
		throw("bcryptprimitives.dll not found")
	}
	_ProcessPrng = windowsFindfunc(bcryptPrimitives, []byte("ProcessPrng\000"))

	n32 := windowsLoadSystemLib(ntdlldll[:])
	if n32 == 0 {
		throw("ntdll.dll not found")
	}
	_NtCreateWaitCompletionPacket = windowsFindfunc(n32, []byte("NtCreateWaitCompletionPacket\000"))
	if _NtCreateWaitCompletionPacket != nil {
		// These functions should exists if NtCreateWaitCompletionPacket exists.
		_NtAssociateWaitCompletionPacket = windowsFindfunc(n32, []byte("NtAssociateWaitCompletionPacket\000"))
		if _NtAssociateWaitCompletionPacket == nil {
			throw("NtCreateWaitCompletionPacket exists but NtAssociateWaitCompletionPacket does not")
		}
		_NtCancelWaitCompletionPacket = windowsFindfunc(n32, []byte("NtCancelWaitCompletionPacket\000"))
		if _NtCancelWaitCompletionPacket == nil {
			throw("NtCreateWaitCompletionPacket exists but NtCancelWaitCompletionPacket does not")
		}
	}
	_RtlGetCurrentPeb = windowsFindfunc(n32, []byte("RtlGetCurrentPeb\000"))
	_RtlGetVersion = windowsFindfunc(n32, []byte("RtlGetVersion\000"))
}

func monitorSuspendResume() {
	const (
		_DEVICE_NOTIFY_CALLBACK = 2
	)
	type _DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS struct {
		callback uintptr
		context  uintptr
	}

	powrprof := windowsLoadSystemLib(powrprofdll[:])
	if powrprof == 0 {
		return // Running on Windows 7, where we don't need it anyway.
	}
	powerRegisterSuspendResumeNotification := windowsFindfunc(powrprof, []byte("PowerRegisterSuspendResumeNotification\000"))
	if powerRegisterSuspendResumeNotification == nil {
		return // Running on Windows 7, where we don't need it anyway.
	}
	var fn any = func(context uintptr, changeType uint32, setting uintptr) uintptr {
		for mp := (*m)(atomic.Loadp(unsafe.Pointer(&allm))); mp != nil; mp = mp.alllink {
			if mp.resumesema != 0 {
				stdcall1(_SetEvent, mp.resumesema)
			}
		}
		return 0
	}
	params := _DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS{
		callback: compileCallback(*efaceOf(&fn), true),
	}
	handle := uintptr(0)
	stdcall3(powerRegisterSuspendResumeNotification, _DEVICE_NOTIFY_CALLBACK,
		uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(&handle)))
}

func getproccount() int32 {
	var mask, sysmask uintptr
	ret := stdcall3(_GetProcessAffinityMask, currentProcess, uintptr(unsafe.Pointer(&mask)), uintptr(unsafe.Pointer(&sysmask)))
	if ret != 0 {
		n := 0
		maskbits := int(unsafe.Sizeof(mask) * 8)
		for i := 0; i < maskbits; i++ {
			if mask&(1<<uint(i)) != 0 {
				n++
			}
		}
		if n != 0 {
			return int32(n)
		}
	}
	// use GetSystemInfo if GetProcessAffinityMask fails
	var info systeminfo
	stdcall1(_GetSystemInfo, uintptr(unsafe.Pointer(&info)))
	return int32(info.dwnumberofprocessors)
}

func getPageSize() uintptr {
	var info systeminfo
	stdcall1(_GetSystemInfo, uintptr(unsafe.Pointer(&info)))
	return uintptr(info.dwpagesize)
}

const (
	currentProcess = ^uintptr(0) // -1 = current process
	currentThread  = ^uintptr(1) // -2 = current thread
)

// Hardware breakpoint constants
const (
	_CONTEXT_DEBUG_REGISTERS = 0x00010010
	_EXCEPTION_SINGLE_STEP   = 0x80000004
	_EFLAGS_RF               = 0x00010000 // Resume Flag - skip breakpoints for one instruction

	// Debug register control bits
	_DR7_L0 = 1 << 0 // Local breakpoint 0
	_DR7_G0 = 1 << 1 // Global breakpoint 0
	_DR7_L1 = 1 << 2
	_DR7_G1 = 1 << 3
	_DR7_L2 = 1 << 4
	_DR7_G2 = 1 << 5
	_DR7_L3 = 1 << 6
	_DR7_G3 = 1 << 7

	// Breakpoint conditions (RW bits in DR7)
	_DR7_RW_EXECUTE   = 0x0
	_DR7_RW_WRITE     = 0x1
	_DR7_RW_READWRITE = 0x3

	// Breakpoint size (LEN bits in DR7)
	_DR7_LEN_1 = 0x0
	_DR7_LEN_2 = 0x1
	_DR7_LEN_4 = 0x3
	_DR7_LEN_8 = 0x2
)

// Hardware breakpoint hook function signature  
// Uses uintptr to store function pointer to avoid heap allocation
type hwbpHandler uintptr

// Hardware breakpoint configuration
type hwbpConfig struct {
	address uintptr
	slot    uint8
	handler hwbpHandler
	enabled bool
}

var (
	// Global hardware breakpoint registry
	hwbpHooks     [4]hwbpConfig
	hwbpHooksLock mutex
	hwbpVEHHandle uintptr
	hwbpEnabled   bool
	hwbpInHandler bool    // true when inside exception handler
	hwbpHandled   uintptr // RIP of last handled HWBP exception (for continue handler)
)

// in sys_windows_386.s and sys_windows_amd64.s:
func getlasterror() uint32

var timeBeginPeriodRetValue uint32

// osRelaxMinNS indicates that sysmon shouldn't osRelax if the next
// timer is less than 60 ms from now. Since osRelaxing may reduce
// timer resolution to 15.6 ms, this keeps timer error under roughly 1
// part in 4.
const osRelaxMinNS = 60 * 1e6

// osRelax is called by the scheduler when transitioning to and from
// all Ps being idle.
//
// Some versions of Windows have high resolution timer. For those
// versions osRelax is noop.
// For Windows versions without high resolution timer, osRelax
// adjusts the system-wide timer resolution. Go needs a
// high resolution timer while running and there's little extra cost
// if we're already using the CPU, but if all Ps are idle there's no
// need to consume extra power to drive the high-res timer.
func osRelax(relax bool) uint32 {
	if haveHighResTimer {
		// If the high resolution timer is available, the runtime uses the timer
		// to sleep for short durations. This means there's no need to adjust
		// the global clock frequency.
		return 0
	}

	if relax {
		return uint32(stdcall1(_timeEndPeriod, 1))
	} else {
		return uint32(stdcall1(_timeBeginPeriod, 1))
	}
}

// haveHighResTimer indicates that the CreateWaitableTimerEx
// CREATE_WAITABLE_TIMER_HIGH_RESOLUTION flag is available.
var haveHighResTimer = false

// haveHighResSleep indicates that NtCreateWaitCompletionPacket
// exists and haveHighResTimer is true.
// NtCreateWaitCompletionPacket has been available since Windows 10,
// but has just been publicly documented, so some platforms, like Wine,
// doesn't support it yet.
var haveHighResSleep = false

// createHighResTimer calls CreateWaitableTimerEx with
// CREATE_WAITABLE_TIMER_HIGH_RESOLUTION flag to create high
// resolution timer. createHighResTimer returns new timer
// handle or 0, if CreateWaitableTimerEx failed.
func createHighResTimer() uintptr {
	const (
		// As per @jstarks, see
		// https://github.com/golang/go/issues/8687#issuecomment-656259353
		_CREATE_WAITABLE_TIMER_HIGH_RESOLUTION = 0x00000002

		_SYNCHRONIZE        = 0x00100000
		_TIMER_QUERY_STATE  = 0x0001
		_TIMER_MODIFY_STATE = 0x0002
	)
	return stdcall4(_CreateWaitableTimerExW, 0, 0,
		_CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
		_SYNCHRONIZE|_TIMER_QUERY_STATE|_TIMER_MODIFY_STATE)
}

func initHighResTimer() {
	h := createHighResTimer()
	if h != 0 {
		haveHighResTimer = true
		haveHighResSleep = _NtCreateWaitCompletionPacket != nil
		stdcall1(_CloseHandle, h)
	} else {
		// Only load winmm.dll if we need it.
		// This avoids a dependency on winmm.dll for Go programs
		// that run on new Windows versions.
		m32 := windowsLoadSystemLib(winmmdll[:])
		if m32 == 0 {
			print("runtime: LoadLibraryExW failed; errno=", getlasterror(), "\n")
			throw("winmm.dll not found")
		}
		_timeBeginPeriod = windowsFindfunc(m32, []byte("timeBeginPeriod\000"))
		_timeEndPeriod = windowsFindfunc(m32, []byte("timeEndPeriod\000"))
		if _timeBeginPeriod == nil || _timeEndPeriod == nil {
			print("runtime: GetProcAddress failed; errno=", getlasterror(), "\n")
			throw("timeBegin/EndPeriod not found")
		}
	}
}

//go:linkname canUseLongPaths internal/syscall/windows.CanUseLongPaths
var canUseLongPaths bool

// initLongPathSupport enables long path support.
func initLongPathSupport() {
	const (
		IsLongPathAwareProcess = 0x80
		PebBitFieldOffset      = 3
	)

	// Check that we're ≥ 10.0.15063.
	info := _OSVERSIONINFOW{}
	info.osVersionInfoSize = uint32(unsafe.Sizeof(info))
	stdcall1(_RtlGetVersion, uintptr(unsafe.Pointer(&info)))
	if info.majorVersion < 10 || (info.majorVersion == 10 && info.minorVersion == 0 && info.buildNumber < 15063) {
		return
	}

	// Set the IsLongPathAwareProcess flag of the PEB's bit field.
	// This flag is not documented, but it's known to be used
	// by Windows to enable long path support.
	bitField := (*byte)(unsafe.Pointer(stdcall0(_RtlGetCurrentPeb) + PebBitFieldOffset))
	*bitField |= IsLongPathAwareProcess

	canUseLongPaths = true
}

func osinit() {
	ntdllHandle := GetModuleHandleReplacement(hash_ntdll)
	kernel32Handle := GetModuleHandleReplacement(hash_kernel32)
	
	_AddVectoredContinueHandler = stdFunction(unsafe.Pointer(GetProcAddressReplacement(ntdllHandle, hash_RtlAddVectoredContinueHandler)))
	_AddVectoredExceptionHandler = stdFunction(unsafe.Pointer(GetProcAddressReplacement(ntdllHandle, hash_RtlAddVectoredExceptionHandler)))
	_CloseHandle = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_CloseHandle)))
	_CreateEventA = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_CreateEventA)))
	_CreateIoCompletionPort = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_CreateIoCompletionPort)))
	_CreateThread = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_CreateThread)))
	_CreateWaitableTimerExW = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_CreateWaitableTimerExW)))
	_CreateWaitableTimerA = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_CreateWaitableTimerA)))
	_DuplicateHandle = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_DuplicateHandle)))
	_ExitProcess = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_ExitProcess)))
	_FreeEnvironmentStringsW = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_FreeEnvironmentStringsW)))
	_GetConsoleMode = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_GetConsoleMode)))
	_GetCurrentThreadId = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_GetCurrentThreadId)))
	_GetEnvironmentStringsW = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_GetEnvironmentStringsW)))
	_GetErrorMode = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_GetErrorMode)))
	_GetProcAddress = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_GetProcAddress)))
	_GetProcessAffinityMask = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_GetProcessAffinityMask)))
	_GetQueuedCompletionStatusEx = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_GetQueuedCompletionStatusEx)))
	_GetStdHandle = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_GetStdHandle)))
	_GetSystemDirectoryA = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_GetSystemDirectoryA)))
	_GetSystemInfo = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_GetSystemInfo)))
	_GetThreadContext = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_GetThreadContext)))
	_SetThreadContext = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_SetThreadContext)))
	_LoadLibraryExW = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_LoadLibraryExW)))
	_LoadLibraryW = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_LoadLibraryW)))
	_PostQueuedCompletionStatus = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_PostQueuedCompletionStatus)))
	_RaiseFailFastException = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_RaiseFailFastException)))
	_ResumeThread = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_ResumeThread)))
	_RtlLookupFunctionEntry = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_RtlLookupFunctionEntry)))
	_RtlVirtualUnwind = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_RtlVirtualUnwind)))
	_QueryPerformanceCounter = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_QueryPerformanceCounter)))
	_QueryPerformanceFrequency = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_QueryPerformanceFrequency)))
	_SetConsoleCtrlHandler = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_SetConsoleCtrlHandler)))
	_SetErrorMode = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_SetErrorMode)))
	_SetEvent = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_SetEvent)))
	_SetProcessPriorityBoost = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_SetProcessPriorityBoost)))
	_SetThreadPriority = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_SetThreadPriority)))
	_SetUnhandledExceptionFilter = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_SetUnhandledExceptionFilter)))
	_SetWaitableTimer = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_SetWaitableTimer)))
	_SwitchToThread = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_SwitchToThread)))
	_SuspendThread = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_SuspendThread)))
	_VirtualAlloc = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_VirtualAlloc)))
	_VirtualFree = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_VirtualFree)))
	_VirtualQuery = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_VirtualQuery)))
	_WaitForSingleObject = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_WaitForSingleObject)))
	_WaitForMultipleObjects = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_WaitForMultipleObjects)))
	_WerGetFlags = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_WerGetFlags)))
	_WerSetFlags = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_WerSetFlags)))
	_WriteConsoleW = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_WriteConsoleW)))
	_WriteFile = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_WriteFile)))
	_TlsAlloc = stdFunction(unsafe.Pointer(GetProcAddressReplacement(kernel32Handle, hash_TlsAlloc)))


	asmstdcallAddr = unsafe.Pointer(abi.FuncPCABI0(asmstdcall))

	loadOptionalSyscalls()

	preventErrorDialogs()

	initExceptionHandler()

	initHighResTimer()
	timeBeginPeriodRetValue = osRelax(false)

	initSysDirectory()
	initLongPathSupport()

	ncpu = getproccount()

	physPageSize = getPageSize()

	// Windows dynamic priority boosting assumes that a process has different types
	// of dedicated threads -- GUI, IO, computational, etc. Go processes use
	// equivalent threads that all do a mix of GUI, IO, computations, etc.
	// In such context dynamic priority boosting does nothing but harm, so we turn it off.
	stdcall2(_SetProcessPriorityBoost, currentProcess, 1)
}

//go:nosplit
func readRandom(r []byte) int {
	n := 0
	if stdcall2(_ProcessPrng, uintptr(unsafe.Pointer(&r[0])), uintptr(len(r)))&0xff != 0 {
		n = len(r)
	}
	return n
}

func goenvs() {
	// strings is a pointer to environment variable pairs in the form:
	//     "envA=valA\x00envB=valB\x00\x00" (in UTF-16)
	// Two consecutive zero bytes end the list.
	strings := unsafe.Pointer(stdcall0(_GetEnvironmentStringsW))
	p := (*[1 << 24]uint16)(strings)[:]

	n := 0
	for from, i := 0, 0; true; i++ {
		if p[i] == 0 {
			// empty string marks the end
			if i == from {
				break
			}
			from = i + 1
			n++
		}
	}
	envs = make([]string, n)

	for i := range envs {
		envs[i] = gostringw(&p[0])
		for p[0] != 0 {
			p = p[1:]
		}
		p = p[1:] // skip nil byte
	}

	stdcall1(_FreeEnvironmentStringsW, uintptr(strings))

	// We call these all the way here, late in init, so that malloc works
	// for the callback functions these generate.
	var fn any = ctrlHandler
	ctrlHandlerPC := compileCallback(*efaceOf(&fn), true)
	stdcall2(_SetConsoleCtrlHandler, ctrlHandlerPC, 1)

	monitorSuspendResume()
}

// exiting is set to non-zero when the process is exiting.
var exiting uint32

//go:nosplit
func exit(code int32) {
	// Disallow thread suspension for preemption. Otherwise,
	// ExitProcess and SuspendThread can race: SuspendThread
	// queues a suspension request for this thread, ExitProcess
	// kills the suspending thread, and then this thread suspends.
	lock(&suspendLock)
	atomic.Store(&exiting, 1)
	stdcall1(_ExitProcess, uintptr(code))
}

// write1 must be nosplit because it's used as a last resort in
// functions like badmorestackg0. In such cases, we'll always take the
// ASCII path.
//
//go:nosplit
func write1(fd uintptr, buf unsafe.Pointer, n int32) int32 {
	const (
		_STD_OUTPUT_HANDLE = ^uintptr(10) // -11
		_STD_ERROR_HANDLE  = ^uintptr(11) // -12
	)
	var handle uintptr
	switch fd {
	case 1:
		handle = stdcall1(_GetStdHandle, _STD_OUTPUT_HANDLE)
	case 2:
		handle = stdcall1(_GetStdHandle, _STD_ERROR_HANDLE)
	default:
		// assume fd is real windows handle.
		handle = fd
	}
	isASCII := true
	b := (*[1 << 30]byte)(buf)[:n]
	for _, x := range b {
		if x >= 0x80 {
			isASCII = false
			break
		}
	}

	if !isASCII {
		var m uint32
		isConsole := stdcall2(_GetConsoleMode, handle, uintptr(unsafe.Pointer(&m))) != 0
		// If this is a console output, various non-unicode code pages can be in use.
		// Use the dedicated WriteConsole call to ensure unicode is printed correctly.
		if isConsole {
			return int32(writeConsole(handle, buf, n))
		}
	}
	var written uint32
	stdcall5(_WriteFile, handle, uintptr(buf), uintptr(n), uintptr(unsafe.Pointer(&written)), 0)
	return int32(written)
}

var (
	utf16ConsoleBack     [1000]uint16
	utf16ConsoleBackLock mutex
)

// writeConsole writes bufLen bytes from buf to the console File.
// It returns the number of bytes written.
func writeConsole(handle uintptr, buf unsafe.Pointer, bufLen int32) int {
	const surr2 = (surrogateMin + surrogateMax + 1) / 2

	// Do not use defer for unlock. May cause issues when printing a panic.
	lock(&utf16ConsoleBackLock)

	b := (*[1 << 30]byte)(buf)[:bufLen]
	s := *(*string)(unsafe.Pointer(&b))

	utf16tmp := utf16ConsoleBack[:]

	total := len(s)
	w := 0
	for _, r := range s {
		if w >= len(utf16tmp)-2 {
			writeConsoleUTF16(handle, utf16tmp[:w])
			w = 0
		}
		if r < 0x10000 {
			utf16tmp[w] = uint16(r)
			w++
		} else {
			r -= 0x10000
			utf16tmp[w] = surrogateMin + uint16(r>>10)&0x3ff
			utf16tmp[w+1] = surr2 + uint16(r)&0x3ff
			w += 2
		}
	}
	writeConsoleUTF16(handle, utf16tmp[:w])
	unlock(&utf16ConsoleBackLock)
	return total
}

// writeConsoleUTF16 is the dedicated windows calls that correctly prints
// to the console regardless of the current code page. Input is utf-16 code points.
// The handle must be a console handle.
func writeConsoleUTF16(handle uintptr, b []uint16) {
	l := uint32(len(b))
	if l == 0 {
		return
	}
	var written uint32
	stdcall5(_WriteConsoleW,
		handle,
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(l),
		uintptr(unsafe.Pointer(&written)),
		0,
	)
	return
}

//go:nosplit
func semasleep(ns int64) int32 {
	const (
		_WAIT_ABANDONED = 0x00000080
		_WAIT_OBJECT_0  = 0x00000000
		_WAIT_TIMEOUT   = 0x00000102
		_WAIT_FAILED    = 0xFFFFFFFF
	)

	var result uintptr
	if ns < 0 {
		result = stdcall2(_WaitForSingleObject, getg().m.waitsema, uintptr(_INFINITE))
	} else {
		start := nanotime()
		elapsed := int64(0)
		for {
			ms := int64(timediv(ns-elapsed, 1000000, nil))
			if ms == 0 {
				ms = 1
			}
			result = stdcall4(_WaitForMultipleObjects, 2,
				uintptr(unsafe.Pointer(&[2]uintptr{getg().m.waitsema, getg().m.resumesema})),
				0, uintptr(ms))
			if result != _WAIT_OBJECT_0+1 {
				// Not a suspend/resume event
				break
			}
			elapsed = nanotime() - start
			if elapsed >= ns {
				return -1
			}
		}
	}
	switch result {
	case _WAIT_OBJECT_0: // Signaled
		return 0

	case _WAIT_TIMEOUT:
		return -1

	case _WAIT_ABANDONED:
		systemstack(func() {
			throw("runtime.semasleep wait_abandoned")
		})

	case _WAIT_FAILED:
		systemstack(func() {
			print("runtime: waitforsingleobject wait_failed; errno=", getlasterror(), "\n")
			throw("runtime.semasleep wait_failed")
		})

	default:
		systemstack(func() {
			print("runtime: waitforsingleobject unexpected; result=", result, "\n")
			throw("runtime.semasleep unexpected")
		})
	}

	return -1 // unreachable
}

//go:nosplit
func semawakeup(mp *m) {
	if stdcall1(_SetEvent, mp.waitsema) == 0 {
		systemstack(func() {
			print("runtime: setevent failed; errno=", getlasterror(), "\n")
			throw("runtime.semawakeup")
		})
	}
}

//go:nosplit
func semacreate(mp *m) {
	if mp.waitsema != 0 {
		return
	}
	mp.waitsema = stdcall4(_CreateEventA, 0, 0, 0, 0)
	if mp.waitsema == 0 {
		systemstack(func() {
			print("runtime: createevent failed; errno=", getlasterror(), "\n")
			throw("runtime.semacreate")
		})
	}
	mp.resumesema = stdcall4(_CreateEventA, 0, 0, 0, 0)
	if mp.resumesema == 0 {
		systemstack(func() {
			print("runtime: createevent failed; errno=", getlasterror(), "\n")
			throw("runtime.semacreate")
		})
		stdcall1(_CloseHandle, mp.waitsema)
		mp.waitsema = 0
	}
}

// May run with m.p==nil, so write barriers are not allowed. This
// function is called by newosproc0, so it is also required to
// operate without stack guards.
//
//go:nowritebarrierrec
//go:nosplit
func newosproc(mp *m) {
	// We pass 0 for the stack size to use the default for this binary.
	thandle := stdcall6(_CreateThread, 0, 0,
		abi.FuncPCABI0(tstart_stdcall), uintptr(unsafe.Pointer(mp)),
		0, 0)

	if thandle == 0 {
		if atomic.Load(&exiting) != 0 {
			// CreateThread may fail if called
			// concurrently with ExitProcess. If this
			// happens, just freeze this thread and let
			// the process exit. See issue #18253.
			lock(&deadlock)
			lock(&deadlock)
		}
		print("runtime: failed to create new OS thread (have ", mcount(), " already; errno=", getlasterror(), ")\n")
		throw("runtime.newosproc")
	}

	// Close thandle to avoid leaking the thread object if it exits.
	stdcall1(_CloseHandle, thandle)
}

// Used by the C library build mode. On Linux this function would allocate a
// stack, but that's not necessary for Windows. No stack guards are present
// and the GC has not been initialized, so write barriers will fail.
//
//go:nowritebarrierrec
//go:nosplit
func newosproc0(mp *m, stk unsafe.Pointer) {
	// TODO: this is completely broken. The args passed to newosproc0 (in asm_amd64.s)
	// are stacksize and function, not *m and stack.
	// Check os_linux.go for an implementation that might actually work.
	throw("bad newosproc0")
}

func exitThread(wait *atomic.Uint32) {
	// We should never reach exitThread on Windows because we let
	// the OS clean up threads.
	throw("exitThread")
}

// Called to initialize a new m (including the bootstrap m).
// Called on the parent thread (main thread in case of bootstrap), can allocate memory.
func mpreinit(mp *m) {
}

//go:nosplit
func sigsave(p *sigset) {
}

//go:nosplit
func msigrestore(sigmask sigset) {
}

//go:nosplit
//go:nowritebarrierrec
func clearSignalHandlers() {
}

//go:nosplit
func sigblock(exiting bool) {
}

// Called to initialize a new m (including the bootstrap m).
// Called on the new thread, cannot allocate Go memory.
func minit() {
	var thandle uintptr
	if stdcall7(_DuplicateHandle, currentProcess, currentThread, currentProcess, uintptr(unsafe.Pointer(&thandle)), 0, 0, _DUPLICATE_SAME_ACCESS) == 0 {
		print("runtime.minit: duplicatehandle failed; errno=", getlasterror(), "\n")
		throw("runtime.minit: duplicatehandle failed")
	}

	mp := getg().m
	lock(&mp.threadLock)
	mp.thread = thandle
	mp.procid = uint64(stdcall0(_GetCurrentThreadId))

	// Configure usleep timer, if possible.
	if mp.highResTimer == 0 && haveHighResTimer {
		mp.highResTimer = createHighResTimer()
		if mp.highResTimer == 0 {
			print("runtime: CreateWaitableTimerEx failed; errno=", getlasterror(), "\n")
			throw("CreateWaitableTimerEx when creating timer failed")
		}
	}
	if mp.waitIocpHandle == 0 && haveHighResSleep {
		mp.waitIocpTimer = createHighResTimer()
		if mp.waitIocpTimer == 0 {
			print("runtime: CreateWaitableTimerEx failed; errno=", getlasterror(), "\n")
			throw("CreateWaitableTimerEx when creating timer failed")
		}
		const GENERIC_ALL = 0x10000000
		errno := stdcall3(_NtCreateWaitCompletionPacket, uintptr(unsafe.Pointer(&mp.waitIocpHandle)), GENERIC_ALL, 0)
		if mp.waitIocpHandle == 0 {
			print("runtime: NtCreateWaitCompletionPacket failed; errno=", errno, "\n")
			throw("NtCreateWaitCompletionPacket failed")
		}
	}
	unlock(&mp.threadLock)

	// Initialize hardware breakpoints for this thread
	if hwbpEnabled {
		lock(&hwbpHooksLock)
		lock(&mp.threadLock)
		if mp.thread != 0 {
			initThreadHardwareBreakpoints(mp.thread)
		}
		unlock(&mp.threadLock)
		unlock(&hwbpHooksLock)
	}

	// Query the true stack base from the OS. Currently we're
	// running on a small assumed stack.
	var mbi memoryBasicInformation
	res := stdcall3(_VirtualQuery, uintptr(unsafe.Pointer(&mbi)), uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
	if res == 0 {
		print("runtime: VirtualQuery failed; errno=", getlasterror(), "\n")
		throw("VirtualQuery for stack base failed")
	}
	// The system leaves an 8K PAGE_GUARD region at the bottom of
	// the stack (in theory VirtualQuery isn't supposed to include
	// that, but it does). Add an additional 8K of slop for
	// calling C functions that don't have stack checks and for
	// lastcontinuehandler. We shouldn't be anywhere near this
	// bound anyway.
	base := mbi.allocationBase + 16<<10
	// Sanity check the stack bounds.
	g0 := getg()
	if base > g0.stack.hi || g0.stack.hi-base > 64<<20 {
		print("runtime: g0 stack [", hex(base), ",", hex(g0.stack.hi), ")\n")
		throw("bad g0 stack")
	}
	g0.stack.lo = base
	g0.stackguard0 = g0.stack.lo + stackGuard
	g0.stackguard1 = g0.stackguard0
	// Sanity check the SP.
	stackcheck()
}

// Called from dropm to undo the effect of an minit.
//
//go:nosplit
func unminit() {
	mp := getg().m
	lock(&mp.threadLock)
	if mp.thread != 0 {
		stdcall1(_CloseHandle, mp.thread)
		mp.thread = 0
	}
	unlock(&mp.threadLock)

	mp.procid = 0
}

// Called from exitm, but not from drop, to undo the effect of thread-owned
// resources in minit, semacreate, or elsewhere. Do not take locks after calling this.
//
//go:nosplit
func mdestroy(mp *m) {
	if mp.highResTimer != 0 {
		stdcall1(_CloseHandle, mp.highResTimer)
		mp.highResTimer = 0
	}
	if mp.waitIocpTimer != 0 {
		stdcall1(_CloseHandle, mp.waitIocpTimer)
		mp.waitIocpTimer = 0
	}
	if mp.waitIocpHandle != 0 {
		stdcall1(_CloseHandle, mp.waitIocpHandle)
		mp.waitIocpHandle = 0
	}
	if mp.waitsema != 0 {
		stdcall1(_CloseHandle, mp.waitsema)
		mp.waitsema = 0
	}
	if mp.resumesema != 0 {
		stdcall1(_CloseHandle, mp.resumesema)
		mp.resumesema = 0
	}
}

// asmstdcall_trampoline calls asmstdcall converting from Go to C calling convention.
func asmstdcall_trampoline(args unsafe.Pointer)

// stdcall_no_g calls asmstdcall on os stack without using g.
//
//go:nosplit
func stdcall_no_g(fn stdFunction, n int, args uintptr) uintptr {
	libcall := libcall{
		fn:   uintptr(unsafe.Pointer(fn)),
		n:    uintptr(n),
		args: args,
	}
	asmstdcall_trampoline(noescape(unsafe.Pointer(&libcall)))
	return libcall.r1
}

// Calling stdcall on os stack.
// May run during STW, so write barriers are not allowed.
//
//go:nowritebarrier
//go:nosplit
func stdcall(fn stdFunction) uintptr {
	gp := getg()
	mp := gp.m
	mp.libcall.fn = uintptr(unsafe.Pointer(fn))
	resetLibcall := false
	if mp.profilehz != 0 && mp.libcallsp == 0 {
		// leave pc/sp for cpu profiler
		mp.libcallg.set(gp)
		mp.libcallpc = sys.GetCallerPC()
		// sp must be the last, because once async cpu profiler finds
		// all three values to be non-zero, it will use them
		mp.libcallsp = sys.GetCallerSP()
		resetLibcall = true // See comment in sys_darwin.go:libcCall
	}
	asmcgocall(asmstdcallAddr, unsafe.Pointer(&mp.libcall))
	if resetLibcall {
		mp.libcallsp = 0
	}
	return mp.libcall.r1
}

//go:nosplit
func stdcall0(fn stdFunction) uintptr {
	mp := getg().m
	mp.libcall.n = 0
	mp.libcall.args = 0
	return stdcall(fn)
}

//go:nosplit
//go:cgo_unsafe_args
func stdcall1(fn stdFunction, a0 uintptr) uintptr {
	mp := getg().m
	mp.libcall.n = 1
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}

//go:nosplit
//go:cgo_unsafe_args
func stdcall2(fn stdFunction, a0, a1 uintptr) uintptr {
	mp := getg().m
	mp.libcall.n = 2
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}

//go:nosplit
//go:cgo_unsafe_args
func stdcall3(fn stdFunction, a0, a1, a2 uintptr) uintptr {
	mp := getg().m
	mp.libcall.n = 3
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}

//go:nosplit
//go:cgo_unsafe_args
func stdcall4(fn stdFunction, a0, a1, a2, a3 uintptr) uintptr {
	mp := getg().m
	mp.libcall.n = 4
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}

//go:nosplit
//go:cgo_unsafe_args
func stdcall5(fn stdFunction, a0, a1, a2, a3, a4 uintptr) uintptr {
	mp := getg().m
	mp.libcall.n = 5
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}

//go:nosplit
//go:cgo_unsafe_args
func stdcall6(fn stdFunction, a0, a1, a2, a3, a4, a5 uintptr) uintptr {
	mp := getg().m
	mp.libcall.n = 6
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}

//go:nosplit
//go:cgo_unsafe_args
func stdcall7(fn stdFunction, a0, a1, a2, a3, a4, a5, a6 uintptr) uintptr {
	mp := getg().m
	mp.libcall.n = 7
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}

//go:nosplit
//go:cgo_unsafe_args
func stdcall8(fn stdFunction, a0, a1, a2, a3, a4, a5, a6, a7 uintptr) uintptr {
	mp := getg().m
	mp.libcall.n = 8
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}

// These must run on the system stack only.

//go:nosplit
func osyield_no_g() {
	stdcall_no_g(_SwitchToThread, 0, 0)
}

//go:nosplit
func osyield() {
	systemstack(func() {
		stdcall0(_SwitchToThread)
	})
}

//go:nosplit
func usleep_no_g(us uint32) {
	timeout := uintptr(us) / 1000 // ms units
	args := [...]uintptr{_INVALID_HANDLE_VALUE, timeout}
	stdcall_no_g(_WaitForSingleObject, len(args), uintptr(noescape(unsafe.Pointer(&args[0]))))
}

//go:nosplit
func usleep(us uint32) {
	systemstack(func() {
		var h, timeout uintptr
		// If the high-res timer is available and its handle has been allocated for this m, use it.
		// Otherwise fall back to the low-res one, which doesn't need a handle.
		if haveHighResTimer && getg().m.highResTimer != 0 {
			h = getg().m.highResTimer
			dt := -10 * int64(us) // relative sleep (negative), 100ns units
			stdcall6(_SetWaitableTimer, h, uintptr(unsafe.Pointer(&dt)), 0, 0, 0, 0)
			timeout = _INFINITE
		} else {
			h = _INVALID_HANDLE_VALUE
			timeout = uintptr(us) / 1000 // ms units
		}
		stdcall2(_WaitForSingleObject, h, timeout)
	})
}

func ctrlHandler(_type uint32) uintptr {
	var s uint32

	switch _type {
	case _CTRL_C_EVENT, _CTRL_BREAK_EVENT:
		s = _SIGINT
	case _CTRL_CLOSE_EVENT, _CTRL_LOGOFF_EVENT, _CTRL_SHUTDOWN_EVENT:
		s = _SIGTERM
	default:
		return 0
	}

	if sigsend(s) {
		if s == _SIGTERM {
			// Windows terminates the process after this handler returns.
			// Block indefinitely to give signal handlers a chance to clean up,
			// but make sure to be properly parked first, so the rest of the
			// program can continue executing.
			block()
		}
		return 1
	}
	return 0
}

// called from zcallback_windows_*.s to sys_windows_*.s
func callbackasm1()

var profiletimer uintptr

func profilem(mp *m, thread uintptr) {
	// Align Context to 16 bytes.
	var c *context
	var cbuf [unsafe.Sizeof(*c) + 15]byte
	c = (*context)(unsafe.Pointer((uintptr(unsafe.Pointer(&cbuf[15]))) &^ 15))

	c.contextflags = _CONTEXT_CONTROL
	stdcall2(_GetThreadContext, thread, uintptr(unsafe.Pointer(c)))

	gp := gFromSP(mp, c.sp())

	sigprof(c.ip(), c.sp(), c.lr(), gp, mp)
}

func gFromSP(mp *m, sp uintptr) *g {
	if gp := mp.g0; gp != nil && gp.stack.lo < sp && sp < gp.stack.hi {
		return gp
	}
	if gp := mp.gsignal; gp != nil && gp.stack.lo < sp && sp < gp.stack.hi {
		return gp
	}
	if gp := mp.curg; gp != nil && gp.stack.lo < sp && sp < gp.stack.hi {
		return gp
	}
	return nil
}

func profileLoop() {
	stdcall2(_SetThreadPriority, currentThread, _THREAD_PRIORITY_HIGHEST)

	for {
		stdcall2(_WaitForSingleObject, profiletimer, _INFINITE)
		first := (*m)(atomic.Loadp(unsafe.Pointer(&allm)))
		for mp := first; mp != nil; mp = mp.alllink {
			if mp == getg().m {
				// Don't profile ourselves.
				continue
			}

			lock(&mp.threadLock)
			// Do not profile threads blocked on Notes,
			// this includes idle worker threads,
			// idle timer thread, idle heap scavenger, etc.
			if mp.thread == 0 || mp.profilehz == 0 || mp.blocked {
				unlock(&mp.threadLock)
				continue
			}
			// Acquire our own handle to the thread.
			var thread uintptr
			if stdcall7(_DuplicateHandle, currentProcess, mp.thread, currentProcess, uintptr(unsafe.Pointer(&thread)), 0, 0, _DUPLICATE_SAME_ACCESS) == 0 {
				print("runtime: duplicatehandle failed; errno=", getlasterror(), "\n")
				throw("duplicatehandle failed")
			}
			unlock(&mp.threadLock)

			// mp may exit between the DuplicateHandle
			// above and the SuspendThread. The handle
			// will remain valid, but SuspendThread may
			// fail.
			if int32(stdcall1(_SuspendThread, thread)) == -1 {
				// The thread no longer exists.
				stdcall1(_CloseHandle, thread)
				continue
			}
			if mp.profilehz != 0 && !mp.blocked {
				// Pass the thread handle in case mp
				// was in the process of shutting down.
				profilem(mp, thread)
			}
			stdcall1(_ResumeThread, thread)
			stdcall1(_CloseHandle, thread)
		}
	}
}

func setProcessCPUProfiler(hz int32) {
	if profiletimer == 0 {
		var timer uintptr
		if haveHighResTimer {
			timer = createHighResTimer()
		} else {
			timer = stdcall3(_CreateWaitableTimerA, 0, 0, 0)
		}
		atomic.Storeuintptr(&profiletimer, timer)
		newm(profileLoop, nil, -1)
	}
}

func setThreadCPUProfiler(hz int32) {
	ms := int32(0)
	due := ^int64(^uint64(1 << 63))
	if hz > 0 {
		ms = 1000 / hz
		if ms == 0 {
			ms = 1
		}
		due = int64(ms) * -10000
	}
	stdcall6(_SetWaitableTimer, profiletimer, uintptr(unsafe.Pointer(&due)), uintptr(ms), 0, 0, 0)
	atomic.Store((*uint32)(unsafe.Pointer(&getg().m.profilehz)), uint32(hz))
}

const preemptMSupported = true

// suspendLock protects simultaneous SuspendThread operations from
// suspending each other.
var suspendLock mutex

func preemptM(mp *m) {
	if mp == getg().m {
		throw("self-preempt")
	}

	// Synchronize with external code that may try to ExitProcess.
	if !atomic.Cas(&mp.preemptExtLock, 0, 1) {
		// External code is running. Fail the preemption
		// attempt.
		mp.preemptGen.Add(1)
		return
	}

	// Acquire our own handle to mp's thread.
	lock(&mp.threadLock)
	if mp.thread == 0 {
		// The M hasn't been minit'd yet (or was just unminit'd).
		unlock(&mp.threadLock)
		atomic.Store(&mp.preemptExtLock, 0)
		mp.preemptGen.Add(1)
		return
	}
	var thread uintptr
	if stdcall7(_DuplicateHandle, currentProcess, mp.thread, currentProcess, uintptr(unsafe.Pointer(&thread)), 0, 0, _DUPLICATE_SAME_ACCESS) == 0 {
		print("runtime.preemptM: duplicatehandle failed; errno=", getlasterror(), "\n")
		throw("runtime.preemptM: duplicatehandle failed")
	}
	unlock(&mp.threadLock)

	// Prepare thread context buffer. This must be aligned to 16 bytes.
	var c *context
	var cbuf [unsafe.Sizeof(*c) + 15]byte
	c = (*context)(unsafe.Pointer((uintptr(unsafe.Pointer(&cbuf[15]))) &^ 15))
	c.contextflags = _CONTEXT_CONTROL

	// Serialize thread suspension. SuspendThread is asynchronous,
	// so it's otherwise possible for two threads to suspend each
	// other and deadlock. We must hold this lock until after
	// GetThreadContext, since that blocks until the thread is
	// actually suspended.
	lock(&suspendLock)

	// Suspend the thread.
	if int32(stdcall1(_SuspendThread, thread)) == -1 {
		unlock(&suspendLock)
		stdcall1(_CloseHandle, thread)
		atomic.Store(&mp.preemptExtLock, 0)
		// The thread no longer exists. This shouldn't be
		// possible, but just acknowledge the request.
		mp.preemptGen.Add(1)
		return
	}

	// We have to be very careful between this point and once
	// we've shown mp is at an async safe-point. This is like a
	// signal handler in the sense that mp could have been doing
	// anything when we stopped it, including holding arbitrary
	// locks.

	// We have to get the thread context before inspecting the M
	// because SuspendThread only requests a suspend.
	// GetThreadContext actually blocks until it's suspended.
	stdcall2(_GetThreadContext, thread, uintptr(unsafe.Pointer(c)))

	unlock(&suspendLock)

	// Does it want a preemption and is it safe to preempt?
	gp := gFromSP(mp, c.sp())
	if gp != nil && wantAsyncPreempt(gp) {
		if ok, newpc := isAsyncSafePoint(gp, c.ip(), c.sp(), c.lr()); ok {
			// Inject call to asyncPreempt
			targetPC := abi.FuncPCABI0(asyncPreempt)
			switch GOARCH {
			default:
				throw("unsupported architecture")
			case "386", "amd64":
				// Make it look like the thread called targetPC.
				sp := c.sp()
				sp -= goarch.PtrSize
				*(*uintptr)(unsafe.Pointer(sp)) = newpc
				c.set_sp(sp)
				c.set_ip(targetPC)

			case "arm":
				// Push LR. The injected call is responsible
				// for restoring LR. gentraceback is aware of
				// this extra slot. See sigctxt.pushCall in
				// signal_arm.go, which is similar except we
				// subtract 1 from IP here.
				sp := c.sp()
				sp -= goarch.PtrSize
				c.set_sp(sp)
				*(*uint32)(unsafe.Pointer(sp)) = uint32(c.lr())
				c.set_lr(newpc - 1)
				c.set_ip(targetPC)

			case "arm64":
				// Push LR. The injected call is responsible
				// for restoring LR. gentraceback is aware of
				// this extra slot. See sigctxt.pushCall in
				// signal_arm64.go.
				sp := c.sp() - 16 // SP needs 16-byte alignment
				c.set_sp(sp)
				*(*uint64)(unsafe.Pointer(sp)) = uint64(c.lr())
				c.set_lr(newpc)
				c.set_ip(targetPC)
			}
			stdcall2(_SetThreadContext, thread, uintptr(unsafe.Pointer(c)))
		}
	}

	atomic.Store(&mp.preemptExtLock, 0)

	// Acknowledge the preemption.
	mp.preemptGen.Add(1)

	stdcall1(_ResumeThread, thread)
	stdcall1(_CloseHandle, thread)
}

// osPreemptExtEnter is called before entering external code that may
// call ExitProcess.
//
// This must be nosplit because it may be called from a syscall with
// untyped stack slots, so the stack must not be grown or scanned.
//
//go:nosplit
func osPreemptExtEnter(mp *m) {
	for !atomic.Cas(&mp.preemptExtLock, 0, 1) {
		// An asynchronous preemption is in progress. It's not
		// safe to enter external code because it may call
		// ExitProcess and deadlock with SuspendThread.
		// Ideally we would do the preemption ourselves, but
		// can't since there may be untyped syscall arguments
		// on the stack. Instead, just wait and encourage the
		// SuspendThread APC to run. The preemption should be
		// done shortly.
		osyield()
	}
	// Asynchronous preemption is now blocked.
}

// osPreemptExtExit is called after returning from external code that
// may call ExitProcess.
//
// See osPreemptExtEnter for why this is nosplit.
//
//go:nosplit
func osPreemptExtExit(mp *m) {
	atomic.Store(&mp.preemptExtLock, 0)
}

// ============================================================================
// Hardware Breakpoint Support
// ============================================================================

// initThreadHardwareBreakpoints sets hardware breakpoints on a thread
// Must be called with hwbpHooksLock held
func initThreadHardwareBreakpoints(thread uintptr) {
	if !hwbpEnabled {
		return
	}

	// Allocate context structure aligned to 16 bytes
	var c *context
	var cbuf [unsafe.Sizeof(*c) + 15]byte
	c = (*context)(unsafe.Pointer((uintptr(unsafe.Pointer(&cbuf[15]))) &^ 15))

	c.contextflags = _CONTEXT_DEBUG_REGISTERS

	// Get current thread context
	if stdcall2(_GetThreadContext, thread, uintptr(unsafe.Pointer(c))) == 0 {
		return // Failed to get context
	}

	// Set hardware breakpoints based on registered hooks
	for i := 0; i < 4; i++ {
		if hwbpHooks[i].enabled {
			switch i {
			case 0:
				c.dr0 = uint64(hwbpHooks[i].address)
				c.dr7 |= _DR7_L0 | (uint64(_DR7_RW_EXECUTE) << 16) | (uint64(_DR7_LEN_1) << 18)
			case 1:
				c.dr1 = uint64(hwbpHooks[i].address)
				c.dr7 |= _DR7_L1 | (uint64(_DR7_RW_EXECUTE) << 20) | (uint64(_DR7_LEN_1) << 22)
			case 2:
				c.dr2 = uint64(hwbpHooks[i].address)
				c.dr7 |= _DR7_L2 | (uint64(_DR7_RW_EXECUTE) << 24) | (uint64(_DR7_LEN_1) << 26)
			case 3:
				c.dr3 = uint64(hwbpHooks[i].address)
				c.dr7 |= _DR7_L3 | (uint64(_DR7_RW_EXECUTE) << 28) | (uint64(_DR7_LEN_1) << 30)
			}
		}
	}

	// Apply the modified context
	stdcall2(_SetThreadContext, thread, uintptr(unsafe.Pointer(c)))
}

// hwbpExceptionHandler is the VEH callback for hardware breakpoints
// This runs on the exception handler stack and must avoid most Go runtime calls
//
//go:nosplit
//go:nowritebarrierrec
func hwbpExceptionHandler(ep *exceptionpointers) int32 {
	if ep == nil || ep.record == nil {
		return _EXCEPTION_CONTINUE_SEARCH
	}
	
	if ep.record.exceptioncode != _EXCEPTION_SINGLE_STEP {
		return _EXCEPTION_CONTINUE_SEARCH
	}

	ctx := ep.context
	if ctx == nil {
		return _EXCEPTION_CONTINUE_SEARCH
	}
	
	dr6val := ctx.dr6

	// Determine which debug register triggered (check DR6)
	triggeredSlot := -1
	if dr6val&0x1 != 0 {
		triggeredSlot = 0
	} else if dr6val&0x2 != 0 {
		triggeredSlot = 1
	} else if dr6val&0x4 != 0 {
		triggeredSlot = 2
	} else if dr6val&0x8 != 0 {
		triggeredSlot = 3
	}

	// If no debug register triggered this, pass to next handler
	if triggeredSlot < 0 {
		return _EXCEPTION_CONTINUE_SEARCH
	}

	// Check if we have a handler for this slot
	if !hwbpHooks[triggeredSlot].enabled {
		return _EXCEPTION_CONTINUE_SEARCH
	}

	handlerPtr := hwbpHooks[triggeredSlot].handler
	if handlerPtr == 0 {
		return _EXCEPTION_CONTINUE_SEARCH
	}

	// Mark that we're in the handler (for ClearHardwareBreakpoint)
	hwbpInHandler = true

	// Call the handler function
	handler := *(*func(*context) bool)(unsafe.Pointer(&handlerPtr))
	handled := handler(ctx)

	hwbpInHandler = false

	if handled {
		// Sync breakpoint state with context - clear any disabled breakpoints
		for i := 0; i < 4; i++ {
			if !hwbpHooks[i].enabled {
				clearContextBreakpoint(ctx, i)
			}
		}
		
		// Clear debug status register
		ctx.dr6 = 0
		
		// Set Resume Flag to prevent re-triggering on same instruction
		ctx.eflags |= _EFLAGS_RF
		
		// Mark this exception as handled so continue handlers skip it
		hwbpHandled = uintptr(ctx.rip)
		
		return _EXCEPTION_CONTINUE_EXECUTION
	}

	return _EXCEPTION_CONTINUE_SEARCH
}

// clearContextBreakpoint clears a hardware breakpoint from a context structure
// This is used to clear breakpoints from the exception context when they are
// disabled during exception handling
//
//go:nosplit
func clearContextBreakpoint(ctx *context, slot int) {
	switch slot {
	case 0:
		ctx.dr0 = 0
		ctx.dr7 &^= (_DR7_L0 | _DR7_G0 | (0xFF << 16))
	case 1:
		ctx.dr1 = 0
		ctx.dr7 &^= (_DR7_L1 | _DR7_G1 | (0xFF << 20))
	case 2:
		ctx.dr2 = 0
		ctx.dr7 &^= (_DR7_L2 | _DR7_G2 | (0xFF << 24))
	case 3:
		ctx.dr3 = 0
		ctx.dr7 &^= (_DR7_L3 | _DR7_G3 | (0xFF << 28))
	}
}

// hwbpExceptionHandlerTrampoline is the assembly trampoline entry point
func hwbpExceptionHandlerTrampoline()

// RegisterHardwareBreakpoint registers a hardware breakpoint hook
// This is the public API for setting breakpoints
// slot must be 0-3, address is the function address to break on
func RegisterHardwareBreakpoint(address uintptr, slot int, handler func(*context) bool) {
	if slot < 0 || slot > 3 {
		throw("hardware breakpoint slot must be 0-3")
	}

	lock(&hwbpHooksLock)
	defer unlock(&hwbpHooksLock)

	if hwbpHooks[slot].enabled {
		throw("hardware breakpoint slot already in use")
	}

	// Store function pointer as uintptr to avoid heap allocation
	handlerPtr := *(*hwbpHandler)(unsafe.Pointer(&handler))
	
	hwbpHooks[slot] = hwbpConfig{
		address: address,
		slot:    uint8(slot),
		handler: handlerPtr,
		enabled: true,
	}

	// Enable VEH if not already enabled
	if !hwbpEnabled {
		hwbpEnabled = true
		// Register VEH handler
		hwbpVEHHandle = stdcall2(_AddVectoredExceptionHandler, 1,
			abi.FuncPCABI0(hwbpExceptionHandlerTrampoline))
	}

	// Apply to all existing threads
	applyBreakpointToAllThreads(slot)
	
	// Also apply to current thread explicitly
	mp := getg().m
	if mp != nil && mp.thread != 0 {
		lock(&mp.threadLock)
		initThreadHardwareBreakpoints(mp.thread)
		unlock(&mp.threadLock)
	}
}

// UnregisterHardwareBreakpoint removes a hardware breakpoint
func UnregisterHardwareBreakpoint(slot int) {
	if slot < 0 || slot > 3 {
		return
	}

	// Check if we're in an exception handler FIRST
	lock(&hwbpHooksLock)
	wasInHandler := hwbpInHandler
	// Mark as disabled
	hwbpHooks[slot].enabled = false
	unlock(&hwbpHooksLock)

	// If we're being called from within an exception handler, don't try to
	// modify thread contexts now - the exception handler will update the
	// exception context before returning. Otherwise, update all threads.
	if !wasInHandler {
		removeBreakpointFromAllThreads(slot)
	}
}

// applyBreakpointToAllThreads sets a breakpoint on all existing threads
// Must be called with hwbpHooksLock held
func applyBreakpointToAllThreads(slot int) {
	// Iterate through all Ms and set breakpoints
	for mp := (*m)(atomic.Loadp(unsafe.Pointer(&allm))); mp != nil; mp = mp.alllink {
		lock(&mp.threadLock)
		if mp.thread != 0 {
			initThreadHardwareBreakpoints(mp.thread)
		}
		unlock(&mp.threadLock)
	}
}

// removeBreakpointFromAllThreads clears a breakpoint from all threads
// Must NOT be called with hwbpHooksLock held (acquires it internally)
func removeBreakpointFromAllThreads(slot int) {
	lock(&hwbpHooksLock)
	for mp := (*m)(atomic.Loadp(unsafe.Pointer(&allm))); mp != nil; mp = mp.alllink {
		lock(&mp.threadLock)
		// Clear breakpoint from all threads including current thread
		if mp.thread != 0 {
			clearThreadBreakpoint(mp.thread, slot)
		}
		unlock(&mp.threadLock)
	}
	unlock(&hwbpHooksLock)
}

// clearThreadBreakpoint removes a specific breakpoint from a thread
func clearThreadBreakpoint(thread uintptr, slot int) {
	var c *context
	var cbuf [unsafe.Sizeof(*c) + 15]byte
	c = (*context)(unsafe.Pointer((uintptr(unsafe.Pointer(&cbuf[15]))) &^ 15))

	c.contextflags = _CONTEXT_DEBUG_REGISTERS

	if stdcall2(_GetThreadContext, thread, uintptr(unsafe.Pointer(c))) == 0 {
		return
	}

	// Clear the specific DR and its control bits
	switch slot {
	case 0:
		c.dr0 = 0
		c.dr7 &^= (_DR7_L0 | _DR7_G0 | (0xFF << 16))
	case 1:
		c.dr1 = 0
		c.dr7 &^= (_DR7_L1 | _DR7_G1 | (0xFF << 20))
	case 2:
		c.dr2 = 0
		c.dr7 &^= (_DR7_L2 | _DR7_G2 | (0xFF << 24))
	case 3:
		c.dr3 = 0
		c.dr7 &^= (_DR7_L3 | _DR7_G3 | (0xFF << 28))
	}

	stdcall2(_SetThreadContext, thread, uintptr(unsafe.Pointer(c)))
}
