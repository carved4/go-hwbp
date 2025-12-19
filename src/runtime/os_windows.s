//go:build amd64
// +build amd64

#include "textflag.h"

// func GetPEB() uintptr
TEXT ·GetPEB(SB),NOSPLIT|NOFRAME,$0-8
    PUSHQ   CX
    MOVQ    0x60(GS), CX   // Read the value at offset 0x60 from the GS segment into CX
    MOVQ    CX, ret+0(FP)  // Store the value in the return slot (CX -> return)
    POPQ   CX
    RET

// func fnv1aHash(str *byte) uint32
// FNV-1a hash function for null-terminated strings
// No allocations, case-insensitive for ASCII
TEXT ·fnv1aHash(SB),NOSPLIT|NOFRAME,$0-12
    MOVQ    str+0(FP), SI       // SI = pointer to string
    TESTQ   SI, SI              // Check if pointer is nil
    JZ      return_zero
    
    MOVL    $0x811c9dc5, AX     // AX = FNV offset basis (2166136261)
    MOVL    $0x01000193, CX     // CX = FNV prime (16777619)
    
hash_loop:
    MOVBQZX (SI), DX            // DX = *str (load byte, zero extend)
    TESTB   DL, DL              // Check if byte is 0 (null terminator)
    JZ      hash_done
    
    // Convert to lowercase if uppercase ASCII (A-Z -> a-z)
    CMPB    DL, $'A'
    JL      not_upper
    CMPB    DL, $'Z'
    JG      not_upper
    ADDB    $32, DL             // Convert to lowercase
    
not_upper:
    XORB    DL, AL              // hash ^= byte
    IMULL   CX, AX              // hash *= FNV_prime
    
    INCQ    SI                  // str++
    JMP     hash_loop
    
hash_done:
    MOVL    AX, ret+8(FP)       // Store result
    RET
    
return_zero:
    MOVL    $0, ret+8(FP)
    RET

// func fnv1aHashUnicode(buffer *uint16, length uint16) uint32
// FNV-1a hash for Unicode strings (UNICODE_STRING)
// No allocations, case-insensitive
TEXT ·fnv1aHashUnicode(SB),NOSPLIT|NOFRAME,$0-20
    MOVQ    buffer+0(FP), SI    // SI = pointer to uint16 buffer
    MOVWQZX length+8(FP), BX    // BX = length in bytes
    TESTQ   SI, SI              // Check if pointer is nil
    JZ      return_zero_uni
    
    SHRQ    $1, BX              // Convert byte length to character count
    TESTQ   BX, BX              // Check if length is 0
    JZ      return_zero_uni
    
    MOVL    $0x811c9dc5, AX     // AX = FNV offset basis
    MOVL    $0x01000193, CX     // CX = FNV prime
    XORQ    DI, DI              // DI = counter
    
hash_loop_uni:
    CMPQ    DI, BX              // if counter >= numChars
    JGE     hash_done_uni
    
    MOVWQZX (SI)(DI*2), DX      // DX = buffer[i] (uint16)
    
    // Convert to lowercase if uppercase ASCII (A-Z -> a-z)
    CMPW    DX, $'A'
    JL      not_upper_uni
    CMPW    DX, $'Z'
    JG      not_upper_uni
    ADDW    $32, DX             // Convert to lowercase
    
not_upper_uni:
    XORW    DX, AX              // hash ^= char (only low 16 bits matter)
    IMULL   CX, AX              // hash *= FNV_prime
    
    INCQ    DI                  // counter++
    JMP     hash_loop_uni
    
hash_done_uni:
    MOVL    AX, ret+16(FP)      // Store result
    RET
    
return_zero_uni:
    MOVL    $0, ret+16(FP)
    RET
