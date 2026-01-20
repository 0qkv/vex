# vex

Single header framework that crashes decompilers using kernel mode stack offsets and fake instructions.

---

## Usage

```cpp
#include "vex.h"

void protected_function() {
    VEX;
    // your code
}

const char* key = VEX_STR("encrypted");
int value = VEX_VAL(12345);
```

---

## Example

```cpp
#include <windows.h>
#include "vex.h"

NTSTATUS communicate_driver(PVOID buffer, SIZE_T size) {
    VEX;
    
    HANDLE device = CreateFileA(
        VEX_STR("\\\\.\\Device"),
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL
    );
    
    if (device == INVALID_HANDLE_VALUE) {
        return VEX_VAL(0xC0000001);
    }
    
    DWORD bytes;
    DeviceIoControl(device, VEX_VAL(0x222004), 
                    buffer, size, buffer, size, &bytes, NULL);
    
    CloseHandle(device);
    return VEX_VAL(0);
}
```

---

## How It Works

**Stack Overflow**

Uses kernel mode stack offsets (0xFFFFFF00+) that overflow decompiler stack analysis. Stack trackers use signed integers for offset arithmetic. Kernel range offsets overflow these integers causing analysis failure.

```asm
mov [rsp+0xFFFFFF00], rcx
lea rax, [rsp+0xFFFFFE00]
```

**Control Flow Destruction**

Indirect jumps with XOR obfuscation destroy CFG reconstruction. The double XOR cancels mathematically but symbolic execution treats each operation as introducing taint, making jump targets unknown.

```asm
lea rax, [rip+8]
xor rax, 0xFFFFFF00
xor rax, 0xFFFFFF00
push rax
ret
```

**Fake Instructions**

Raw byte emissions decode as valid instructions that are never executed. Linear sweep disassemblers create fake functions and cross references, causing infinite analysis loops.

```asm
jmp real_code
_emit 0xE8
_emit 0xDE
_emit 0xAD
_emit 0xBE
_emit 0xEF
real_code:
```

**Opaque Predicates**

Mathematical invariants that always evaluate the same way but appear dynamic to symbolic execution. Creates unreachable blocks that poison dead code elimination.

```asm
mov rax, <value>
imul rax, [rax+1]
and rax, 1
jz always_taken
```

All protection is skipped at runtime via direct jumps. Zero overhead.

---

## Compilation

```batch
cl /O2 /std:c++14 program.cpp
```

---

## Requirements

Windows x64  
MSVC  
C++14

---

## License

MIT
