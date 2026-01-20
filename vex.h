#ifndef VEX_H
#define VEX_H

#include <cstdint>
#include <type_traits>

namespace vex {
    constexpr uint64_t hc(uint64_t s, uint64_t v) {
        return s ^ (v + 0x9e3779b97f4a7c15ULL + (s << 6) + (s >> 2));
    }

    constexpr uint64_t hs(const char* str, uint64_t s = 0xcbf29ce484222325ULL) {
        return *str ? hs(str + 1, hc(s, *str)) : s;
    }

    #define VX_R(id) ((uint32_t)(vex::hs(__FILE__ __DATE__ __TIME__ #id) & 0xFFFFFFFF))

    template<typename T, size_t N>
    struct enc {
        T d[N];
        constexpr enc(const T(&a)[N], uint32_t k) : d{} {
            for (size_t i = 0; i < N; i++) {
                d[i] = a[i] ^ ((k >> ((i % 4) * 8)) & 0xFF);
            }
        }
        void dec(T* o, uint32_t k) const {
            for (size_t i = 0; i < N; i++) {
                o[i] = d[i] ^ ((k >> ((i % 4) * 8)) & 0xFF);
            }
        }
    };

    template<size_t N>
    class str {
        enc<char, N> e;
        uint32_t k;
        mutable char b[N];
    public:
        constexpr str(const char(&s)[N], uint32_t kk) : e(s, kk), k(kk), b{} {}
        operator const char*() const {
            e.dec(b, k);
            return b;
        }
    };

    template<typename T>
    struct val {
        T ev;
        uint32_t k;
        constexpr val(T v, uint32_t kk) : ev(v ^ kk), k(kk) {}
        operator T() const { return ev ^ k; }
    };
}

#define VEX_STR(s) ((const char*)vex::str<sizeof(s)>(s, VX_R(__COUNTER__)))
#define VEX_VAL(v) ((decltype(v))vex::val<decltype(v)>(v, VX_R(__COUNTER__)))

#if defined(_MSC_VER) && defined(_M_X64)

#define S1 (VX_R(1)|0xFFFFFF00)
#define S2 (VX_R(2)|0xFFFFFE00)
#define S3 (VX_R(3)|0xFFFFFD00)
#define S4 (VX_R(4)|0xFFFFFC00)
#define S5 (VX_R(5)|0xFFFFFB00)
#define S6 (VX_R(6)|0xFFFFFA00)
#define S7 (VX_R(7)|0xFFFFF900)
#define S8 (VX_R(8)|0xFFFFF800)
#define S9 (VX_R(9)|0xFFFFF700)
#define S10 (VX_R(10)|0xFFFFF600)
#define S11 (VX_R(11)|0xFFFFF500)
#define S12 (VX_R(12)|0xFFFFF400)
#define S13 (VX_R(13)|0xFFFFF300)
#define S14 (VX_R(14)|0xFFFFF200)
#define S15 (VX_R(15)|0xFFFFF100)
#define S16 (VX_R(16)|0xFFFFF000)
#define S17 (VX_R(17)|0xFFFFEF00)
#define S18 (VX_R(18)|0xFFFFEE00)
#define S19 (VX_R(19)|0xFFFFED00)
#define S20 (VX_R(20)|0xFFFFEC00)

#define VEX \
    __asm { jmp L0 } \
    __asm { mov qword ptr [rsp+S1], rcx } \
    __asm { mov qword ptr [rsp+S2], rdx } \
    __asm { mov qword ptr [rsp+S3], r8 } \
    __asm { mov qword ptr [rsp+S4], r9 } \
    __asm { mov qword ptr [rsp+S5], r10 } \
    __asm { mov qword ptr [rsp+S6], r11 } \
    __asm { mov qword ptr [rsp+S7], r12 } \
    __asm { mov qword ptr [rsp+S8], r13 } \
    __asm { mov qword ptr [rsp+S9], r14 } \
    __asm { mov qword ptr [rsp+S10], r15 } \
    __asm { lea rax, [rsp+S11] } \
    __asm { mov qword ptr [rax], rsi } \
    __asm { lea rbx, [rsp+S12] } \
    __asm { mov qword ptr [rbx], rdi } \
    __asm { lea rcx, [rsp+S13] } \
    __asm { mov qword ptr [rcx], rbx } \
    __asm { lea rdx, [rsp+S14] } \
    __asm { mov qword ptr [rdx], rbp } \
    __asm { lea r8, [rsp+S15] } \
    __asm { mov qword ptr [r8], rax } \
    __asm { lea r9, [rsp+S16] } \
    __asm { mov qword ptr [r9], rcx } \
    __asm { lea r10, [rsp+S17] } \
    __asm { mov qword ptr [r10], rdx } \
    __asm { lea r11, [rsp+S18] } \
    __asm { mov qword ptr [r11], r8 } \
    __asm { lea r12, [rsp+S19] } \
    __asm { mov qword ptr [r12], r9 } \
    __asm { lea r13, [rsp+S20] } \
    __asm { mov qword ptr [r13], r10 } \
    __asm { L0: } \
    __asm { jmp L1 } \
    __asm { _emit 0xE8 } \
    __asm { _emit 0xDE } \
    __asm { _emit 0xAD } \
    __asm { _emit 0xBE } \
    __asm { _emit 0xEF } \
    __asm { _emit 0xE9 } \
    __asm { _emit 0xCA } \
    __asm { _emit 0xFE } \
    __asm { _emit 0xBA } \
    __asm { _emit 0xBE } \
    __asm { L1: } \
    __asm { lea rax, [rip+8] } \
    __asm { xor rax, S1 } \
    __asm { xor rax, S1 } \
    __asm { push rax } \
    __asm { ret } \
    __asm { jmp L2 } \
    __asm { _emit 0x0F } \
    __asm { _emit 0x84 } \
    __asm { _emit 0xFF } \
    __asm { _emit 0xFF } \
    __asm { _emit 0xFF } \
    __asm { _emit 0xFF } \
    __asm { L2: } \
    __asm { rdtsc } \
    __asm { mov rbx, rax } \
    __asm { shl rbx, 32 } \
    __asm { or rbx, rax } \
    __asm { and rbx, 1 } \
    __asm { test rbx, rbx } \
    __asm { jmp L3 } \
    __asm { int 3 } \
    __asm { int 3 } \
    __asm { int 3 } \
    __asm { L3: } \
    __asm { jmp L4 } \
    __asm { _emit 0x48 } \
    __asm { _emit 0xB8 } \
    __asm { _emit 0xEF } \
    __asm { _emit 0xBE } \
    __asm { _emit 0xAD } \
    __asm { _emit 0xDE } \
    __asm { _emit 0x00 } \
    __asm { _emit 0x00 } \
    __asm { _emit 0x00 } \
    __asm { _emit 0x00 } \
    __asm { L4: } \
    __asm { push rax } \
    __asm { push rbx } \
    __asm { push rcx } \
    __asm { push rdx } \
    __asm { xchg rax, rbx } \
    __asm { xchg rcx, rdx } \
    __asm { xchg qword ptr [rsp], rax } \
    __asm { xchg qword ptr [rsp+8], rbx } \
    __asm { xchg qword ptr [rsp+16], rcx } \
    __asm { xchg qword ptr [rsp+24], rdx } \
    __asm { pop rdx } \
    __asm { pop rcx } \
    __asm { pop rbx } \
    __asm { pop rax } \
    __asm { jmp L5 } \
    __asm { _emit 0xFF } \
    __asm { _emit 0x25 } \
    __asm { _emit 0x00 } \
    __asm { _emit 0x00 } \
    __asm { _emit 0x00 } \
    __asm { _emit 0x00 } \
    __asm { L5: } \
    __asm { mov rax, S2 } \
    __asm { mov rbx, rax } \
    __asm { add rbx, 1 } \
    __asm { imul rax, rbx } \
    __asm { and rax, 1 } \
    __asm { test rax, rax } \
    __asm { jz L6 } \
    __asm { int 3 } \
    __asm { L6: } \
    __asm { jmp L7 } \
    __asm { push offset LH } \
    __asm { push qword ptr fs:[0] } \
    __asm { mov qword ptr fs:[0], rsp } \
    __asm { LH: } \
    __asm { xor rax, rax } \
    __asm { L7: } \
    __asm { rdtsc } \
    __asm { mov rbx, rax } \
    __asm { shr rbx, 1 } \
    __asm { shl rbx, 1 } \
    __asm { cmp rax, rbx } \
    __asm { jne L8 } \
    __asm { jmp L9 } \
    __asm { L8: } \
    __asm { _emit 0xCC } \
    __asm { L9: } \
    __asm { jmp L10 } \
    __asm { _emit 0x66 } \
    __asm { _emit 0x90 } \
    __asm { _emit 0x0F } \
    __asm { _emit 0x1F } \
    __asm { _emit 0x00 } \
    __asm { L10: } \
    __asm { lea rdx, [rip+8] } \
    __asm { xor rdx, S3 } \
    __asm { xor rdx, S3 } \
    __asm { push rdx } \
    __asm { ret } \
    __asm { jmp L11 } \
    __asm { _emit 0xE9 } \
    __asm { _emit 0xFF } \
    __asm { _emit 0xFF } \
    __asm { _emit 0xFF } \
    __asm { _emit 0xFF } \
    __asm { _emit 0xEB } \
    __asm { _emit 0xFE } \
    __asm { L11: } \
    __asm { push rcx } \
    __asm { mov rcx, S4 } \
    __asm { xor rcx, S4 } \
    __asm { add rax, rcx } \
    __asm { pop rcx } \
    __asm { jmp LE } \
    __asm { _emit 0xEB } \
    __asm { _emit 0xFE } \
    __asm { LE: }

#else
#define VEX
#endif

#endif
