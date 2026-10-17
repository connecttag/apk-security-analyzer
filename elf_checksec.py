# -*- coding: utf-8 -*-
"""
elf_checksec.py - فاحص أمان وتصليب ملفات المكتبات الأصلية (ELF Checksec) لنظام أندرويد (.so)
نسخة Pure-Python خفيفة ومستقلة تماماً خالية من أي مكتبات خارجية (Zero External Dependencies).
مستوحاة ومطورة بناءً على معايير فحص ELF في MobSF (NX, PIE, Stack Canary, RelRO, Banned Functions, Stripped).
"""

import struct
from typing import Dict, Any, Optional, List

BANNED_C_FUNCTIONS = [
    b"strcpy", b"sprintf", b"gets", b"strcat", b"system", b"popen", b"vsprintf"
]

def analyze_elf_bytes(data: bytes, file_name: str = "", arch: str = "") -> Optional[Dict[str, Any]]:
    """
    تحليل ثنائي لملف ELF واستخراج خصائص الأمان وتصليب الذاكرة (Checksec).
    يدعم صيغتي ELF32 و ELF64 مع التعامل التلقائي مع Endianness.
    """
    if not data or len(data) < 52 or data[:4] != b"\x7fELF":
        return None

    try:
        ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = data[5]   # 1 = Little Endian, 2 = Big Endian
        endian = "<" if ei_data == 1 else ">"
        is_64 = (ei_class == 2)

        if is_64:
            if len(data) < 64:
                return None
            (
                e_type, e_machine, e_version, e_entry,
                e_phoff, e_shoff, e_flags, e_ehsize,
                e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
            ) = struct.unpack(endian + "HHIQQQIHHHHHH", data[16:64])
        else:
            (
                e_type, e_machine, e_version, e_entry,
                e_phoff, e_shoff, e_flags, e_ehsize,
                e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
            ) = struct.unpack(endian + "HHIIIIIHHHHHH", data[16:52])

        is_nx = True  # الافتراضي في المعايير الحديثة هو تفعيل NX إلا إن كان صريحاً PF_X
        has_gnu_stack = False
        has_relro = False
        is_bind_now = False
        has_rpath = False
        has_runpath = False
        dynamic_offset = 0
        dynamic_size = 0

        # فحص ترويسات البرنامج (Program Headers)
        for i in range(min(e_phnum, 128)):
            ph_offset = e_phoff + i * e_phentsize
            if ph_offset + (56 if is_64 else 32) > len(data):
                break

            if is_64:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(
                    endian + "IIQQQQQQ", data[ph_offset:ph_offset + 56]
                )
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(
                    endian + "IIIIIIII", data[ph_offset:ph_offset + 32]
                )

            # PT_GNU_STACK = 0x6474e551
            if p_type == 0x6474e551:
                has_gnu_stack = True
                # إذا كانت راية التنفيذ PF_X (0x1) مفعلة على المكدس فالذاكرة غير محمية
                if (p_flags & 0x1) != 0:
                    is_nx = False

            # PT_GNU_RELRO = 0x6474e552
            elif p_type == 0x6474e552:
                has_relro = True

            # PT_DYNAMIC = 2
            elif p_type == 2:
                dynamic_offset = p_offset
                dynamic_size = p_filesz

        # فحص القسم الديناميكي Dynamic Section للتأكد من BIND_NOW و RPATH و RUNPATH
        if dynamic_offset > 0 and dynamic_size > 0:
            entry_size = 16 if is_64 else 8
            count = min(dynamic_size // entry_size, 512)
            for j in range(count):
                cur = dynamic_offset + j * entry_size
                if cur + entry_size > len(data):
                    break

                if is_64:
                    d_tag, d_val = struct.unpack(endian + "qQ", data[cur:cur + 16])
                else:
                    d_tag, d_val = struct.unpack(endian + "iI", data[cur:cur + 8])

                if d_tag == 0:  # DT_NULL
                    break
                elif d_tag == 24:  # DT_BIND_NOW
                    is_bind_now = True
                elif d_tag == 30:  # DT_FLAGS
                    if (d_val & 0x8) != 0:  # DF_BIND_NOW
                        is_bind_now = True
                elif d_tag == 0x6ffffffb:  # DT_FLAGS_1
                    if (d_val & 0x1) != 0:  # DF_1_NOW
                        is_bind_now = True
                elif d_tag == 15:  # DT_RPATH
                    has_rpath = True
                elif d_tag == 29:  # DT_RUNPATH
                    has_runpath = True

        if has_relro:
            relro_str = "FULL" if is_bind_now else "PARTIAL"
        else:
            relro_str = "NO"

        # في مكتبات أندرويد المشتركة (.so) e_type هو ET_DYN (3) الذي يعني مبدئياً Position Independent
        is_pie = (e_type == 3)

        # فحص وجود حماية المكدس Stack Canary
        has_canary = (b"__stack_chk_fail" in data or b"__stack_chk_guard" in data)

        # فحص الدوال غير الآمنة المحظورة Banned C Functions
        found_banned = []
        for b_func in BANNED_C_FUNCTIONS:
            if (b"\x00" + b_func + b"\x00") in data:
                found_banned.append(b_func.decode("utf-8", errors="ignore"))

        # فحص تجريد الرموز Stripped Symbols
        is_stripped = True
        if e_shoff > 0 and e_shnum > 0 and e_shstrndx < e_shnum:
            try:
                shstr_offset = e_shoff + e_shstrndx * e_shentsize
                if shstr_offset + (64 if is_64 else 40) <= len(data):
                    if is_64:
                        _, _, _, _, str_offset, str_size, _, _, _, _ = struct.unpack(
                            endian + "IIQQQQIIQQ", data[shstr_offset:shstr_offset + 64]
                        )
                    else:
                        _, _, _, _, str_offset, str_size, _, _, _, _ = struct.unpack(
                            endian + "IIIIIIIIII", data[shstr_offset:shstr_offset + 40]
                        )

                    if str_offset + str_size <= len(data):
                        shstrtab = data[str_offset:str_offset + str_size]
                        for s in range(min(e_shnum, 128)):
                            s_off = e_shoff + s * e_shentsize
                            if s_off + 4 <= len(data):
                                name_idx = struct.unpack(endian + "I", data[s_off:s_off + 4])[0]
                                if name_idx < len(shstrtab):
                                    name = shstrtab[name_idx:].split(b"\x00")[0]
                                    if name == b".symtab":
                                        is_stripped = False
                                        break
            except Exception:
                pass

        size_kb = round(len(data) / 1024.0, 1)

        return {
            "name": file_name,
            "arch": arch,
            "size_kb": size_kb,
            "is_64_bit": is_64,
            "is_nx": is_nx,
            "is_pie": is_pie,
            "relro": relro_str,
            "has_stack_canary": has_canary,
            "has_rpath": has_rpath,
            "has_runpath": has_runpath,
            "is_stripped": is_stripped,
            "banned_functions": found_banned
        }

    except Exception:
        return None
