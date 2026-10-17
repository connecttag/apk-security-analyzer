#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
decompiler_service.py - محرك التفكيك البرمجي الداخلي (Built-in Decompiler & Disassembler)
يستخدم محرك Androguard DAD المدمج لتحويل بايت كود Dalvik إلى كود Java كامل،
أو توليد كود Smali الهيكلي، مع فحص الأسطر المشبوهة والثغرات الأمنية في الكود المصدري.
"""

import os
import sys
import re
import traceback
from typing import Dict, List, Any, Optional

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    from androguard.core.analysis import analysis
    from androguard.decompiler.decompiler import DecompilerDAD
except ImportError:
    pass

# أنماط فحص الأسطر المشبوهة في الأكواد
SUSPICIOUS_PATTERNS = [
    # تنفيذ أوامر النظام (Command Injection / Shell Execution)
    {
        "pattern": re.compile(r'(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|\/system\/bin\/sh|bin\/su)', re.IGNORECASE),
        "reason": "تنفيذ أوامر صدفية في النظام (Shell/Root Command Execution)",
        "severity": "CRITICAL",
        "category": "COMMAND_EXECUTION"
    },
    # تحميل الأكواد الديناميكي (Dynamic Code Loading)
    {
        "pattern": re.compile(r'(DexClassLoader|PathClassLoader|InMemoryDexClassLoader|dalvik\.system)', re.IGNORECASE),
        "reason": "تحميل كود تنفيذي خارجي ديناميكياً في الذاكرة (Dynamic Code Loading)",
        "severity": "CRITICAL",
        "category": "DYNAMIC_CODE"
    },
    # الانعكاس البرمجي للوصول لدوال خفية (Dangerous Reflection)
    {
        "pattern": re.compile(r'(Class\.forName|getDeclaredMethod|getMethod.*\.invoke|setAccessible\(true\))', re.IGNORECASE),
        "reason": "استخدام الانعكاس البرمجي (Reflection) للوصول لكلاسات أو دوال خاصة/محمية",
        "severity": "HIGH",
        "category": "REFLECTION"
    },
    # تجسس وتسجيل ومراقبة (Surveillance & Eavesdropping)
    {
        "pattern": re.compile(r'(AudioRecord|MediaRecorder.*AudioSource|Camera\.open|camera2|getDeviceId|getImei|getSubscriberId|getSimSerialNumber)', re.IGNORECASE),
        "reason": "استدعاء حساس لتسجيل الصوت أو الكاميرا أو سحب معرفات الشريحة والعتاد",
        "severity": "HIGH",
        "category": "SURVEILLANCE"
    },
    # مراقبة الموقع الجغرافي (Location Tracking)
    {
        "pattern": re.compile(r'(requestLocationUpdates|getLastKnownLocation|LocationListener|ACCESS_FINE_LOCATION)', re.IGNORECASE),
        "reason": "تتبع ورصد الموقع الجغرافي للمستخدم",
        "severity": "MEDIUM",
        "category": "LOCATION"
    },
    # إرسال رسائل نصية في الخلفية (Background SMS)
    {
        "pattern": re.compile(r'(SmsManager.*sendTextMessage|sendMultipartTextMessage)', re.IGNORECASE),
        "reason": "إرسال رسائل نصية قصيرة SMS في الخلفية",
        "severity": "HIGH",
        "category": "SMS"
    },
    # تجاوز أمان الشبكة والشهادات (Insecure Network / SSL Bypass)
    {
        "pattern": re.compile(r'(X509TrustManager|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllCerts|checkServerTrusted\(.*\{\s*\}\))', re.IGNORECASE),
        "reason": "تعطيل التحقق من شهادات SSL/TLS (Insecure TrustManager / MITM Risk)",
        "severity": "CRITICAL",
        "category": "NETWORK_SECURITY"
    },
    # حركة مرور HTTP غير مشفرة (Cleartext Traffic)
    {
        "pattern": re.compile(r'http:\/\/(?!schemas\.android\.com|www\.w3\.org)[a-zA-Z0-9\-\.]+', re.IGNORECASE),
        "reason": "استخدام بروتوكول HTTP غير المشفر لنقل البيانات",
        "severity": "MEDIUM",
        "category": "CLEARTEXT_TRAFFIC"
    },
    # خوارزميات تشفير ضعيفة (Weak Cryptography)
    {
        "pattern": re.compile(r'(DES|DESede|RC4|AES\/ECB|MD5|SHA-1)(?!\w)', re.IGNORECASE),
        "reason": "استخدام خوارزمية تشفير أو هاش ضعيفة أو مهجورة",
        "severity": "MEDIUM",
        "category": "WEAK_CRYPTO"
    },
    # كشف الروت والتصحيح (Root / Debug Detection)
    {
        "pattern": re.compile(r'(isDebuggerConnected|\/su\/bin|supersu|magisk|which\s+su|build\.tags.*test-keys)', re.IGNORECASE),
        "reason": "فحص وكشف بيئة الروت أو التصحيح (Anti-Root / Anti-Debug)",
        "severity": "LOW",
        "category": "ANTI_TAMPER"
    }
]

class DecompilerService:
    def __init__(self, apk: Optional[APK] = None, dx: Optional[analysis.Analysis] = None):
        self.apk = apk
        self.dx = dx
        self.dex_list = []

    def load_apk(self, apk_path: str):
        """تحميل ملف APK وتهيئة كائنات التحليل وربط مفكك DAD."""
        self.apk = APK(apk_path)
        self.dx = analysis.Analysis()
        self.dex_list = []
        target_api = self.apk.get_target_sdk_version() or 28

        for dex_bytes in self.apk.get_all_dex():
            try:
                df = DEX(dex_bytes, using_api=target_api)
                self.dx.add(df)
                self.dex_list.append(df)
                df.set_decompiler(DecompilerDAD(df, self.dx))
            except Exception:
                pass
        self.dx.create_xref()

    def decompile_class(self, class_name: str, format_type: str = "java") -> Dict[str, Any]:
        """
        تفكيك كلاس محدد بالاسم إلى كود Java أو Smali، وفحص الأسطر المشبوهة.
        يدعم أسماء مثل:
        - com.example.MainActivity
        - Lcom/example/MainActivity;
        """
        if not self.dx:
            return {
                "status": "error",
                "message": "لم يتم تحميل كائن التحليل DEX بنجاح."
            }

        # تنظيف وتحويل اسم الكلاس إلى النمطين: الدلفيك والنقطي
        if class_name.startswith("L") and class_name.endswith(";"):
            dalvik_name = class_name
            dot_name = class_name[1:-1].replace("/", ".")
        else:
            dot_name = class_name
            dalvik_name = "L" + class_name.replace(".", "/") + ";"

        target_cls = None
        # البحث في كلاسات الـ Analysis
        for cls in self.dx.get_classes():
            cname = cls.name
            if cname == dalvik_name or cname == dot_name or cname.rstrip(";").endswith("/" + dot_name.split(".")[-1]):
                target_cls = cls
                break

        if not target_cls:
            # محاولة بحث متساهل غير حساس لحالة الأحرف
            dot_lower = dot_name.lower()
            for cls in self.dx.get_classes():
                if dot_lower in cls.name.lower():
                    target_cls = cls
                    break

        if not target_cls:
            return {
                "status": "error",
                "class_name": class_name,
                "message": f"تعذر العثور على الكلاس '{class_name}' في ملفات DEX للتطبيق."
            }

        if format_type.lower() == "smali":
            return self._generate_smali(target_cls, dot_name)
        else:
            return self._generate_java(target_cls, dot_name)

    def _generate_java(self, cls_analysis, display_name: str) -> Dict[str, Any]:
        """تفكيك الكلاس إلى لغة Java باستخدام Androguard DAD."""
        source_code = ""
        vm_class = cls_analysis.get_vm_class()
        try:
            source_code = vm_class.get_source()
        except Exception as e:
            # في حال فشل التفكيك الكامل، محاولة التوليد الهيكلي للدوال
            source_code = f"// [تنبيه] واجه التفكيك التلقائي الكامل استثناء: {str(e)}\n"
            source_code += f"// محاولة توليد الهيكل البرمجي للدوال:\n\n"
            source_code += f"package {'.'.join(display_name.split('.')[:-1])};\n\n"
            source_code += f"public class {display_name.split('.')[-1]} {{\n"
            try:
                for method in cls_analysis.get_methods():
                    m_name = method.name
                    try:
                        m_vm = method.get_method()
                        m_source = m_vm.get_source()
                        source_code += f"\n{m_source}\n"
                    except Exception as me:
                        source_code += f"\n    // الدالة {m_name}: {str(me)}\n"
                        source_code += f"    public void {m_name}() /* bytecode unavailable */ {{}}\n"
                source_code += "\n}\n"
            except Exception:
                source_code += f"\n    // لم يتم استخراج الدوال\n}}\n"

        if not source_code or len(source_code.strip()) == 0:
            source_code = f"// تعذر استخراج كود Java للكلاس {display_name}.\n"

        suspicious_lines = self._scan_suspicious_lines(source_code)

        return {
            "status": "success",
            "class_name": display_name,
            "format": "java",
            "source_code": source_code,
            "total_lines": len(source_code.splitlines()),
            "suspicious_lines": suspicious_lines,
            "methods_count": len(list(cls_analysis.get_methods())) if hasattr(cls_analysis, "get_methods") else 0
        }

    def _generate_smali(self, cls_analysis, display_name: str) -> Dict[str, Any]:
        """توليد كود Smali / Dalvik Disassembly للكلاس."""
        vm_class = cls_analysis.get_vm_class()
        lines = []

        class_name = cls_analysis.name
        superclass = getattr(vm_class, 'sname', 'Ljava/lang/Object;')
        access_flags = getattr(vm_class, 'get_access_flags_string', lambda: 'public')() if hasattr(vm_class, 'get_access_flags_string') else (getattr(vm_class, 'access_flags_string', None) or 'public')

        lines.append(f".class {access_flags} {class_name}")
        lines.append(f".super {superclass}")
        lines.append("")

        # الحقول (Fields)
        try:
            class_data = getattr(vm_class, 'class_data_item', None)
            if class_data:
                for f in getattr(class_data, 'static_fields', []) or []:
                    lines.append(f".field static {f.get_name()}:{f.get_type()}")
                for f in getattr(class_data, 'instance_fields', []) or []:
                    lines.append(f".field {f.get_name()}:{f.get_type()}")
            if class_data:
                lines.append("")
        except Exception:
            pass

        # الدوال والتعليمات (Methods & Instructions)
        try:
            for method in cls_analysis.get_methods():
                m_item = method.get_method()
                m_name = method.name
                m_desc = method.descriptor
                m_flags = getattr(m_item, 'get_access_flags_string', lambda: 'public')() if hasattr(m_item, 'get_access_flags_string') else 'public'

                lines.append(f".method {m_flags} {m_name}{m_desc}")
                try:
                    code_item = getattr(m_item, 'get_code', lambda: None)() if hasattr(m_item, 'get_code') else getattr(m_item, 'code_item', None)
                    if code_item and hasattr(code_item, 'get_registers_size'):
                        lines.append(f"    .registers {code_item.get_registers_size()}")
                    elif code_item and hasattr(code_item, 'registers_size'):
                        lines.append(f"    .registers {code_item.registers_size}")

                    if hasattr(m_item, 'get_instructions'):
                        for ins in m_item.get_instructions():
                            lines.append(f"    {ins.get_name()} {ins.get_output()}")
                except Exception as ins_err:
                    lines.append(f"    # خطأ أثناء قراءة تعليمات الدالة: {str(ins_err)}")
                lines.append(".end method")
                lines.append("")
        except Exception as me:
            lines.append(f"# استثناء أثناء تفكيك دوال Smali: {str(me)}")

        source_code = "\n".join(lines)
        suspicious_lines = self._scan_suspicious_lines(source_code)

        return {
            "status": "success",
            "class_name": display_name,
            "format": "smali",
            "source_code": source_code,
            "total_lines": len(lines),
            "suspicious_lines": suspicious_lines,
            "methods_count": len(list(cls_analysis.get_methods())) if hasattr(cls_analysis, "get_methods") else 0
        }

    def _scan_suspicious_lines(self, code: str) -> List[Dict[str, Any]]:
        """فحص أسطر الكود البرمجي ورصد السلوكيات الحساسة والثغرات."""
        findings = []
        lines = code.splitlines()
        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith("//") or line_str.startswith("#") or line_str.startswith("/*"):
                continue
            for rule in SUSPICIOUS_PATTERNS:
                if rule["pattern"].search(line_str):
                    findings.append({
                        "line_number": idx,
                        "line_content": line_str[:120],
                        "reason": rule["reason"],
                        "severity": rule["severity"],
                        "category": rule["category"]
                    })
                    break # فحص تطابق واحد لكل سطر لتجنب التكرار
        return findings
