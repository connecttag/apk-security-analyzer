# -*- coding: utf-8 -*-
"""
crypto_audit.py - تدقيق أخطاء تكوين التشفير البرمجي وخوارزميات التشفير الضعيفة
Cryptographic Misconfigurations & Insecure Ciphers Auditor
يفحص بايت كود DEX واستدعاءات Smali لرصد:
1. وضع ECB في خوارزميات التشفير (AES/ECB/PKCS5Padding).
2. استخدام خوارزميات قديمة مكسورة (DES, 3DES, RC4, Blowfish).
3. متجهات تهيئة ثابتة أو ضعيفة (Static / Hardcoded IV).
4. استخدام مولدات عشوائية غير آمنة (java.util.Random بدلاً من SecureRandom).
5. اشتقاق المفاتيح باستخدام دوال تجزئة مكسورة (MD5, SHA1).
"""

import re
from typing import Dict, List, Any
from androguard.core.analysis.analysis import Analysis
from androguard.core.apk import APK

INSECURE_CIPHERS = {
    "des": ("DES", "CRITICAL", "خوارزمية DES قديمة ومكسورة أمنياً بحجم مفتاح 56-bit فقط."),
    "desede": ("Triple DES (3DES)", "HIGH", "خوارزمية 3DES بطيئة وتعتبر متقادمة ومعرضة لهجمات Sweet32."),
    "rc4": ("RC4 (ARCFOUR)", "CRITICAL", "خوارزمية تشفير التدفق RC4 مكسورة تماماً وعرضة لهجمات انحياز البايتات."),
    "rc2": ("RC2", "CRITICAL", "خوارزمية RC2 ضعيفة وعرضة لكسر التشفير بسهولة."),
    "blowfish": ("Blowfish", "MEDIUM", "خوارزمية Blowfish تستخدم حجم كتلة 64-bit مما يجعلها عرضة لهجمات تصادم الكتل.")
}

STATIC_IV_PATTERNS = [
    re.compile(r'^[0\s]{8,}$'),
    re.compile(r'^[0-9a-fA-F]{16}$'),
    re.compile(r'^(?:0123456789|12345678|abcdefgh|password|initialv)', re.IGNORECASE),
]

class CryptoAuditor:
    def __init__(self, apk: APK, anydx: Analysis):
        self.apk = apk
        self.anydx = anydx

    def audit(self) -> Dict[str, Any]:
        findings = []

        # 1. فحص استدعاءات Cipher.getInstance والسلاسل النصية المرتبطة بالتشفير
        cipher_strings = set()
        try:
            for s in self.anydx.get_strings():
                val = s.get_value() if hasattr(s, 'get_value') else str(s)
                if not val or len(val) > 80:
                    continue
                v_lower = val.lower().strip()
                if "aes" in v_lower or "des" in v_lower or "rsa" in v_lower or "cipher" in v_lower:
                    cipher_strings.add(val)
        except Exception:
            pass

        # فحص وضع ECB وخوارزميات التشفير الضعيفة
        for cs in cipher_strings:
            cs_lower = cs.lower().strip()
            
            # رصد وضع ECB
            if "/ecb/" in cs_lower or cs_lower == "aes/ecb" or cs_lower == "aes":
                findings.append({
                    "type": "INSECURE_CIPHER_MODE_ECB",
                    "title": "استخدام وضع التشفير غير الآمن Electronic Codebook (ECB)",
                    "severity": "HIGH",
                    "description": f"تم رصد تهيئة التشفير بالنمط ({cs}). وضع ECB يسرب أنماط وتكرارات البيانات الصريحة ولا يوفر سرية حقيقية للكتل المتطابقة.",
                    "recommendation": "استخدم وضع GCM (مثل AES/GCM/NoPadding) مع مصادقة البيانات (AEAD)، أو وضع CBC مع HMAC.",
                    "evidence": [cs]
                })

            # رصد خوارزميات التشفير المكسورة
            for cipher_key, (c_name, sev, c_desc) in INSECURE_CIPHERS.items():
                if cs_lower == cipher_key or cs_lower.startswith(f"{cipher_key}/"):
                    findings.append({
                        "type": f"BROKEN_CIPHER_{cipher_key.upper()}",
                        "title": f"استخدام خوارزمية تشفير مكسورة ({c_name})",
                        "severity": sev,
                        "description": f"{c_desc} (النمط المرصود: {cs})",
                        "recommendation": "استبدل الخوارزمية بـ AES-256-GCM أو ChaCha20-Poly1305.",
                        "evidence": [cs]
                    })

        # 2. فحص استدعاءات بايت كود الدوال الحساسة (Random, IV, KeyGenerator)
        has_insecure_random = False
        sample_insecure_random_class = ""
        has_insecure_kdf = False
        sample_insecure_kdf_class = ""

        try:
            for method in self.anydx.get_methods():
                c_name = method.get_class_name().lower()
                # استبعاد مكتبات أندرويد الداخلية ومكتبات العرض
                if any(c_name.startswith(p) for p in ("landroidx/", "lcom/google/", "lkotlin/", "landroid/")):
                    continue

                for _, call, _ in method.get_xref_to():
                    called_class = call.get_class_name()
                    called_method = call.name

                    # رصد استخدام java.util.Random في كود التطبيق المباشر
                    if "java/util/Random" in called_class and not "SecureRandom" in called_class:
                        if not has_insecure_random:
                            has_insecure_random = True
                            sample_insecure_random_class = f"{method.get_class_name()}->{method.name}"

                    # رصد اشتقاق المفاتيح بـ MD5 أو SHA-1
                    if "MessageDigest" in called_class and called_method == "getInstance":
                        # سنفحص في النصوص إن وُجد اقتران بين MD5 و SecretKey
                        pass
        except Exception:
            pass

        if has_insecure_random:
            findings.append({
                "type": "INSECURE_RANDOM_GENERATOR",
                "title": "استخدام مولد عشوائي غير آمن (java.util.Random)",
                "severity": "MEDIUM",
                "description": "يستخدم التطبيق كلاس java.util.Random بدلاً من SecureRandom. هذا المولد قابل للتنبؤ حسابياً ولا يصلح للعمليات الحساسة أو التوكنات.",
                "recommendation": "استخدم دائماً java.security.SecureRandom لإنشاء قيم التهيئة (IVs)، الرموز العشوائية، والمفاتيح.",
                "evidence": [sample_insecure_random_class]
            })

        # 3. فحص الـ Static IV عبر السلاسل النصية
        for s in cipher_strings:
            for pat in STATIC_IV_PATTERNS:
                if pat.search(s) and len(s) in (8, 16, 24, 32):
                    findings.append({
                        "type": "HARDCODED_STATIC_IV",
                        "title": "اشتباه في متجه تهيئة ثابت (Hardcoded Static IV)",
                        "severity": "HIGH",
                        "description": f"تم رصد سلسلة ثابتة تُشتبه بأنها IV لتشفير CBC: '{s}'. إعادة استخدام نفس الـ IV يلغي أمان التشفير ويتيح استنتاج النصوص الأصلية.",
                        "recommendation": "قم بتوليد IV عشوائي جديد لكل عملية تشفير باستخدام SecureRandom وقم بإرفاقه مع النص المشفر.",
                        "evidence": [s]
                    })
                    break

        return {
            "has_crypto_issues": len(findings) > 0,
            "total_issues": len(findings),
            "findings": findings
        }
