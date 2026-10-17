# secrets_analyzer.py
# -*- coding: utf-8 -*-
"""
secrets_analyzer.py - فاحص تسريب مفاتيح الـ API والأسرار المنسية داخل كود الـ APK
يقوم بفحص جدول النصوص في ملفات DEX ومحتوى الموارد (strings.xml)
"""

import re
from typing import Dict, List, Any
from androguard.core.apk import APK
from androguard.core.analysis.analysis import Analysis

class SecretsAnalyzer:
    """كاشف الأسرار ومفاتيح الـ API المنسية وروابط الاختبار."""

    PATTERNS = [
        {
            "type": "GOOGLE_API_KEY",
            "name": "Google Maps / Cloud API Key",
            "pattern": r"AIza[0-9A-Za-z\-_]{35}",
            "severity": "HIGH",
            "description": "مفتاح Google API مكشوف قد يتيح استهلاك خدمات سحابية على حساب المطور."
        },
        {
            "type": "FIREBASE_URL",
            "name": "Firebase Realtime Database URL",
            "pattern": r"https://[a-zA-Z0-9\-_]+\.firebaseio\.com",
            "severity": "HIGH",
            "description": "رابط قاعدة بيانات Firebase مكشوف؛ إن كانت القواعد (Rules) غير محكمة فقد تتسرب البيانات."
        },
        {
            "type": "AWS_ACCESS_KEY",
            "name": "AWS Access Key ID",
            "pattern": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
            "severity": "CRITICAL",
            "description": "مفتاح وصول سحابي لـ Amazon Web Services مكشوف!"
        },
        {
            "type": "STRIPE_SECRET_KEY",
            "name": "Stripe API Key",
            "pattern": r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,99}",
            "severity": "CRITICAL",
            "description": "مفتاح بوابة الدفع Stripe (حي أو اختباري) مكشوف داخل التطبيق."
        },
        {
            "type": "PRIVATE_KEY",
            "name": "Private RSA/EC Encryption Key",
            "pattern": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
            "severity": "CRITICAL",
            "description": "مفتاح تشفير خاص مدمج داخل كود التطبيق!"
        },
        {
            "type": "GITHUB_TOKEN",
            "name": "GitHub Access Token",
            "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
            "severity": "CRITICAL",
            "description": "رمز وصول شخصي لمستودعات GitHub مكشوف."
        },
        {
            "type": "STAGING_DEV_URL",
            "name": "Unprotected Staging / Dev Server",
            "pattern": r"https?://[a-zA-Z0-9_\-\.]*(?:staging|dev|test|sandbox|internal)[a-zA-Z0-9_\-\.]*\.[a-zA-Z]{2,}(?::[0-9]{2,5})?(?:/[^\s\"']*)?",
            "severity": "MEDIUM",
            "description": "رابط لخادم تجريبي أو تطويري داخلي غير محمي قد يحتوي على نقاط نهاية حساسة."
        },
        {
            "type": "BASIC_AUTH_URL",
            "name": "Hardcoded Basic Auth in URL",
            "pattern": r"https?://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9_\-\.]+",
            "severity": "HIGH",
            "description": "رابط يحتوي على اسم مستخدم وكلمة مرور مضمنة مباشرة في الـ URL."
        }
    ]

    def __init__(self, apk: APK, anydx: Analysis = None):
        self.apk = apk
        self.anydx = anydx

    def scan(self) -> List[Dict[str, Any]]:
        """فحص التطبيق واستخراج كافة المفاتيح والأسرار المكتشفة."""
        found_secrets = []
        seen_keys = set()

        # 1. جمع كافة النصوص المتاحة من الـ DEX والـ Resources
        strings_pool = self._collect_strings()

        # 2. فحص النصوص باستخدام الأنماط المحددة
        for pattern_info in self.PATTERNS:
            regex = re.compile(pattern_info["pattern"])
            p_type = pattern_info["type"]

            for text_entry in strings_pool:
                text = text_entry["value"]
                location = text_entry["location"]

                for match in regex.finditer(text):
                    secret_value = match.group(0)
                    if secret_value in seen_keys:
                        continue
                    seen_keys.add(secret_value)

                    # إخفاء جزء من القيمة للحماية (Masking)
                    masked = self._mask_secret(secret_value)

                    found_secrets.append({
                        "type": p_type,
                        "name": pattern_info["name"],
                        "severity": pattern_info["severity"],
                        "description": pattern_info["description"],
                        "masked_value": masked,
                        "location": location
                    })

                    if len(found_secrets) >= 100: # حد أقصى معقول
                        break

        # 3. فحص الإنتروبيا العشوائية (Shannon Entropy) لكشف المفاتيح والتشفير الصلب المخصص
        try:
            from entropy_analyzer import scan_strings_for_entropy
            raw_strings = [item["value"] for item in strings_pool]
            entropy_items = scan_strings_for_entropy(raw_strings, max_results=30)
            for item in entropy_items:
                masked = item.get("masked_value")
                if masked and not any(s.get("masked_value") == masked for s in found_secrets):
                    found_secrets.append(item)
                    if len(found_secrets) >= 120:
                        break
        except Exception:
            pass

        return found_secrets

    def _collect_strings(self) -> List[Dict[str, str]]:
        """جمع النصوص من ملفات الـ DEX وموارد الـ APK."""
        pool = []

        # من جدول النصوص في DEX عبر Androguard
        if self.anydx:
            try:
                for s in self.anydx.get_strings():
                    val = s.get_value()
                    if val and len(val) >= 8:
                        pool.append({"value": val, "location": "DEX Bytecode"})
            except Exception:
                pass

        # من ملفات الـ XML والموارد (strings.xml)
        try:
            for file_name in self.apk.get_files():
                if file_name.endswith(".xml") or file_name.startswith("res/values/"):
                    try:
                        raw = self.apk.get_file(file_name)
                        if raw:
                            text_content = raw.decode("utf-8", errors="ignore")
                            # استخراج النصوص بين علامات الـ XML أو القيم
                            for line in text_content.splitlines():
                                line_clean = line.strip()
                                if len(line_clean) >= 8:
                                    pool.append({"value": line_clean, "location": f"Resource: {file_name}"})
                    except Exception:
                        continue
        except Exception:
            pass

        return pool

    def _mask_secret(self, secret: str) -> str:
        """إخفاء منتصف المفتاح للحفاظ على الأمان."""
        if len(secret) <= 8:
            return secret[:2] + "****" + secret[-2:]
        keep_start = min(4, len(secret) // 4)
        keep_end = min(4, len(secret) // 4)
        return secret[:keep_start] + "..." + ("*" * 6) + "..." + secret[-keep_end:]
