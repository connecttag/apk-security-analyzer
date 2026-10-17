# -*- coding: utf-8 -*-
"""
entropy_analyzer.py - فاحص ومكتشف الأسرار المشفرة والمفاتيح عبر الإنتروبيا العشوائية (Shannon Entropy)
مستوحى ومطور من محرك entropy.py في MobSF لكشف مفاتيح التشفير (AES/RSA/Tokens) المضمنة
التي لا تتبع أنماط وتواقيع مزودين محددين (Provider-agnostic Secret Detection).
"""

import math
import re
from typing import List, Dict, Any, Set

B64_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARSET = "0123456789abcdefABCDEF"

B64_REGEX = re.compile(r'[a-zA-Z0-9+/=]{24,100}')
HEX_REGEX = re.compile(r'\b[a-fA-F0-9]{32,100}\b')

EXCLUDE_SUBSTRINGS = (
    "android", "androidx", "kotlin", "google", "compose",
    "material", "facebook", "twitter", "okhttp", "retrofit",
    "schema", "xmlns", "layout", "drawable", "string", "style",
    "java/lang", "dalvik", "lkotlin", "landroid"
)

def calculate_shannon_entropy(data: str, charset: str) -> float:
    """حساب درجة الإنتروبيا (Shannon Entropy) لسلسلة نصية."""
    if not data or len(data) == 0:
        return 0.0
    length = float(len(data))
    ent = 0.0
    for char in set(data):
        if char in charset:
            p_x = data.count(char) / length
            if p_x > 0:
                ent -= p_x * math.log2(p_x)
    return ent

def is_false_positive(candidate: str) -> bool:
    """فلترة وتصفية المرشحات لمنع الإنذارات الخاطئة الشائعة في بيئة أندرويد."""
    c_lower = candidate.lower()
    
    # استبعاد المسارات ومعرفات الدوال وفئات الـ DEX
    if "/" in candidate or "\\" in candidate or candidate.startswith("L"):
        return True
    
    # استبعاد الكلمات الأبجدية فقط (Purely alphabetical)
    if candidate.isalpha():
        return True
        
    # استبعاد النصوص التي لا تحتوي على تنوع كافٍ في الأحرف
    if len(set(candidate)) < 7:
        return True
        
    # استبعاد أرقام الهواتف أو التواريخ المتكررة
    if candidate.isdigit():
        return True
        
    # استبعاد أسماء الحزم والمكتبات الشائعة
    if any(ex in c_lower for ex in EXCLUDE_SUBSTRINGS):
        return True
        
    return False

def mask_secret(value: str) -> str:
    """حجب القيمة السرية للحفاظ على الخصوصية مع إظهار أطرافها."""
    if len(value) <= 8:
        return "****"
    prefix = value[:4]
    suffix = value[-4:]
    return f"{prefix}...{suffix}"

def scan_strings_for_entropy(strings_list: List[str], max_results: int = 25) -> List[Dict[str, Any]]:
    """
    فحص قائمة النصوص واستخراج السلاسل ذات الإنتروبيا العشوائية العالية (المفاتيح المشفرة والتشفير الصلب).
    """
    detected = []
    seen = set()

    for s in strings_list:
        if not s or len(s) < 20 or len(s) > 200:
            continue
            
        # 1. فحص سلاسل Hex (المفاتيح العشوائية وتجزئات التشفير السرية)
        hex_matches = HEX_REGEX.findall(s)
        for h in hex_matches:
            if h in seen or is_false_positive(h):
                continue
            ent = calculate_shannon_entropy(h, HEX_CHARSET)
            if ent >= 3.4:  # حد عشوائية Hex
                seen.add(h)
                detected.append({
                    "type": "HIGH_ENTROPY_HEX",
                    "name": "مفتاح تشفير سري أو توكن Hex عشوائي",
                    "severity": "HIGH",
                    "description": f"تم رصد سلسلة سداسية عشرية (Hex) ذات إنتروبيا عشوائية مرتفعة ({round(ent, 2)}) تشير إلى مفتاح تشفير خاص أو توكن مصادقة صلب.",
                    "masked_value": mask_secret(h),
                    "location": "DEX / Resources Strings"
                })
                if len(detected) >= max_results:
                    return detected

        # 2. فحص سلاسل Base64 (مفاتيح التشفير، رموز JWT، التوكنات)
        b64_matches = B64_REGEX.findall(s)
        for b in b64_matches:
            if b in seen or is_false_positive(b):
                continue
            ent = calculate_shannon_entropy(b, B64_CHARSET)
            if ent >= 4.5:  # حد عشوائية Base64
                seen.add(b)
                detected.append({
                    "type": "HIGH_ENTROPY_BASE64",
                    "name": "مفتاح سري عالي الإنتروبيا (Base64 Secret Key)",
                    "severity": "HIGH",
                    "description": f"تم رصد سلسلة مشفرة ذات إنتروبيا عشوائية مرتفعة ({round(ent, 2)}) يُشتبه بأنها مفتاح سري خاص، توكن JWT، أو رمز توقيع مضمن في الكود.",
                    "masked_value": mask_secret(b),
                    "location": "DEX / Resources Strings"
                })
                if len(detected) >= max_results:
                    return detected

    return detected
