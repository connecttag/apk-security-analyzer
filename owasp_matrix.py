# -*- coding: utf-8 -*-
"""
owasp_matrix.py - محرك مصفوفة التوافق مع معيار OWASP MASVS & MASTG العالمي
OWASP Mobile Application Security Verification Standard Compliance Engine
يقوم بتحليل كافة نتائج الفحص وتعيينها على محاور المعيار السبعة:
1. MASVS-STORAGE: أمان التخزين وحماية البيانات
2. MASVS-CRYPTO: أمان التشفير والمفاتيح الرقمية
3. MASVS-AUTH: المصادقة وإدارة الجلسات
4. MASVS-NETWORK: أمان الاتصالات والشبكة
5. MASVS-PLATFORM: التفاعل مع المنصة والمكونات المصدرة
6. MASVS-CODE: جودة الكود وإعدادات البناء والمكتبات
7. MASVS-RESILIENCE: الدفاع ومقاومة التلاعب
"""

from typing import Dict, List, Any

def generate_owasp_compliance_matrix(
    manifest_security: Dict[str, Any] = None,
    signatures: Dict[str, Any] = None,
    crypto_audit: Dict[str, Any] = None,
    webview_audit: Dict[str, Any] = None,
    network_audit: Dict[str, Any] = None,
    firebase_audit: Dict[str, Any] = None,
    cloud_bucket_audit: Dict[str, Any] = None,
    manifest_audit: Dict[str, Any] = None,
    native_libs: Dict[str, Any] = None,
    app_defenses: Dict[str, Any] = None,
    playstore_audit: Dict[str, Any] = None,
    secrets: List[Dict[str, Any]] = None,
    leaked_keystores: Dict[str, Any] = None,
    ipc_audit: Dict[str, Any] = None
) -> Dict[str, Any]:
    """توليد مصفوفة امتثال وتقييم شامل لمعيار OWASP MASVS."""
    manifest_flags = manifest_security.get("flags", {}) if manifest_security else {}
    certs = signatures.get("certificates", []) if signatures else []
    crypto_findings = crypto_audit.get("findings", []) if crypto_audit else []
    webview_findings = webview_audit.get("findings", []) if webview_audit else []
    ipc_findings = ipc_audit.get("findings", []) if ipc_audit else []
    sec_cfg = network_audit.get("security_config", {}) if network_audit else {}
    secrets_list = secrets or []

    categories = []

    # 1. MASVS-STORAGE
    storage_items = []
    # فحص allowBackup
    allow_backup = manifest_flags.get("allow_backup", True)
    storage_items.append({
        "id": "MASVS-STORAGE-1",
        "title": "حظر النسخ الاحتياطي غير المصرح به للبيانات (allowBackup)",
        "status": "FAIL" if allow_backup else "PASS",
        "description": "النسخ الاحتياطي مفعل (allowBackup=true)؛ يمكن استخراج البيانات عبر adb backup." if allow_backup else "النسخ الاحتياطي معطل بنجاح (allowBackup=false)."
    })
    # فحص ملفات Keystore المسربة
    has_keystores = leaked_keystores.get("has_leaked_keystores", False) if leaked_keystores else False
    storage_items.append({
        "id": "MASVS-STORAGE-2",
        "title": "حماية مخازن الشهادات والمفاتيح من التضمين في الحزمة",
        "status": "FAIL" if has_keystores else "PASS",
        "description": "تم العثور على ملفات مفاتيح أو شهادات مدمجة داخل الحزمة!" if has_keystores else "لم يتم العثور على ملفات Keystore مسربة داخل الحزمة."
    })
    # فحص مسارات FileProvider
    has_root_path = any(f.get("type") == "FILE_PROVIDER_PATH_TRAVERSAL" for f in ipc_findings)
    storage_items.append({
        "id": "MASVS-STORAGE-3",
        "title": "أمان مسارات مشاركة الملفات (FileProvider Path Traversal)",
        "status": "FAIL" if has_root_path else "PASS",
        "description": "تم رصد استخدام <root-path> مما يتيح تجاوز مسارات الملفات والوصول للجذر!" if has_root_path else "مسارات مشاركة الملفات لا تحتوي على مسار الجذر المفتوح."
    })

    # 2. MASVS-CRYPTO
    crypto_items = []
    # قوة المفتاح الرقمي
    weak_key = any(c.get("is_weak_key", False) for c in certs)
    crypto_items.append({
        "id": "MASVS-CRYPTO-1",
        "title": "استخدام مفاتيح تشفير رقمية قوية (>= 2048-bit)",
        "status": "FAIL" if weak_key else "PASS",
        "description": "طول مفتاح الشهادة أقل من 2048-bit مما يجعله ضعيفاً." if weak_key else "طول المفتاح يفي بالمعايير الأمنية المعتمدة (>= 2048-bit)."
    })
    # خوارزميات التجزئة
    weak_hash = any(c.get("is_weak_hash", False) for c in certs)
    crypto_items.append({
        "id": "MASVS-CRYPTO-2",
        "title": "حظر خوارزميات التجزئة المكسورة (MD5 / SHA-1)",
        "status": "FAIL" if weak_hash else "PASS",
        "description": "تم رصد استخدام خوارزميات تجزئة ضعيفة (MD5/SHA1)." if weak_hash else "التطبيق يعتمد خوارزميات تجزئة قوية وحديثة (SHA-256+)."
    })
    # وضع التشفير ECB وخوارزميات مكسورة
    has_ecb = any("ECB" in f.get("type", "") for f in crypto_findings)
    crypto_items.append({
        "id": "MASVS-CRYPTO-3",
        "title": "حظر أوضاع التشفير غير الآمنة (Electronic Codebook - ECB)",
        "status": "FAIL" if has_ecb else "PASS",
        "description": "تم رصد استخدام وضع التشفير المكسور ECB." if has_ecb else "لا يستخدم التطبيق وضع التشفير غير الآمن ECB."
    })
    # الأسرار المضمنة بالإنتروبيا
    has_high_entropy = any("ENTROPY" in s.get("type", "") for s in secrets_list)
    crypto_items.append({
        "id": "MASVS-CRYPTO-4",
        "title": "خلو الكود من مفاتيح التشفير الصلبة (Hardcoded High-Entropy Secrets)",
        "status": "FAIL" if has_high_entropy else "PASS",
        "description": "تم رصد مفاتيح تشفير أو توكنات سرية ذات إنتروبيا عشوائية مرتفعة مضمنة في الكود." if has_high_entropy else "لم يتم رصد مفاتيح تشفير سرية صلبة عبر فحص الإنتروبيا."
    })

    # 3. MASVS-AUTH
    auth_items = []
    has_basic_auth = any(s.get("type") == "BASIC_AUTH_URL" for s in secrets_list)
    auth_items.append({
        "id": "MASVS-AUTH-1",
        "title": "حظر تضمين بيانات الاعتماد والمصادقة في الروابط (Basic Auth in URL)",
        "status": "FAIL" if has_basic_auth else "PASS",
        "description": "تم رصد روابط تحتوي على اسم مستخدم وكلمة مرور مضمنة صراحة!" if has_basic_auth else "الروابط والنطاقات خالية من بيانات الاعتماد المضمنة."
    })
    has_leaked_tokens = any(s.get("type") in ("GITHUB_TOKEN", "STRIPE_SECRET_KEY", "AWS_ACCESS_KEY") for s in secrets_list)
    auth_items.append({
        "id": "MASVS-AUTH-2",
        "title": "حماية مفاتيح وتوكنات الوصول السحابي والخدمي",
        "status": "FAIL" if has_leaked_tokens else "PASS",
        "description": "تم رصد توكنات ومفاتيح وصول سحابية حساسة مكشوفة." if has_leaked_tokens else "لا توجد توكنات خدمات سحابية حساسة مكشوفة."
    })

    # 4. MASVS-NETWORK
    network_items = []
    # حركة المرور غير المشفرة Cleartext
    cleartext_permitted = sec_cfg.get("cleartext_traffic_permitted", False) if sec_cfg else manifest_flags.get("uses_cleartext_traffic", False)
    network_items.append({
        "id": "MASVS-NETWORK-1",
        "title": "إلزامية تشفير كافة اتصالات الشبكة وحظر HTTP غير المشفر (Cleartext)",
        "status": "FAIL" if cleartext_permitted else "PASS",
        "description": "حركة مرور HTTP غير المشفرة مسموحة في التطبيق." if cleartext_permitted else "كافة الاتصالات مشفرة بـ HTTPS افتراضياً."
    })
    # الوثوق بشهادات المستخدم
    user_certs = sec_cfg.get("user_certificates_trusted", False) if sec_cfg else False
    network_items.append({
        "id": "MASVS-NETWORK-2",
        "title": "الوثوق بشهادات النظام المعتمدة فقط (حظر User CAs في الإنتاج)",
        "status": "FAIL" if user_certs else "PASS",
        "description": "التطبيق يثق بشهادات المستخدم، مما يتيح اعتراض الترافيك بهجمات MITM." if user_certs else "التطبيق يثق بشهادات النظام الرسمية فقط."
    })
    # قواعد بيانات Firebase
    open_fb = firebase_audit.get("open_databases_count", 0) if firebase_audit else 0
    network_items.append({
        "id": "MASVS-NETWORK-3",
        "title": "حماية قواعد بيانات Firebase من القراءة العامة غير المصرح بها",
        "status": "FAIL" if open_fb > 0 else "PASS",
        "description": f"تم رصد {open_fb} قاعدة بيانات Firebase مفتوحة للعلن بدون مصادقة!" if open_fb > 0 else "قواعد بيانات Firebase محمية بقواعد أمان."
    })
    # المستودعات السحابية المفتوحة
    open_buckets = cloud_bucket_audit.get("open_buckets_count", 0) if cloud_bucket_audit else 0
    network_items.append({
        "id": "MASVS-NETWORK-4",
        "title": "حماية المستودعات السحابية (AWS S3 / GCS / Azure) من التصفح العام",
        "status": "FAIL" if open_buckets > 0 else "PASS",
        "description": f"تم اكتشاف {open_buckets} مستودع سحابي مفتوح للعلن!" if open_buckets > 0 else "المستودعات السحابية محمية أو غير مكشوفة."
    })
    # WebView SSL Bypass
    has_ssl_bypass = any(f.get("type") == "WEBVIEW_SSL_PROCEED_BYPASS" for f in webview_findings)
    network_items.append({
        "id": "MASVS-NETWORK-5",
        "title": "التحقق الصارم من شهادات SSL داخل مكونات الـ WebView",
        "status": "FAIL" if has_ssl_bypass else "PASS",
        "description": "تم رصد دالة تتجاوز أخطاء شهادات SSL عبر handler.proceed()!" if has_ssl_bypass else "مكونات الـ WebView لا تتجاوز فحص شهادات SSL."
    })

    # 5. MASVS-PLATFORM
    platform_items = []
    # المكونات المكشوفة غير المحمية
    unprotected = manifest_audit.get("unprotected_count", 0) if manifest_audit else 0
    platform_items.append({
        "id": "MASVS-PLATFORM-1",
        "title": "حماية المكونات المصدّرة (Exported Components) بأذونات وصول",
        "status": "FAIL" if unprotected > 0 else "PASS",
        "description": f"يحتوي التطبيق على {unprotected} مكون مصدّر ومكشوف دون أي حماية صلاحيات." if unprotected > 0 else "كافة المكونات المصدرة محمية أو خاصة بالتطبيق."
    })
    # إعادة توجيه النوايا
    has_intent_redir = any(f.get("type") == "INTENT_REDIRECTION_SUSPECTED" for f in ipc_findings)
    platform_items.append({
        "id": "MASVS-PLATFORM-2",
        "title": "حظر إعادة توجيه النوايا غير الموثوقة (Intent Redirection)",
        "status": "FAIL" if has_intent_redir else "PASS",
        "description": "تم رصد دوال تعيد تمرير نوايا Intent خارجية لمكونات أخرى." if has_intent_redir else "لا توجد مؤشرات على ثغرات إعادة توجيه النوايا."
    })

    # 6. MASVS-CODE
    code_items = []
    # وضع التصحيح
    is_debuggable = manifest_flags.get("debuggable", False)
    code_items.append({
        "id": "MASVS-CODE-1",
        "title": "تعطيل وضع التصحيح في حزمة الإنتاج (android:debuggable=false)",
        "status": "FAIL" if is_debuggable else "PASS",
        "description": "وضع التصحيح مفعل صراحة في المانيفست (debuggable=true)." if is_debuggable else "وضع التصحيح معطل بنجاح (حزمة إنتاج آمنة)."
    })
    # فحص حماية المكتبات الثنائية الأصلية (NX / Canary / PIE)
    native_summary = native_libs.get("summary", {}) if native_libs else {}
    vuln_canary = native_summary.get("without_canary_count", 0) > 0
    code_items.append({
        "id": "MASVS-CODE-2",
        "title": "تفعيل دروع حماية الذاكرة للمكتبات الأصلية C/C++ (Stack Canary & PIE)",
        "status": "FAIL" if vuln_canary else "PASS",
        "description": "توجد مكتبات C/C++ تفتقر لمراقب المكدس Stack Canary." if vuln_canary else "كافة المكتبات الأصلية مجمعة بدروع حماية الذاكرة المتقدمة."
    })

    # 7. MASVS-RESILIENCE
    resilience_items = []
    # كشف الروت والمحاكيات
    root_det = app_defenses.get("root_detection", {}) if app_defenses else {}
    has_root = root_det.get("detected", False)
    resilience_items.append({
        "id": "MASVS-RESILIENCE-1",
        "title": "وجود آليات لكشف كسر الحماية (Root Detection)",
        "status": "PASS" if has_root else "WARN",
        "description": "تم رصد آليات برمجية لكشف أجهزة الروت." if has_root else "لا يحتوي التطبيق على آليات صريحة لكشف كسر الحماية (الروت)."
    })
    # فحص التلاعب وإعادة الحزم عبر Google Play
    is_repackaged = playstore_audit.get("is_likely_repackaged", False) if playstore_audit else False
    resilience_items.append({
        "id": "MASVS-RESILIENCE-2",
        "title": "سلامة التوقيع الرقمي ومطابقة النسخة الرسمية على Google Play",
        "status": "FAIL" if is_repackaged else "PASS",
        "description": "الحزمة مشبوهة وتتعارض مع التوقيع الرسمي للتطبيق على متجر Google Play!" if is_repackaged else "التطبيق موقع وموثق دون تعارضات إعادة حزم."
    })

    all_cat_specs = [
        ("MASVS-STORAGE", "أمان التخزين وحماية البيانات (Data Storage)", storage_items),
        ("MASVS-CRYPTO", "أمان التشفير والمفاتيح الرقمية (Cryptography)", crypto_items),
        ("MASVS-AUTH", "المصادقة وإدارة الجلسات (Authentication)", auth_items),
        ("MASVS-NETWORK", "أمان اتصالات الشبكة (Network Communication)", network_items),
        ("MASVS-PLATFORM", "التفاعل مع المنصة والمكونات (Platform Interaction)", platform_items),
        ("MASVS-CODE", "جودة الكود وإعدادات البناء (Code Quality & Build)", code_items),
        ("MASVS-RESILIENCE", "مقاومة التلاعب والتنقيح (Resilience & Tamper)", resilience_items),
    ]

    total_tests = 0
    total_passed = 0

    for cat_id, cat_title, items in all_cat_specs:
        passed = sum(1 for it in items if it["status"] == "PASS")
        failed = sum(1 for it in items if it["status"] == "FAIL")
        warned = sum(1 for it in items if it["status"] == "WARN")
        t_count = len(items)
        score_pct = int((passed / t_count) * 100) if t_count > 0 else 100

        total_tests += t_count
        total_passed += passed

        categories.append({
            "category_id": cat_id,
            "title": cat_title,
            "score_percent": score_pct,
            "status": "FAIL" if failed > 0 else ("WARN" if warned > 0 else "PASS"),
            "passed_count": passed,
            "failed_count": failed,
            "warned_count": warned,
            "checklist": items
        })

    overall_score = int((total_passed / total_tests) * 100) if total_tests > 0 else 0
    compliance_level = "MASVS-L1 COMPLIANT" if overall_score >= 80 else ("NEEDS HARDENING" if overall_score >= 50 else "HIGH RISK")

    return {
        "overall_score": overall_score,
        "compliance_level": compliance_level,
        "total_tests": total_tests,
        "total_passed": total_passed,
        "total_failed": total_tests - total_passed,
        "categories": categories
    }
