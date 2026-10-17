#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apk_inspector.py - المحرك الرئيسي لفحص وتدقيق حزم أندرويد ومقارنة النسخ (APK Inspector & Diff Engine)
نسخة مخصصة لمشروع AdbLite - خالية تماماً من تبعيات المتاجر أو قواعد البيانات الخارجية.
يدعم كشف الأسرار المسربة، استخراج المانيفست، وتصدير الموارد، والبحث في الـ DEX.
"""

import os
import sys
import json
import argparse
import io
import traceback
import tempfile
import zipfile
from pathlib import Path

# ضبط مخرجات الطرفية لدعم UTF-8 بشكل صحيح
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# إضافة المسار الحالي لبيئة بايثون
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

# إضافة مسار androguard إن كان متوفراً محلياً
LOCAL_ANDROGUARD = os.path.join(CURRENT_DIR, "androguard")
if os.path.exists(LOCAL_ANDROGUARD) and CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    from androguard.core.analysis import analysis
except ImportError as e:
    output = {
        "status": "error",
        "error_type": "IMPORT_ERROR",
        "message": f"تعذر استيراد مكتبة Androguard: {str(e)}. يرجى التأكد من توفر المكتبة في البيئة."
    }
    print(json.dumps(output, ensure_ascii=False))
    sys.exit(1)

from info_extractor import InfoExtractor
from security_analyzer import SecurityAnalyzer
from network_analyzer import NetworkAnalyzer
from development_analyzer import DevelopmentAnalyzer
from secrets_analyzer import SecretsAnalyzer
from report_generator import ReportGenerator
try:
    from sbom_analyzer import extract_sbom
except ImportError:
    extract_sbom = lambda apk: {"total_dependencies": 0, "versioned_libraries": [], "packages_detected": []}

# تعطيل رسائل DEBUG الكثيفة من loguru و androguard
try:
    from loguru import logger
    logger.remove()
    logger.add(sys.stderr, level="ERROR")
except Exception:
    pass

def resolve_apk_target(apk_path: str):
    """
    إذا كان الملف عبارة عن حزمة APKS أو XAPK أو APKM أو ZIP مقسم،
    يتم استخراج base.apk تلقائياً لفحصه مع الحفاظ على مسار الملف الأصلي.
    """
    if not os.path.exists(apk_path):
        return apk_path, None

    lower_name = apk_path.lower()
    if lower_name.endswith((".apks", ".xapk", ".apkm", ".zip")) or zipfile.is_zipfile(apk_path):
        try:
            with zipfile.ZipFile(apk_path, "r") as z:
                names = z.namelist()
                # إذا كان APK عادي في الأصل (يحتوي على AndroidManifest.xml في الجذر)، اتركه كما هو
                if "AndroidManifest.xml" in names:
                    return apk_path, None

                # البحث عن الحزمة الأساسية base.apk أو splits/base-master.apk
                candidates = [n for n in names if n == "base.apk" or n.endswith("/base.apk") or n.endswith("base-master.apk")]
                if not candidates:
                    candidates = [n for n in names if n.endswith(".apk")]

                if candidates:
                    target_entry = candidates[0]
                    temp_dir = tempfile.mkdtemp(prefix="sabr_split_")
                    extracted_path = z.extract(target_entry, temp_dir)
                    return extracted_path, temp_dir
        except Exception:
            pass

    return apk_path, None

def sanitize_for_json(obj):
    """تحويل أي كائن غير قابل للتسلسل مثل bytes إلى نص أو كائن متوافق مع JSON."""
    if isinstance(obj, (bytes, bytearray)):
        return obj.decode("utf-8", errors="replace")
    elif isinstance(obj, dict):
        return {str(k): sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple, set)):
        return [sanitize_for_json(item) for item in obj]
    elif hasattr(obj, "__dict__"):
        return sanitize_for_json(obj.__dict__)
    return obj

def run_inspection(apk_path: str, icon_dir: str = None) -> dict:
    """تنفيذ فحص كامل لملف الـ APK وإرجاع قاموس النتائج."""
    if not os.path.exists(apk_path):
        return {
            "status": "error",
            "error_type": "FILE_NOT_FOUND",
            "message": f"ملف الـ APK غير موجود: {apk_path}"
        }

    actual_apk_path, temp_split_dir = resolve_apk_target(apk_path)

    try:
        a = APK(actual_apk_path)
        dx_data = a.get_dex()
        anydx = analysis.Analysis()
        if dx_data:
            anydx.add(DEX(dx_data))

        if not icon_dir:
            icon_dir = os.path.join(CURRENT_DIR, "temp_icons")

        info_ext = InfoExtractor(a)
        sec_an = SecurityAnalyzer(a, anydx)
        net_an = NetworkAnalyzer(anydx, apk=a)
        dev_an = DevelopmentAnalyzer(a, anydx)
        secrets_an = SecretsAnalyzer(a, anydx)

        basic_info = info_ext.get_basic_info(apk_path)
        hashes = info_ext.calculate_hashes(apk_path)
        components = info_ext.get_components_info()
        icon_path = info_ext.extract_main_icon(icon_dir)
        manifest_xml = info_ext.get_manifest_xml()
        resources_summary = info_ext.get_resources_summary()

        # التدقيق العميق لمكونات المانيفست المكشوفة وسمات الأمان
        manifest_audit = sec_an.audit_components()
        manifest_security = sec_an.audit_manifest_security_flags()

        # كشف آليات الدفاع والتلاعب
        app_defenses = sec_an.detect_app_defenses()

        # تدقيق الروابط العميقة (Deep Links)
        deep_links = sec_an.audit_deep_links()

        # فحص المكتبات الأصلية C/C++ (.so)
        native_libs = sec_an.analyze_native_libraries()

        # فحص التوقيع والشهادات وثغرة Janus والـ Keystores المسربة
        permissions = sec_an.get_permissions_info()
        signatures = sec_an.get_signature_info()
        janus_info = sec_an.check_janus_vulnerability()
        debug_cert_info = sec_an.check_debug_certificate()
        leaked_keystores = sec_an.scan_leaked_keystores()

        # فحص تسريب المفاتيح والأسرار والإنتروبيا العشوائية
        leaked_secrets = secrets_an.scan()

        network_urls = net_an.analyze_urls()
        all_raw_urls = net_an.extract_urls()
        ip_addresses = net_an.extract_ip_addresses()
        interesting_strings = net_an.get_interesting_strings()
        network_calls = net_an.analyze_network_calls()
        network_security_config = net_an.audit_network_security_config()

        # 1. كشف وتدقيق قواعد بيانات Firebase المفتوحة (Open Firebase Database Auditor)
        try:
            from firebase_analyzer import audit_firebase_databases
            firebase_audit = audit_firebase_databases(all_raw_urls)
        except Exception as e:
            firebase_audit = {
                "has_firebase_db": False,
                "total_databases": 0,
                "open_databases_count": 0,
                "open_databases": [],
                "secure_databases": [],
                "error": str(e)
            }

        # 2. كشف التطبيقات المستنسخة والملغمة بمطابقة Google Play (Play Store Clone & Repackage Detector)
        try:
            from playstore_verifier import verify_playstore_package
            is_debug_signed = bool(debug_cert_info and debug_cert_info.get("is_debug_signed", False))
            playstore_audit = verify_playstore_package(
                package_name=basic_info.get("package_name"),
                app_name=basic_info.get("app_name"),
                is_debug_signed=is_debug_signed
            )
        except Exception as e:
            playstore_audit = {
                "checked": False,
                "exists_on_play_store": False,
                "error": str(e)
            }

        basic_info["playstore"] = playstore_audit

        # 3. تدقيق أخطاء تكوين التشفير البرمجي وخوارزميات التشفير الضعيفة
        try:
            from crypto_audit import CryptoAuditor
            crypto_audit = CryptoAuditor(a, anydx).audit()
        except Exception as e:
            crypto_audit = {"has_crypto_issues": False, "total_issues": 0, "findings": [], "error": str(e)}

        # 4. تدقيق أمان الـ WebView وثغرات الـ JavaScript Bridge
        try:
            from webview_analyzer import WebViewAuditor
            webview_audit = WebViewAuditor(a, anydx).audit()
        except Exception as e:
            webview_audit = {"has_webview": False, "total_issues": 0, "findings": [], "error": str(e)}

        # 5. تدقيق المستودعات السحابية المفتوحة (Cloud Storage Buckets)
        try:
            from cloud_bucket_analyzer import audit_cloud_buckets
            cloud_bucket_audit = audit_cloud_buckets(all_raw_urls)
        except Exception as e:
            cloud_bucket_audit = {"has_cloud_buckets": False, "total_buckets": 0, "open_buckets_count": 0, "open_buckets": [], "secure_buckets": [], "error": str(e)}

        # 6. كشف ثغرات أمن المكونات البينية (IPC & Intent Redirection / FileProvider Path Traversal)
        try:
            from ipc_analyzer import IpcAuditor
            ipc_audit = IpcAuditor(a, anydx).audit()
        except Exception as e:
            ipc_audit = {"total_issues": 0, "findings": [], "file_provider_paths": [], "error": str(e)}

        sensitive_methods = sec_an.get_sensitive_methods()
        vulnerabilities = sec_an.get_vulnerabilities()
        is_blacklisted = sec_an.check_blacklist()
        risk_assessment = sec_an.calculate_risk_assessment(
            permissions,
            sensitive_methods,
            is_blacklisted,
            janus_info,
            debug_cert_info,
            leaked_keystores,
            manifest_audit,
            manifest_security,
            playstore_info=playstore_audit,
            firebase_audit=firebase_audit,
            crypto_audit=crypto_audit,
            webview_audit=webview_audit,
            cloud_bucket_audit=cloud_bucket_audit,
            ipc_audit=ipc_audit
        )

        # 7. مصفوفة التوافق مع المعيار العالمي OWASP MASVS & MASTG
        try:
            from owasp_matrix import generate_owasp_compliance_matrix
            owasp_compliance = generate_owasp_compliance_matrix(
                manifest_security=manifest_security,
                signatures=signatures,
                crypto_audit=crypto_audit,
                webview_audit=webview_audit,
                network_audit={"security_config": network_security_config},
                firebase_audit=firebase_audit,
                cloud_bucket_audit=cloud_bucket_audit,
                manifest_audit=manifest_audit,
                native_libs=native_libs,
                app_defenses=app_defenses,
                playstore_audit=playstore_audit,
                secrets=leaked_secrets,
                leaked_keystores=leaked_keystores,
                ipc_audit=ipc_audit
            )
        except Exception as e:
            owasp_compliance = {"overall_score": 0, "compliance_level": "ERROR", "categories": [], "error": str(e)}

        dev_languages = dev_an.detect_languages_and_frameworks()
        ads_info = dev_an.check_ads_libraries()
        known_libs = dev_an.detect_known_libraries()
        exodus_trackers = dev_an.detect_exodus_trackers(urls=all_raw_urls)
        sbom_info = extract_sbom(a)

        # الكشف المعماري الشامل (Architecture & Tech Stack)
        architecture_profile = dev_an.detect_architecture_profile()

        # استنتاج تصنيف وفئة التطبيق (Inferred App Category)
        category_res = dev_an.infer_app_category(
            permissions=permissions.get("all_permissions", []),
            activities=components.get("activities", [])
        )

        # استخراج نوع الأجهزة والمنصات المستهدفة (Target Form Factors)
        form_factors = info_ext.get_target_form_factors()

        # استخراج مصفوفة عتاد الأجهزة وشاشات العرض (<uses-feature> & Hardware Matrix)
        hardware_matrix = info_ext.get_hardware_and_screens_matrix()

        # استخراج اللغات والتحقق من التوطين واللغة العربية (Localization Audit)
        localization_info = info_ext.get_localization_info()

        # استخراج الأيقونات بكافة الكثافات بصيغة WebP و PNG
        multi_dpi_icons = info_ext.extract_all_icons(icon_dir)

        # توليد الملخص التنفيذي البشري (Executive Summary)
        min_sdk_val = basic_info.get("sdk_versions", {}).get("min", 0)
        min_sdk_str = f"Android {min_sdk_val}" if min_sdk_val > 0 else "Android"
        summary_res = dev_an.generate_natural_summary(
            app_name=basic_info.get("app_name", ""),
            permissions=permissions.get("all_permissions", []),
            features=components.get("features", []),
            has_ads=ads_info.get("has_ads", False),
            min_sdk_name=min_sdk_str,
            inferred_category=category_res.get("inferred_category", "Tools")
        )

        basic_info["inferred_category"] = category_res.get("inferred_category", "Tools")
        basic_info["category_confidence"] = category_res.get("confidence_score", 0)
        basic_info["natural_summary"] = summary_res.get("summary_en", "")
        basic_info["natural_summary_ar"] = summary_res.get("summary_ar", "")
        basic_info["capability_highlights"] = summary_res.get("highlights_en", [])
        basic_info["capability_highlights_ar"] = summary_res.get("highlights_ar", [])
        basic_info["form_factors"] = form_factors
        basic_info["hardware_matrix"] = hardware_matrix

        resources_summary["localization"] = localization_info
        resources_summary["multi_dpi_icons"] = multi_dpi_icons

        return sanitize_for_json({
            "status": "success",
            "apk_path": apk_path,
            "basic_info": basic_info,
            "hardware_matrix": hardware_matrix,
            "hashes": hashes,
            "components": components,
            "manifest_audit": manifest_audit,
            "manifest_security": manifest_security,
            "app_defenses": app_defenses,
            "deep_links": deep_links,
            "native_libraries": native_libs,
            "sbom": sbom_info,
            "manifest_xml": manifest_xml,
            "resources_summary": resources_summary,
            "secrets": leaked_secrets,
            "permissions": permissions,
            "owasp": owasp_compliance,
            "cloud_buckets": cloud_bucket_audit,
            "security": {
                "is_blacklisted": is_blacklisted,
                "signatures": signatures,
                "janus_vulnerability": janus_info,
                "debug_certificate": debug_cert_info,
                "leaked_keystores": leaked_keystores,
                "playstore_audit": playstore_audit,
                "crypto_audit": crypto_audit,
                "webview_audit": webview_audit,
                "ipc_audit": ipc_audit,
                "owasp_compliance": owasp_compliance,
                "sensitive_methods_count": len(sensitive_methods),
                "sensitive_methods_sample": sensitive_methods[:30],
                "vulnerabilities": vulnerabilities,
                "manifest_security": manifest_security,
                "app_defenses": app_defenses,
                "deep_links": deep_links,
                "native_libraries": native_libs,
                "risk_assessment": risk_assessment
            },
            "network": {
                "urls": network_urls,
                "ip_addresses": ip_addresses,
                "interesting_strings": interesting_strings,
                "network_calls": network_calls,
                "security_config": network_security_config,
                "firebase_audit": firebase_audit,
                "cloud_bucket_audit": cloud_bucket_audit
            },
            "development": {
                "languages_frameworks": dev_languages,
                "architecture": architecture_profile,
                "ads": ads_info,
                "exodus_trackers": exodus_trackers,
                "known_libraries": known_libs
            },
            "icon_path": icon_path or ""
        })

    except Exception as e:
        return {
            "status": "error",
            "error_type": "ANALYSIS_FAILED",
            "message": str(e),
            "traceback": traceback.format_exc()
        }

def run_diff(old_apk: str, new_apk: str) -> dict:
    """مقارنة نسختين من التطبيق (APK Diff) لكشف التغييرات والتلاعب الأمني."""
    old_res = run_inspection(old_apk)
    if old_res.get("status") != "success":
        return {"status": "error", "message": f"فشل فحص النسخة السابقة: {old_res.get('message')}"}

    new_res = run_inspection(new_apk)
    if new_res.get("status") != "success":
        return {"status": "error", "message": f"فشل فحص النسخة الجديدة: {new_res.get('message')}"}

    old_basic = old_res.get("basic_info", {})
    new_basic = new_res.get("basic_info", {})

    old_perms = set(old_res.get("permissions", {}).get("all_permissions", []))
    new_perms = set(new_res.get("permissions", {}).get("all_permissions", []))

    old_dangerous = set(old_res.get("permissions", {}).get("dangerous_permissions", []))
    new_dangerous = set(new_res.get("permissions", {}).get("dangerous_permissions", []))

    # التحقق الحرج من التوقيع الرقمي (هل تم إعادة حزم التطبيق بمفتاح مختلف؟)
    old_certs = old_res.get("security", {}).get("signatures", {}).get("certificates", [])
    new_certs = new_res.get("security", {}).get("signatures", {}).get("certificates", [])

    old_sha256 = {c.get("sha256") for c in old_certs if c.get("sha256")}
    new_sha256 = {c.get("sha256") for c in new_certs if c.get("sha256")}
    signature_changed = bool(old_sha256 and new_sha256 and old_sha256 != new_sha256)

    # شبكات الإعلانات
    old_ads = set(old_res.get("development", {}).get("ads", {}).get("detected_networks", []))
    new_ads = set(new_res.get("development", {}).get("ads", {}).get("detected_networks", []))

    # الروابط الجديدة
    old_urls = set(old_res.get("network", {}).get("urls", {}).get("other_urls", []))
    new_urls = set(new_res.get("network", {}).get("urls", {}).get("other_urls", []))

    return {
        "status": "success",
        "old_package": old_basic.get("package_name"),
        "new_package": new_basic.get("package_name"),
        "old_version": old_basic.get("version", {}).get("name"),
        "new_version": new_basic.get("version", {}).get("name"),
        "old_version_code": old_basic.get("version", {}).get("code"),
        "new_version_code": new_basic.get("version", {}).get("code"),
        "size_diff_mb": round(new_basic.get("size_mb", 0) - old_basic.get("size_mb", 0), 2),
        "signature_changed": signature_changed,
        "permissions_added": sorted(list(new_perms - old_perms)),
        "permissions_removed": sorted(list(old_perms - new_perms)),
        "dangerous_permissions_added": sorted(list(new_dangerous - old_dangerous)),
        "dangerous_permissions_removed": sorted(list(old_dangerous - new_dangerous)),
        "ads_added": sorted(list(new_ads - old_ads)),
        "ads_removed": sorted(list(old_ads - new_ads)),
        "new_urls_added": sorted(list(new_urls - old_urls)),
        "old_risk": old_res.get("security", {}).get("risk_assessment", {}),
        "new_risk": new_res.get("security", {}).get("risk_assessment", {})
    }

def main():
    parser = argparse.ArgumentParser(
        description="أداة فحص وتدقيق تطبيقات أندرويد لـ AdbLite (APK Inspector & Diff)",
        usage="%(prog)s [apk_path] [options]"
    )
    parser.add_argument("apk_path", type=str, nargs="?", help="مسار ملف الـ APK المراد فحصه")
    parser.add_argument("--diff", nargs=2, metavar=("OLD_APK", "NEW_APK"), help="مقارنة نسختين من التطبيق")
    parser.add_argument("-o", "--output", type=str, default=None, help="مسار ملف JSON لحفظ النتائج فيه")
    parser.add_argument("--export-html", type=str, default=None, help="تصدير تقرير HTML أوفلاين تفاعلي")
    parser.add_argument("--export-md", type=str, default=None, help="تصدير تقرير Markdown موثق")
    parser.add_argument("--export-sql", type=str, default=None, help="تصدير بيانات الفحص كملف SQL لمستودعات ومتاجر التطبيقات")
    parser.add_argument("--export-bundle", type=str, default=None, help="تصدير حزمة نشر المتجر المتكاملة كملف ZIP مضغوط")
    parser.add_argument("--export-all-icons", type=str, default=None, help="تصدير حزمة الأيقونات بكافة الدقات إلى مجلد محدد")
    parser.add_argument("--export-awm-sql", type=str, default=None, help="تصدير استعلامات SQL لمخطط متجر AwmStore")
    parser.add_argument("--export-awm-store", type=str, default=None, help="تصدير حزمة متجر AwmStore المتكاملة (مجلد أو أرشيف ZIP)")
    parser.add_argument("--export-resources", type=str, default=None, help="تصدير الأيقونات والموارد إلى مجلد محلي")
    parser.add_argument("--search-dex", type=str, default=None, help="البحث في كلاسات ودوال الـ DEX")
    parser.add_argument("--decompile-class", type=str, default=None, help="اسم الكلاس المراد تفكيكه واستخراج كوده المصدري")
    parser.add_argument("--format", choices=["java", "smali"], default="java", help="صيغة الكود المطلوب (java أو smali)")
    parser.add_argument("--manifest", action="store_true", help="استخراج وعرض ملف AndroidManifest.xml فقط")
    parser.add_argument("--icon-dir", type=str, default=None, help="مجلد حفظ الأيقونة المستخرجة")

    args = parser.parse_args()

    # 1. وضع المقارنة بين نسختين
    if args.diff:
        result = run_diff(args.diff[0], args.diff[1])
        if args.output:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(result, f, ensure_ascii=False, indent=2)
            except Exception as e:
                sys.stderr.write(f"خطأ أثناء حفظ التقرير: {str(e)}\n")
        print(json.dumps(result, ensure_ascii=False))
        return

    if not args.apk_path:
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(args.apk_path):
        print(json.dumps({"status": "error", "message": f"ملف غير موجود: {args.apk_path}"}, ensure_ascii=False))
        sys.exit(1)

    target_apk, _ = resolve_apk_target(args.apk_path)

    # 2. فحص سريع للمانيفست فقط إن طُلب
    if args.manifest:
        try:
            a = APK(target_apk)
            info = InfoExtractor(a)
            manifest = info.get_manifest_xml()
            print(json.dumps({"status": "success", "manifest_xml": manifest}, ensure_ascii=False))
            return
        except Exception as e:
            print(json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False))
            sys.exit(1)

    # 3. تصدير الموارد والأيقونات فقط إن طُلب
    if args.export_resources:
        try:
            a = APK(target_apk)
            info = InfoExtractor(a)
            count = info.export_resources(args.export_resources)
            print(json.dumps({"status": "success", "exported_count": count, "output_dir": args.export_resources}, ensure_ascii=False))
            return
        except Exception as e:
            print(json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False))
            sys.exit(1)

    # 3.1 تصدير حزمة الأيقونات بكافة الكثافات بصيغة WebP/PNG
    if args.export_all_icons:
        try:
            a = APK(target_apk)
            info = InfoExtractor(a)
            icons = info.extract_all_icons(args.export_all_icons)
            print(json.dumps({"status": "success", "icons": icons, "output_dir": args.export_all_icons}, ensure_ascii=False))
            return
        except Exception as e:
            print(json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False))
            sys.exit(1)

    # 4. البحث في كلاسات ودوال DEX إن طُلب
    if args.search_dex:
        try:
            a = APK(target_apk)
            dx_data = a.get_dex()
            anydx = analysis.Analysis()
            if dx_data:
                anydx.add(DEX(dx_data))
            info = InfoExtractor(a)
            matches = info.search_dex_symbols(anydx, args.search_dex)
            print(json.dumps({"status": "success", "query": args.search_dex, "matches": matches}, ensure_ascii=False))
            return
        except Exception as e:
            print(json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False))
            sys.exit(1)

    # 5. تفكيك كلاس معين إن طُلب
    if args.decompile_class:
        try:
            from decompiler_service import DecompilerService
            decompiler = DecompilerService()
            decompiler.load_apk(target_apk)
            res = decompiler.decompile_class(args.decompile_class, args.format)
            print(json.dumps(res, ensure_ascii=False))
            return
        except Exception as e:
            print(json.dumps({"status": "error", "message": str(e), "traceback": traceback.format_exc()}, ensure_ascii=False))
            sys.exit(1)

    # 6. الفحص الكامل
    result = run_inspection(args.apk_path, args.icon_dir)

    # تصدير التقارير إن طُلب
    if result.get("status") == "success":
        report_gen = ReportGenerator(result)
        if args.export_html:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(args.export_html)), exist_ok=True)
                with open(args.export_html, "w", encoding="utf-8") as f:
                    f.write(report_gen.generate_html())
            except Exception as e:
                sys.stderr.write(f"خطأ أثناء تصدير HTML: {str(e)}\n")

        if args.export_md:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(args.export_md)), exist_ok=True)
                with open(args.export_md, "w", encoding="utf-8") as f:
                    f.write(report_gen.generate_markdown())
            except Exception as e:
                sys.stderr.write(f"خطأ أثناء تصدير Markdown: {str(e)}\n")

        if args.export_sql:
            try:
                from sql_generator import StoreSqlGenerator
                sql_gen = StoreSqlGenerator()
                sql_gen.generate_catalog_sql(result, args.export_sql)
            except Exception as e:
                sys.stderr.write(f"خطأ أثناء تصدير SQL: {str(e)}\n")

        if args.export_bundle:
            try:
                from bundle_generator import StoreBundleGenerator
                bundle_gen = StoreBundleGenerator()
                bundle_gen.generate_bundle(result, target_apk, args.export_bundle)
            except Exception as e:
                sys.stderr.write(f"خطأ أثناء تصدير حزمة المتجر: {str(e)}\n")

        if args.export_awm_sql:
            try:
                from awm_store_exporter import AwmStoreExporter
                awm_gen = AwmStoreExporter()
                awm_gen.export_sql(result, target_apk, args.export_awm_sql)
            except Exception as e:
                sys.stderr.write(f"خطأ أثناء تصدير AwmStore SQL: {str(e)}\n")

        if args.export_awm_store:
            try:
                from awm_store_exporter import AwmStoreExporter
                awm_gen = AwmStoreExporter()
                awm_gen.export_package(result, target_apk, args.export_awm_store)
            except Exception as e:
                sys.stderr.write(f"خطأ أثناء تصدير حزمة متجر AwmStore: {str(e)}\n")

    if args.output:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            sys.stderr.write(f"خطأ أثناء حفظ التقرير: {str(e)}\n")

    print(json.dumps(result, ensure_ascii=False, default=str))

if __name__ == "__main__":
    main()
