# bundle_generator.py
# -*- coding: utf-8 -*-
"""
bundle_generator.py - مولد حزمة نشر المتجر المتكاملة (Store Asset Packaging & ZIP Export)
يقوم بإنشاء ملف مضغوط .zip يحتوي على:
1. app_catalog.sql: ملف استعلامات SQL لإدراج التطبيق في قاعدة البيانات.
2. metadata.json: بيانات وصفية مهيكلة متوافقة مع معايير F-Droid و Google Play API.
3. icons/: مجلد يحتوي على أيقونات التطبيق بدقاتها المتعددة (Multi-DPI).
4. README.txt: ملخص التطبيق، البصمات التشفيرية، ومتطلبات العتاد.
"""

import os
import io
import json
import zipfile
import tempfile
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

from sql_generator import StoreSqlGenerator

class StoreBundleGenerator:
    def __init__(self, db_name: str = "sabr_app_catalog"):
        self.sql_gen = StoreSqlGenerator(db_name=db_name)

    def generate_bundle(self, inspection: Dict[str, Any], apk_path: str, output_zip_path: str) -> str:
        """
        توليد حزمة المتجر وتصديرها كملف ZIP متكامل.
        """
        basic = inspection.get("basic_info", {})
        hashes = inspection.get("hashes", {})
        security = inspection.get("security", {})
        dev = inspection.get("development", {})
        perms = inspection.get("permissions", {})
        comps = inspection.get("components", {})
        resources = inspection.get("resources_summary", {})
        localization = resources.get("localization", {})
        risk = security.get("risk_assessment", {})
        hw_matrix = inspection.get("hardware_matrix") or basic.get("hardware_matrix", {})

        pkg_name = basic.get("package_name", "unknown")
        app_name = basic.get("app_name", pkg_name)
        ver_code = basic.get("version", {}).get("code", 0)
        ver_name = basic.get("version", {}).get("name", "unknown")
        min_sdk = basic.get("sdk_versions", {}).get("min", 0)
        target_sdk = basic.get("sdk_versions", {}).get("target", 0)
        size_mb = basic.get("size_mb", 0.0)
        category = basic.get("inferred_category", "Tools")
        natural_summary = basic.get("natural_summary", "")
        natural_summary_ar = basic.get("natural_summary_ar", "")
        highlights = basic.get("capability_highlights", [])
        highlights_ar = basic.get("capability_highlights_ar", [])

        sha256 = hashes.get("sha256", "")
        sha1 = hashes.get("sha1", "")
        md5 = hashes.get("md5", "")

        risk_level = risk.get("risk_level", "LOW")
        risk_score = risk.get("risk_score", 0)

        default_lang = localization.get("default_language", "en")
        supported_locales = localization.get("supported_locales", [])

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # التأكد من وجود المجلد المخرج
        os.makedirs(os.path.dirname(os.path.abspath(output_zip_path)), exist_ok=True)

        with tempfile.TemporaryDirectory(prefix="sabr_bundle_") as temp_dir:
            # 1. توليد سكربت SQL
            sql_script = self.sql_gen.generate_catalog_sql(inspection)
            sql_file = os.path.join(temp_dir, "app_catalog.sql")
            with open(sql_file, "w", encoding="utf-8") as f:
                f.write(sql_script)

            # 2. توليد metadata.json
            metadata = {
                "package_name": pkg_name,
                "app_name": app_name,
                "version_code": ver_code,
                "version_name": ver_name,
                "min_sdk": min_sdk,
                "target_sdk": target_sdk,
                "size_mb": size_mb,
                "category": category,
                "default_language": default_lang,
                "supported_locales": supported_locales,
                "summary": natural_summary,
                "summary_ar": natural_summary_ar,
                "capability_highlights": highlights,
                "capability_highlights_ar": highlights_ar,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "hashes": {
                    "sha256": sha256,
                    "sha1": sha1,
                    "md5": md5
                },
                "hardware_matrix": hw_matrix,
                "screens": hw_matrix.get("screens", {
                    "small_screens": True,
                    "normal_screens": True,
                    "large_screens": True,
                    "xlarge_screens": True,
                    "any_density": True,
                    "resizeable": True
                }),
                "permissions": {
                    "all": perms.get("all_permissions", []),
                    "dangerous": perms.get("dangerous_permissions", [])
                },
                "components": {
                    "activities_count": len(comps.get("activities", [])),
                    "services_count": len(comps.get("services", [])),
                    "receivers_count": len(comps.get("receivers", [])),
                    "providers_count": len(comps.get("providers", []))
                },
                "trackers": dev.get("exodus_trackers", {}).get("trackers", []),
                "exported_at": now_str,
                "generator": "Sabr Android Security & Store Studio"
            }

            metadata_file = os.path.join(temp_dir, "metadata.json")
            with open(metadata_file, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)

            # 3. تجهيز مجلد الأيقونات بدقاتها المتعددة
            icons_dir = os.path.join(temp_dir, "icons")
            os.makedirs(icons_dir, exist_ok=True)

            # استخراج الأيقونات إذا كان مسار APK صالحاً
            multi_icons = resources.get("multi_dpi_icons")
            if not multi_icons and apk_path and os.path.exists(apk_path):
                try:
                    from androguard.core.apk import APK
                    from info_extractor import InfoExtractor
                    ext = InfoExtractor(APK(apk_path))
                    multi_icons = ext.extract_all_icons(icons_dir)
                except Exception:
                    multi_icons = {}

            # نسخ الأيقونات المستخرجة
            if multi_icons:
                for dpi_label, icon_src in multi_icons.items():
                    if icon_src and os.path.exists(icon_src):
                        ext_name = os.path.splitext(icon_src)[1]
                        dest_icon = os.path.join(icons_dir, f"icon_{dpi_label}{ext_name}")
                        if icon_src != dest_icon:
                            try:
                                import shutil
                                shutil.copy2(icon_src, dest_icon)
                            except Exception:
                                pass

            # نسخ الأيقونة الرئيسية إذا وجدت
            main_icon = inspection.get("icon_path")
            if main_icon and os.path.exists(main_icon):
                try:
                    import shutil
                    shutil.copy2(main_icon, os.path.join(icons_dir, "icon_main.png"))
                except Exception:
                    pass

            # 4. توليد README.txt
            cam_req = "Required" if hw_matrix.get("is_camera_required") else ("Optional" if hw_matrix.get("has_camera") else "None")
            readme_text = f"""===========================================================================
سَبْر (Sabr) - حزمة نشر المستودع والمتجر المتكاملة (Store Publishing Bundle)
===========================================================================
Application Name : {app_name}
Package Name     : {pkg_name}
Version          : {ver_name} (Code: {ver_code})
Size             : {size_mb} MB
Target Android   : API {target_sdk} (Min: API {min_sdk})
Category         : {category}
Default Language : {default_lang}
Risk Assessment  : {risk_level} (Score: {risk_score}/100)

Cryptographic Hashes:
- SHA-256 : {sha256}
- SHA-1   : {sha1}
- MD5     : {md5}

Hardware & Device Requirements:
- Camera     : {cam_req}
- Biometrics : {'Supported' if hw_matrix.get('has_biometrics') else 'None'}
- NFC        : {'Supported' if hw_matrix.get('has_nfc') else 'None'}
- Bluetooth  : {'Supported' if hw_matrix.get('has_bluetooth') else 'None'}
- GPS/Loc    : {'Supported' if hw_matrix.get('has_gps') else 'None'}
- Telephony  : {'Supported' if hw_matrix.get('has_telephony') else 'None'}
- Microphone : {'Supported' if hw_matrix.get('has_microphone') else 'None'}

Archive Contents:
1. app_catalog.sql - Ready-to-import database catalog SQL script
2. metadata.json   - Full F-Droid & Google Play compatible metadata
3. icons/          - Multi-DPI app icons (main, hdpi, xhdpi, xxhdpi, etc.)
4. README.txt      - This summary manifest

Generated on: {now_str}
By: Sabr Android Security & Store Studio
===========================================================================
"""
            readme_file = os.path.join(temp_dir, "README.txt")
            with open(readme_file, "w", encoding="utf-8") as f:
                f.write(readme_text)

            # 5. ضغط كافة الملفات في أرشيف ZIP
            with zipfile.ZipFile(output_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(sql_file, "app_catalog.sql")
                zipf.write(metadata_file, "metadata.json")
                zipf.write(readme_file, "README.txt")

                for root, _, files in os.walk(icons_dir):
                    for file in files:
                        full_p = os.path.join(root, file)
                        rel_p = os.path.relpath(full_p, temp_dir)
                        zipf.write(full_p, rel_p)

        return output_zip_path
