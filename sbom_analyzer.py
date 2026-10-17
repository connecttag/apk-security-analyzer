# -*- coding: utf-8 -*-
"""
sbom_analyzer.py - محلل قائمة مكونات البرمجيات (Software Bill of Materials - SBOM) لحزم أندرويد
يستخرج إصدارات المكتبات والاعتماديات بدقة فائقة من ملفات META-INF/*.version والملفات الوصفية،
على غرار منهجية MobSF في استخراج شجرة المكونات والتبعيات البرمجية.
"""

from typing import Dict, List, Any, Optional

def extract_sbom(apk) -> Dict[str, Any]:
    """
    استخراج شجرة مكونات البرمجيات والاعتماديات وإصداراتها الدقيقة من حزمة الـ APK.
    """
    versioned_libraries = []
    seen_artifacts = set()
    packages_detected = set()

    try:
        files = apk.get_files() or []
        for file_name in files:
            # 1. استخراج الإصدارات الرسمية من META-INF/*.version
            if file_name.startswith("META-INF/") and file_name.endswith(".version"):
                try:
                    stem = file_name.split("/")[-1][:-8]  # إزالة .version
                    raw_data = apk.get_file(file_name)
                    version_str = raw_data.decode("utf-8", errors="ignore").strip() if raw_data else ""
                    
                    if "_" in stem:
                        parts = stem.split("_", 1)
                        group, artifact = parts[0], parts[1]
                    else:
                        group, artifact = "", stem

                    key = f"{group}:{artifact}"
                    if key not in seen_artifacts and version_str:
                        seen_artifacts.add(key)
                        versioned_libraries.append({
                            "group": group,
                            "name": artifact,
                            "version": version_str,
                            "is_outdated": False
                        })
                except Exception:
                    pass

            # 2. استخراج الحزم المميزة من ملفات المسارات الداخلية
            if file_name.endswith((".class", ".dex", ".json")):
                parts = file_name.split("/")
                if len(parts) >= 3 and parts[0] in ("com", "org", "io", "androidx", "kotlinx"):
                    pkg_prefix = ".".join(parts[:3])
                    packages_detected.add(pkg_prefix)

    except Exception:
        pass

    # ترتيب المكتبات حسب المجموعة والاسم
    versioned_libraries.sort(key=lambda x: (x["group"], x["name"]))

    return {
        "total_dependencies": len(versioned_libraries),
        "versioned_libraries": versioned_libraries,
        "packages_detected": sorted(list(packages_detected))[:50]
    }
