# info_extractor.py
# -*- coding: utf-8 -*-
import os
import io
import hashlib
from typing import Dict, List, Optional, Any
from pathlib import Path
from androguard.core.apk import APK
from androguard.core.analysis.analysis import Analysis
from PIL import Image

class InfoExtractor:
    def __init__(self, apk: APK):
        self.apk = apk

    def get_basic_info(self, apk_path: str) -> Dict[str, Any]:
        """استخراج البيانات الأساسية للتطبيق."""
        raw_code = self.apk.get_androidversion_code()
        try:
            code_int = int(str(raw_code).strip()) if raw_code else 0
        except Exception:
            code_int = 0

        raw_min = self.apk.get_min_sdk_version()
        try:
            min_sdk = int(str(raw_min).strip()) if raw_min else 0
        except Exception:
            min_sdk = 0

        raw_target = self.apk.get_target_sdk_version()
        try:
            target_sdk = int(str(raw_target).strip()) if raw_target else 0
        except Exception:
            target_sdk = 0

        raw_max = self.apk.get_max_sdk_version()
        try:
            max_sdk = int(str(raw_max).strip()) if raw_max else None
        except Exception:
            max_sdk = None

        return {
            "filename": os.path.basename(apk_path),
            "package_name": self.apk.get_package() or "unknown",
            "app_name": self.apk.get_app_name() or Path(apk_path).stem,
            "version": {
                "code": code_int,
                "name": str(self.apk.get_androidversion_name() or "unknown"),
            },
            "sdk_versions": {
                "min": min_sdk,
                "target": target_sdk,
                "max": max_sdk,
            },
            "size_mb": round(os.path.getsize(apk_path) / (1024 * 1024), 2),
        }

    def get_components_info(self) -> Dict[str, Any]:
        """استخراج مكونات النظام البرمجية (Activities, Services, Receivers, Providers)."""
        return {
            "activities": self.apk.get_activities() or [],
            "main_activity": self.apk.get_main_activity() or "unknown",
            "services": self.apk.get_services() or [],
            "receivers": self.apk.get_receivers() or [],
            "providers": self.apk.get_providers() or [],
            "libraries": self.apk.get_libraries() or [],
            "features": self.apk.get_features() or [],
        }

    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """حساب البصمات الرقمية للملف (MD5, SHA1, SHA256)."""
        hashes = {'md5': '', 'sha1': '', 'sha256': ''}
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha1'] = hashlib.sha1(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()
        except Exception:
            pass
        return hashes

    def extract_main_icon(self, output_dir: str) -> Optional[str]:
        """استخراج وحفظ الأيقونة الرئيسية بصيغة PNG لعرضها في الواجهة الرسومية."""
        try:
            os.makedirs(output_dir, exist_ok=True)
            icon_rel_path = self.apk.get_app_icon()
            if not icon_rel_path:
                return None
            icon_data = self.apk.get_file(icon_rel_path)
            if not icon_data:
                return None

            output_file = os.path.join(output_dir, f"{self.apk.get_package()}_icon.png")
            try:
                img = Image.open(io.BytesIO(icon_data))
                img.save(output_file, format='PNG')
                return output_file
            except Exception:
                with open(output_file, "wb") as f:
                    f.write(icon_data)
                return output_file
        except Exception:
            return None

    def get_manifest_xml(self) -> str:
        """استخراج ملف AndroidManifest.xml ككود نصي منسق."""
        try:
            axml = self.apk.get_android_manifest_axml()
            if axml:
                xml_obj = axml.get_xml_obj()
                if xml_obj is not None:
                    from xml.dom import minidom
                    import xml.etree.ElementTree as ET
                    rough_string = ET.tostring(xml_obj, encoding="utf-8")
                    reparsed = minidom.parseString(rough_string)
                    return reparsed.toprettyxml(indent="  ")
        except Exception:
            pass

        try:
            axml = self.apk.get_android_manifest_axml()
            if axml:
                xml_data = axml.get_xml()
                if xml_data:
                    return xml_data.decode("utf-8", errors="ignore") if isinstance(xml_data, bytes) else str(xml_data)
        except Exception:
            pass

        return ""

    def get_resources_summary(self) -> Dict[str, Any]:
        """استخراج فهرس بملفات الموارد والأيقونات المضمنة."""
        drawables = []
        assets = []
        all_files = self.apk.get_files() or []
        for f in all_files:
            if f.startswith("res/drawable") or f.startswith("res/mipmap"):
                drawables.append(f)
            elif f.startswith("assets/"):
                assets.append(f)

        return {
            "total_files": len(all_files),
            "drawables_count": len(drawables),
            "assets_count": len(assets),
            "sample_drawables": drawables[:25],
            "sample_assets": assets[:25]
        }

    def export_resources(self, output_dir: str) -> int:
        """تصدير وحفظ كافة الأيقونات والصور والأصول إلى مجلد محلي."""
        exported_count = 0
        try:
            os.makedirs(output_dir, exist_ok=True)
            for f in self.apk.get_files() or []:
                if any(f.startswith(p) for p in ["res/drawable", "res/mipmap", "assets/"]):
                    data = self.apk.get_file(f)
                    if data:
                        target_path = os.path.join(output_dir, f.replace("/", os.sep))
                        os.makedirs(os.path.dirname(target_path), exist_ok=True)
                        with open(target_path, "wb") as out_f:
                            out_f.write(data)
                        exported_count += 1
        except Exception:
            pass
        return exported_count

    def search_dex_symbols(self, anydx: Analysis, query: str) -> List[str]:
        """البحث عن الكلاسات والدوال في DEX المطابقة لاستعلام معين."""
        results = []
        if not anydx or not query:
            return results
        q_lower = query.lower()
        try:
            for cls in anydx.get_classes():
                cls_name = cls.name
                if q_lower in cls_name.lower():
                    results.append(f"Class: {cls_name}")
                for m in cls.get_methods():
                    m_name = m.name
                    if q_lower in m_name.lower():
                        results.append(f"Method: {cls_name}->{m_name}")
                if len(results) >= 60:
                    break
        except Exception:
            pass
        return results

    def get_target_form_factors(self) -> Dict[str, bool]:
        """تحديد نوع الأجهزة والمنصات المستهدفة للتطبيق (الهواتف، الساعات، التلفاز)."""
        is_wear = False
        is_tv = False
        is_multidex = False
        try:
            is_wear = bool(self.apk.is_wearable())
            is_tv = bool(self.apk.is_leanback() or self.apk.is_androidtv())
            is_multidex = bool(self.apk.is_multidex())
        except Exception:
            pass

        return {
            "is_phone_tablet": not is_wear,
            "is_wearable": is_wear,
            "is_android_tv": is_tv,
            "is_multidex": is_multidex
        }

    def get_localization_info(self) -> Dict[str, Any]:
        """استخراج اللغات المدعومة والتحقق من التوطين واللغة العربية من جدول الموارد."""
        supported_locales = set()
        default_language = "en"

        try:
            arsc = self.apk.get_android_resources()
            if arsc:
                pkg_names = arsc.get_packages_names() or [self.apk.get_package()]
                for pkg in pkg_names:
                    try:
                        raw_locales = arsc.get_locales(pkg) or []
                        for loc in raw_locales:
                            if not loc or loc == "\x00\x00":
                                continue
                            supported_locales.add(loc)
                    except Exception:
                        pass
        except Exception:
            pass

        locales_list = sorted(list(supported_locales))
        supports_arabic = any(loc == "ar" or loc.startswith("ar-") or loc.startswith("ar_") for loc in locales_list)
        supports_english = any(loc == "en" or loc.startswith("en-") or loc.startswith("en_") for loc in locales_list) or len(locales_list) > 0

        if "ar" in locales_list and not supports_english:
            default_language = "ar"
        elif "en" in locales_list:
            default_language = "en"
        elif locales_list:
            default_language = locales_list[0].split("-")[0]

        return {
            "supported_locales": locales_list,
            "total_locales": len(locales_list),
            "supports_arabic": supports_arabic,
            "supports_english": supports_english,
            "default_language": default_language
        }

    def extract_all_icons(self, output_dir: str) -> Dict[str, str]:
        """استخراج حزمة الأيقونات بكافة كثافات الشاشة (DPI) بصيغتي WebP و PNG."""
        icons = {}
        dpi_list = [
            (None, "main"),
            (120, "120dpi_ldpi"),
            (160, "160dpi_mdpi"),
            (240, "240dpi_hdpi"),
            (320, "320dpi_xhdpi"),
            (480, "480dpi_xxhdpi"),
            (640, "640dpi_xxxhdpi")
        ]

        try:
            os.makedirs(output_dir, exist_ok=True)
            pkg = self.apk.get_package() or "app"

            for dpi_val, dpi_label in dpi_list:
                try:
                    icon_rel_path = self.apk.get_app_icon(max_dpi=dpi_val) if dpi_val else self.apk.get_app_icon()
                    if not icon_rel_path:
                        continue
                    icon_data = self.apk.get_file(icon_rel_path)
                    if not icon_data:
                        continue

                    out_webp = os.path.join(output_dir, f"{pkg}_{dpi_label}.webp")
                    out_png = os.path.join(output_dir, f"{pkg}_{dpi_label}.png")

                    saved_path = out_png
                    try:
                        img = Image.open(io.BytesIO(icon_data))
                        img.save(out_webp, format="WEBP", quality=95)
                        saved_path = out_webp
                    except Exception:
                        with open(out_png, "wb") as f:
                            f.write(icon_data)
                        saved_path = out_png

                    icons[dpi_label] = saved_path
                except Exception:
                    continue
        except Exception:
            pass

        return icons

    def get_hardware_and_screens_matrix(self) -> Dict[str, Any]:
        """
        استخراج وتحليل مصفوفة عتاد الأجهزة وشاشات العرض (<uses-feature> & Hardware Matrix).
        تحليل متطلبات العتاد الصريحة والضمنية من الصلاحيات وشاشات العرض المدعومة.
        """
        explicit_features = {}
        screens_info = {
            "small_screens": True,
            "normal_screens": True,
            "large_screens": True,
            "xlarge_screens": True,
            "any_density": True,
            "resizeable": True
        }

        # 1. فحص عناصر المانيفست
        try:
            axml = self.apk.get_android_manifest_axml()
            if axml:
                xml_obj = axml.get_xml_obj()
                if xml_obj is not None:
                    # فحص <uses-feature>
                    for elem in xml_obj.findall(".//uses-feature"):
                        name = (
                            elem.attrib.get("{http://schemas.android.com/apk/res/android}name")
                            or elem.attrib.get("name")
                        )
                        req_val = (
                            elem.attrib.get("{http://schemas.android.com/apk/res/android}required")
                            or elem.attrib.get("required")
                        )
                        gles_val = (
                            elem.attrib.get("{http://schemas.android.com/apk/res/android}glEsVersion")
                            or elem.attrib.get("glEsVersion")
                        )
                        if name:
                            is_req = str(req_val).lower() != "false" if req_val is not None else True
                            explicit_features[str(name)] = {
                                "is_required": is_req,
                                "gles_version": gles_val
                            }
                        elif gles_val:
                            explicit_features["android.hardware.opengles"] = {
                                "is_required": True,
                                "gles_version": gles_val
                            }

                    # فحص <supports-screens>
                    for elem in xml_obj.findall(".//supports-screens"):
                        for key, attr_name in [
                            ("small_screens", "smallScreens"),
                            ("normal_screens", "normalScreens"),
                            ("large_screens", "largeScreens"),
                            ("xlarge_screens", "xlargeScreens"),
                            ("any_density", "anyDensity"),
                            ("resizeable", "resizeable")
                        ]:
                            val = (
                                elem.attrib.get(f"{{http://schemas.android.com/apk/res/android}}{attr_name}")
                                or elem.attrib.get(attr_name)
                            )
                            if val is not None:
                                screens_info[key] = str(val).lower() not in ("false", "0")
        except Exception:
            pass

        # 2. فحص الصلاحيات لاشتقاق العتاد الضمني
        all_perms = set(self.apk.get_permissions() or [])

        # خريطة الميزات الرئيسية
        hardware_defs = [
            {
                "id": "camera",
                "feature": "android.hardware.camera",
                "title": "Camera",
                "title_ar": "الكاميرا",
                "implied_perms": ["android.permission.CAMERA", "android.permission.FOREGROUND_SERVICE_CAMERA"]
            },
            {
                "id": "camera_autofocus",
                "feature": "android.hardware.camera.autofocus",
                "title": "Camera Autofocus",
                "title_ar": "الضبط التلقائي للكاميرا",
                "implied_perms": []
            },
            {
                "id": "camera_flash",
                "feature": "android.hardware.camera.flash",
                "title": "Camera Flash",
                "title_ar": "فلاش الكاميرا",
                "implied_perms": []
            },
            {
                "id": "biometrics",
                "feature": "android.hardware.fingerprint",
                "title": "Biometrics / Fingerprint",
                "title_ar": "البصمة والمقاييس الحيوية",
                "implied_perms": [
                    "android.permission.USE_FINGERPRINT",
                    "android.permission.USE_BIOMETRIC"
                ]
            },
            {
                "id": "nfc",
                "feature": "android.hardware.nfc",
                "title": "NFC",
                "title_ar": "الاتصال قريب المدى (NFC)",
                "implied_perms": ["android.permission.NFC"]
            },
            {
                "id": "bluetooth",
                "feature": "android.hardware.bluetooth",
                "title": "Bluetooth",
                "title_ar": "البلوتوث",
                "implied_perms": [
                    "android.permission.BLUETOOTH",
                    "android.permission.BLUETOOTH_ADMIN",
                    "android.permission.BLUETOOTH_CONNECT",
                    "android.permission.BLUETOOTH_SCAN",
                    "android.permission.BLUETOOTH_ADVERTISE"
                ]
            },
            {
                "id": "bluetooth_le",
                "feature": "android.hardware.bluetooth_le",
                "title": "Bluetooth Low Energy (BLE)",
                "title_ar": "البلوتوث منخفض الطاقة (BLE)",
                "implied_perms": []
            },
            {
                "id": "gps",
                "feature": "android.hardware.location.gps",
                "title": "GPS & Location",
                "title_ar": "تحديد المواقع الدقيق (GPS)",
                "implied_perms": [
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.ACCESS_COARSE_LOCATION"
                ]
            },
            {
                "id": "telephony",
                "feature": "android.hardware.telephony",
                "title": "Telephony & Cellular",
                "title_ar": "الاتصال الخلوي والهاتف",
                "implied_perms": [
                    "android.permission.CALL_PHONE",
                    "android.permission.SEND_SMS",
                    "android.permission.RECEIVE_SMS",
                    "android.permission.READ_PHONE_STATE",
                    "android.permission.MANAGE_OWN_CALLS",
                    "android.permission.FOREGROUND_SERVICE_PHONE_CALL"
                ]
            },
            {
                "id": "microphone",
                "feature": "android.hardware.microphone",
                "title": "Microphone / Audio",
                "title_ar": "الميكروفون وتسجيل الصوت",
                "implied_perms": [
                    "android.permission.RECORD_AUDIO",
                    "android.permission.FOREGROUND_SERVICE_MICROPHONE"
                ]
            },
            {
                "id": "sensors",
                "feature": "android.hardware.sensor",
                "title": "Sensors (Motion/Body)",
                "title_ar": "حساسات الحركة والنشاط",
                "implied_perms": [
                    "android.permission.BODY_SENSORS",
                    "android.permission.ACTIVITY_RECOGNITION"
                ]
            }
        ]

        feature_items = []
        flags = {
            "has_camera": False,
            "is_camera_required": False,
            "has_biometrics": False,
            "has_nfc": False,
            "has_bluetooth": False,
            "has_bluetooth_le": False,
            "has_gps": False,
            "has_telephony": False,
            "has_microphone": False,
            "has_sensors": False
        }

        # دمج الميزات الصريحة والضمنية
        for hdef in hardware_defs:
            f_name = hdef["feature"]
            h_id = hdef["id"]

            if f_name in explicit_features:
                explicit_info = explicit_features[f_name]
                is_req = explicit_info["is_required"]
                feature_items.append({
                    "name": f_name,
                    "title": hdef["title"],
                    "title_ar": hdef["title_ar"],
                    "status": "REQUIRED" if is_req else "OPTIONAL",
                    "is_required": is_req,
                    "source": "EXPLICIT_MANIFEST",
                    "details": "<uses-feature>"
                })
                # تحديث الأعلام
                if "camera" in h_id:
                    flags["has_camera"] = True
                    if is_req: flags["is_camera_required"] = True
                elif h_id == "biometrics": flags["has_biometrics"] = True
                elif h_id == "nfc": flags["has_nfc"] = True
                elif h_id == "bluetooth": flags["has_bluetooth"] = True
                elif h_id == "bluetooth_le":
                    flags["has_bluetooth"] = True
                    flags["has_bluetooth_le"] = True
                elif h_id == "gps": flags["has_gps"] = True
                elif h_id == "telephony": flags["has_telephony"] = True
                elif h_id == "microphone": flags["has_microphone"] = True
                elif h_id == "sensors": flags["has_sensors"] = True

            else:
                # التحقق إن كانت الصلاحيات تقتضي العتاد
                matched_perm = next((p for p in hdef["implied_perms"] if p in all_perms), None)
                if matched_perm:
                    feature_items.append({
                        "name": f_name,
                        "title": hdef["title"],
                        "title_ar": hdef["title_ar"],
                        "status": "IMPLIED",
                        "is_required": True,
                        "source": "IMPLIED_BY_PERMISSION",
                        "details": matched_perm
                    })
                    if "camera" in h_id:
                        flags["has_camera"] = True
                        flags["is_camera_required"] = True
                    elif h_id == "biometrics": flags["has_biometrics"] = True
                    elif h_id == "nfc": flags["has_nfc"] = True
                    elif h_id == "bluetooth": flags["has_bluetooth"] = True
                    elif h_id == "gps": flags["has_gps"] = True
                    elif h_id == "telephony": flags["has_telephony"] = True
                    elif h_id == "microphone": flags["has_microphone"] = True
                    elif h_id == "sensors": flags["has_sensors"] = True

        # إضافة أي ميزات صريحة أخرى غير موجودة في hardware_defs
        known_names = {h["feature"] for h in hardware_defs}
        for exp_name, exp_info in explicit_features.items():
            if exp_name not in known_names:
                clean_title = exp_name.replace("android.hardware.", "").replace(".", " ").title()
                is_req = exp_info["is_required"]
                feature_items.append({
                    "name": exp_name,
                    "title": clean_title,
                    "title_ar": clean_title,
                    "status": "REQUIRED" if is_req else "OPTIONAL",
                    "is_required": is_req,
                    "source": "EXPLICIT_MANIFEST",
                    "details": "<uses-feature>"
                })

        return {
            "features": feature_items,
            "has_camera": flags["has_camera"],
            "is_camera_required": flags["is_camera_required"],
            "has_biometrics": flags["has_biometrics"],
            "has_nfc": flags["has_nfc"],
            "has_bluetooth": flags["has_bluetooth"],
            "has_bluetooth_le": flags["has_bluetooth_le"],
            "has_gps": flags["has_gps"],
            "has_telephony": flags["has_telephony"],
            "has_microphone": flags["has_microphone"],
            "has_sensors": flags["has_sensors"],
            "screens": screens_info,
            "total_explicit_features": len(explicit_features),
            "total_features": len(feature_items)
        }


