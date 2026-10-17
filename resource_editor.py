#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
resource_editor.py - محرر الموارد البصري واستوديو الأيقونات والتعريب الذكي (Sabr Visual Resource Studio)
يوفر وظائف احترافية بدون كود:
1. استبدال وتوليد كافة مقاسات الأيقونات (1-Click App Icon Replacer) لجميع الكثافات والأبعاد:
   - mipmap/drawable (mdpi, hdpi, xhdpi, xxhdpi, xxxhdpi).
   - الأيقونات الدائرية (ic_launcher_round) مع قناع تنعيم حواف دائري ناعم (Antialiased Circular Alpha Mask).
   - الأيقونات التكيفية الحديثة (Adaptive Icons Foreground).
2. محرر واستعراض النصوص والتعريب (Visual Strings Localizer):
   - قراءة كافة ملفات strings.xml لكل اللغات (default, ar, fr, es...).
   - البحث والتصفية بحسب اللغة أو النص أو المفتاح.
   - تعديل النصوص وحفظها أو إضافة مفاتيح جديدة بضغطة زر مع الحفاظ على ترميز UTF-8 وXML Escaping.
3. خط أنابيب تعديل الحزم الكامل المباشر (Full Resource Modding Pipeline).
"""

import os
import sys
import re
import json
import shutil
import argparse
import tempfile
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional, Tuple

# ضبط الترميز لدعم الحروف العربية في موجه أوامر ويندوز
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# استيراد مكتبة Pillow لمعالجة الصور
try:
    from PIL import Image, ImageDraw
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from apk_patcher import ApkModdingPipeline, SecurityPatcher
except ImportError:
    try:
        from tools.analyzer.apk_patcher import ApkModdingPipeline, SecurityPatcher
    except ImportError:
        ApkModdingPipeline = None
        SecurityPatcher = None


# المقاسات القياسية المعتمدة في أندرويد لكثافات الشاشة (Android Density Dimensions in Pixels)
DENSITY_SIZES = {
    "mdpi": {"standard": 48, "foreground": 108},
    "hdpi": {"standard": 72, "foreground": 162},
    "xhdpi": {"standard": 96, "foreground": 216},
    "xxhdpi": {"standard": 144, "foreground": 324},
    "xxxhdpi": {"standard": 192, "foreground": 432},
}


class ResourceEditor:
    """محرك فحص وتعديل الموارد والأيقونات والنصوص في المشاريع المفككة."""

    def __init__(self, project_dir: str):
        self.project_dir = os.path.abspath(project_dir)
        self.res_dir = os.path.join(self.project_dir, "res")
        self.manifest_path = os.path.join(self.project_dir, "AndroidManifest.xml")

    # =========================================================================
    # 1. إدارة واستعراض وتعديل النصوص (Strings Localizer)
    # =========================================================================

    def list_locales(self) -> List[str]:
        """استخراج قائمة بكافة اللغات والمحليات المتاحة في المشروع (التي تحتوي على strings.xml)."""
        if not os.path.exists(self.res_dir):
            return ["default"]

        # بادئات غير خاصة باللغات (Screen / Device Configuration Qualifiers)
        ignored_qualifiers = {"night", "land", "port", "sw", "w", "h", "v", "hdpi", "mdpi", "xhdpi", "xxhdpi", "xxxhdpi", "large", "xlarge", "normal", "small", "watch"}

        locales = set()
        for entry in os.listdir(self.res_dir):
            if not entry.startswith("values"):
                continue

            # التحقق من وجود ملف نصوص strings.xml
            strings_file = os.path.join(self.res_dir, entry, "strings.xml")
            if not os.path.exists(strings_file):
                continue

            if entry == "values":
                locales.add("default")
            elif entry.startswith("values-"):
                loc_code = entry[len("values-"):]
                # التحقق من أن الكود ليس qualifier صرف مثل v31 أو night
                first_part = loc_code.split("-")[0]
                if first_part in ignored_qualifiers or re.match(r"^[vwh]\d+", first_part):
                    continue
                locales.add(loc_code)

        ordered = []
        if "default" in locales:
            ordered.append("default")
            locales.remove("default")
        if "ar" in locales:
            ordered.append("ar")
            locales.remove("ar")

        ordered.extend(sorted(list(locales)))
        return ordered

    def list_strings(
        self,
        locale_filter: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 5000
    ) -> Dict[str, Any]:
        """
        قراءة جميع النصوص من ملفات strings.xml.
        يرجع مصفوفة تفاعلية للمحرر.
        """
        if not os.path.exists(self.res_dir):
            return {"status": "error", "message": "مجلد الموارد res غير موجود", "strings": [], "locales": []}

        all_locales = self.list_locales()
        result_strings = []

        target_dirs = []
        if locale_filter and locale_filter != "all":
            dir_name = "values" if locale_filter == "default" else f"values-{locale_filter}"
            dir_path = os.path.join(self.res_dir, dir_name)
            if os.path.exists(dir_path):
                target_dirs.append((dir_name, locale_filter, dir_path))
        else:
            for entry in os.listdir(self.res_dir):
                if entry == "values" or entry.startswith("values-"):
                    loc = "default" if entry == "values" else entry[len("values-"):]
                    target_dirs.append((entry, loc, os.path.join(self.res_dir, entry)))

        query_lower = search_query.strip().lower() if search_query else None

        for dir_name, loc, full_dir in target_dirs:
            strings_file = os.path.join(full_dir, "strings.xml")
            if not os.path.exists(strings_file):
                continue

            try:
                tree = ET.parse(strings_file)
                root = tree.getroot()
                rel_file = os.path.relpath(strings_file, self.project_dir).replace("\\", "/")

                for elem in root.findall("string"):
                    name = elem.attrib.get("name", "")
                    if not name:
                        continue

                    val = elem.text or ""
                    translatable = elem.attrib.get("translatable", "true").lower() != "false"
                    formatted = elem.attrib.get("formatted", "")

                    # التصفية بحسب البحث
                    if query_lower:
                        if query_lower not in name.lower() and query_lower not in val.lower():
                            continue

                    result_strings.append({
                        "name": name,
                        "value": val,
                        "locale": loc,
                        "file": rel_file,
                        "translatable": translatable,
                        "formatted": formatted if formatted else None
                    })

                    if len(result_strings) >= limit:
                        break
            except Exception as e:
                # تجاهل الأخطاء العارضة في ملفات الـ XML غير القياسية
                continue

            if len(result_strings) >= limit:
                break

        return {
            "status": "success",
            "total_count": len(result_strings),
            "locales": all_locales,
            "strings": result_strings
        }

    def save_strings(self, updates: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        حفظ وتحديث النصوص المحددة في ملفات strings.xml المناسبة.
        يقوم بإنشاء المجلد أو الملف إذا لم يكن موجوداً.
        """
        if not os.path.exists(self.res_dir):
            return {"status": "error", "message": "مجلد الموارد res غير موجود"}

        if not updates:
            return {"status": "success", "updated_count": 0, "message": "لا توجد تعديلات لحفظها"}

        # تجميع التحديثات بحسب اللغة
        by_locale: Dict[str, List[Dict[str, Any]]] = {}
        for item in updates:
            loc = item.get("locale", "default")
            by_locale.setdefault(loc, []).append(item)

        files_modified = []
        total_modified_strings = 0

        for loc, items in by_locale.items():
            dir_name = "values" if loc == "default" else f"values-{loc}"
            loc_dir = os.path.join(self.res_dir, dir_name)
            os.makedirs(loc_dir, exist_ok=True)
            strings_file = os.path.join(loc_dir, "strings.xml")

            root = None
            if os.path.exists(strings_file):
                try:
                    tree = ET.parse(strings_file)
                    root = tree.getroot()
                except Exception:
                    root = None

            if root is None:
                root = ET.Element("resources")
                tree = ET.ElementTree(root)

            # فهرسة العناصر الحالية لتحديث سريع
            existing_map = {elem.attrib.get("name"): elem for elem in root.findall("string") if elem.attrib.get("name")}

            for u in items:
                name = u.get("name")
                val = u.get("value", "")
                if not name:
                    continue

                if name in existing_map:
                    elem = existing_map[name]
                    elem.text = val
                else:
                    elem = ET.SubElement(root, "string", {"name": name})
                    elem.text = val
                    existing_map[name] = elem

                total_modified_strings += 1

            # حفظ التعديلات بترميز UTF-8 سليم مع الحفاظ على رأس XML
            try:
                # تنظيم المسافات البادئة (Indentation)
                if hasattr(ET, "indent"):
                    ET.indent(tree, space="    ", level=0)

                tree.write(strings_file, encoding="utf-8", xml_declaration=True)
                files_modified.append(os.path.relpath(strings_file, self.project_dir).replace("\\", "/"))
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"فشل حفظ ملف {strings_file}: {str(e)}",
                    "files_modified": files_modified
                }

        return {
            "status": "success",
            "updated_count": total_modified_strings,
            "files_modified": files_modified,
            "message": f"تم بنجاح تحديث {total_modified_strings} نص في {len(files_modified)} ملف."
        }

    # =========================================================================
    # 2. مستبدل الأيقونات الذكي (1-Click App Icon Replacer)
    # =========================================================================

    def get_manifest_icon_info(self) -> Dict[str, Any]:
        """استخراج اسم ومسار الأيقونة والأيقونة الدائرية من AndroidManifest.xml."""
        default_icon = "ic_launcher"
        default_round = "ic_launcher_round"

        if not os.path.exists(self.manifest_path):
            return {
                "icon_name": default_icon,
                "round_icon_name": default_round,
                "has_round_icon": True,
                "is_adaptive": False
            }

        try:
            tree = ET.parse(self.manifest_path)
            root = tree.getroot()
            ns = "http://schemas.android.com/apk/res/android"
            app = root.find("application")
            if app is None:
                return {"icon_name": default_icon, "round_icon_name": default_round, "has_round_icon": True}

            icon_attr = app.attrib.get(f"{{{ns}}}icon", "")
            round_attr = app.attrib.get(f"{{{ns}}}roundIcon", "")

            # استخراج اسم المصدر (مثال: @mipmap/ic_launcher أو @drawable/icon_app)
            icon_name = icon_attr.split("/")[-1] if "/" in icon_attr else default_icon
            round_name = round_attr.split("/")[-1] if "/" in round_attr else default_round

            # التحقق مما إذا كانت هناك أيقونة تكيفية Adaptive Icon
            is_adaptive = False
            for test_dir in ["mipmap-anydpi", "mipmap-anydpi-v26", "drawable-anydpi", "drawable-anydpi-v26"]:
                p = os.path.join(self.res_dir, test_dir, f"{icon_name}.xml")
                if os.path.exists(p):
                    is_adaptive = True
                    break

            return {
                "icon_name": icon_name,
                "round_icon_name": round_name,
                "has_round_icon": bool(round_attr),
                "is_adaptive": is_adaptive,
                "raw_icon": icon_attr,
                "raw_round_icon": round_attr
            }
        except Exception:
            return {"icon_name": default_icon, "round_icon_name": default_round, "has_round_icon": True}

    def get_icon_inventory(self) -> Dict[str, Any]:
        """فحص وحصر جميع ملفات الأيقونات المتوفرة في كافة مجلدات mipmap و drawable."""
        if not os.path.exists(self.res_dir):
            return {"status": "error", "message": "مجلد الموارد غير موجود", "icons": []}

        manifest_info = self.get_manifest_icon_info()
        main_icon = manifest_info["icon_name"]
        round_icon = manifest_info["round_icon_name"]

        found_icons = []

        for folder in sorted(os.listdir(self.res_dir)):
            if not (folder.startswith("mipmap") or folder.startswith("drawable")):
                continue

            folder_path = os.path.join(self.res_dir, folder)
            if not os.path.isdir(folder_path):
                continue

            for f in sorted(os.listdir(folder_path)):
                f_lower = f.lower()
                is_main = f_lower.startswith(main_icon.lower())
                is_round = f_lower.startswith(round_icon.lower())
                is_fg = "foreground" in f_lower and (main_icon.lower() in f_lower or "launcher" in f_lower)

                if is_main or is_round or is_fg or "ic_launcher" in f_lower:
                    full_p = os.path.join(folder_path, f)
                    rel_p = os.path.relpath(full_p, self.project_dir).replace("\\", "/")
                    file_info = {
                        "file_name": f,
                        "folder": folder,
                        "relative_path": rel_p,
                        "is_main": is_main,
                        "is_round": is_round,
                        "is_foreground": is_fg,
                        "is_xml": f.endswith(".xml")
                    }

                    if HAS_PIL and f.endswith(".png"):
                        try:
                            with Image.open(full_p) as im:
                                file_info["width"] = im.width
                                file_info["height"] = im.height
                        except Exception:
                            pass

                    found_icons.append(file_info)

        return {
            "status": "success",
            "manifest_info": manifest_info,
            "total_icons_found": len(found_icons),
            "icons": found_icons
        }

    def _create_circular_icon(self, img: "Image.Image") -> "Image.Image":
        """إنشاء نسخة دائرية مع قناع تنعيم حواف عالي الدقة (Smooth Antialiased Circular Mask)."""
        img_rgba = img.convert("RGBA")
        size = img_rgba.size

        # إنشاء قناع بمقاس مضاعف (Supersampling 2x) للحصول على أقصى نعومة حواف ممكنة
        ss_size = (size[0] * 2, size[1] * 2)
        mask_ss = Image.new("L", ss_size, 0)
        draw = ImageDraw.Draw(mask_ss)
        draw.ellipse((0, 0, ss_size[0], ss_size[1]), fill=255)

        # إعادة تصغير القناع بدقة Lanczos
        mask = mask_ss.resize(size, Image.Resampling.LANCZOS)

        circular = Image.new("RGBA", size, (0, 0, 0, 0))
        circular.paste(img_rgba, (0, 0), mask=mask)
        return circular

    def _prepare_sized_icon(
        self,
        src_img: "Image.Image",
        target_size: Tuple[int, int],
        is_foreground: bool = False
    ) -> "Image.Image":
        """
        تغيير حجم الصورة لتناسب الأبعاد المطلوبة بدقة عالية.
        في حال كانت أيقونة تكيفية (Foreground)، يتم وضعها في منطقة الأمان (Safe Zone = 66% من العرض)
        مع مساحات شفافة متناغمة ومطابقة لمعايير Material Design.
        """
        src_rgba = src_img.convert("RGBA")
        tw, th = target_size

        if is_foreground:
            # معيار الأيقونات التكيفية: مساحة الأيقونة 72dp داخل كانفاس 108dp (نسبة ~66%)
            fg_w = int(round(tw * 0.66))
            fg_h = int(round(th * 0.66))

            scale = min(fg_w / src_rgba.width, fg_h / src_rgba.height)
            nw = max(1, int(round(src_rgba.width * scale)))
            nh = max(1, int(round(src_rgba.height * scale)))

            resized = src_rgba.resize((nw, nh), Image.Resampling.LANCZOS)
            canvas = Image.new("RGBA", (tw, th), (0, 0, 0, 0))
            left = (tw - nw) // 2
            top = (th - nh) // 2
            canvas.paste(resized, (left, top), mask=resized)
            return canvas
        else:
            # قص مركزي وتوسيط لملء الأبعاد المحددة
            scale = max(tw / src_rgba.width, th / src_rgba.height)
            nw = max(1, int(round(src_rgba.width * scale)))
            nh = max(1, int(round(src_rgba.height * scale)))

            resized = src_rgba.resize((nw, nh), Image.Resampling.LANCZOS)
            left = (nw - tw) // 2
            top = (nh - th) // 2
            return resized.crop((left, top, left + tw, top + th))

    def replace_icons(
        self,
        source_image_path: str,
        generate_round: bool = True,
        update_foreground: bool = True
    ) -> Dict[str, Any]:
        """
        استبدال وتوزيع كافة مقاسات الأيقونات (1-Click App Icon Replacer).
        يقرأ صورة واحدة ويولد جميع أبعاد mipmap و drawable تلقائياً.
        """
        if not HAS_PIL:
            return {"status": "error", "message": "مكتبة Pillow غير مثبتة في بيئة بايثون."}

        if not os.path.exists(source_image_path):
            return {"status": "error", "message": f"ملف الصورة المصدر غير موجود: {source_image_path}"}

        try:
            source_img = Image.open(source_image_path)
            source_img.load()
        except Exception as e:
            return {"status": "error", "message": f"فشل فتح الصورة المصدر: {str(e)}"}

        manifest_info = self.get_manifest_icon_info()
        main_icon_name = manifest_info["icon_name"]
        round_icon_name = manifest_info["round_icon_name"]

        # إنشاء النسخة الدائرية
        circular_source = self._create_circular_icon(source_img) if generate_round else None

        replaced_files = []
        densities = ["mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi"]

        # 1. البحث عن الملفات الموجودة حالياً واستبدالها مع الحفاظ على أبعادها
        for folder in os.listdir(self.res_dir):
            if not (folder.startswith("mipmap") or folder.startswith("drawable")):
                continue

            folder_path = os.path.join(self.res_dir, folder)
            if not os.path.isdir(folder_path):
                continue

            # استنتاج الكثافة
            density = None
            for d in densities:
                if f"-{d}" in folder:
                    density = d
                    break

            for f in os.listdir(folder_path):
                if not f.endswith(".png"):
                    continue

                full_p = os.path.join(folder_path, f)
                f_no_ext = os.path.splitext(f)[0]

                # قراءة أبعاد الملف الحالي
                try:
                    with Image.open(full_p) as current_im:
                        target_size = (current_im.width, current_im.height)
                except Exception:
                    dim = DENSITY_SIZES.get(density, {}).get("standard", 96) if density else 96
                    target_size = (dim, dim)

                should_replace = False
                use_circular = False
                is_fg = False

                if f_no_ext == main_icon_name or f_no_ext == "ic_launcher":
                    should_replace = True
                elif generate_round and (f_no_ext == round_icon_name or f_no_ext == "ic_launcher_round"):
                    should_replace = True
                    use_circular = True
                elif update_foreground and ("foreground" in f_no_ext and ("launcher" in f_no_ext or main_icon_name in f_no_ext)):
                    should_replace = True
                    is_fg = True

                if should_replace:
                    try:
                        base = circular_source if use_circular else source_img
                        resized_icon = self._prepare_sized_icon(base, target_size, is_foreground=is_fg)
                        resized_icon.save(full_p, "PNG", optimize=True)
                        rel_p = os.path.relpath(full_p, self.project_dir).replace("\\", "/")
                        replaced_files.append({
                            "path": rel_p,
                            "width": target_size[0],
                            "height": target_size[1],
                            "type": "round" if use_circular else ("foreground" if is_fg else "standard")
                        })
                    except Exception:
                        pass

        # 2. في حال لم توجد مجلدات mipmap (حالة نادرة)، ننشئها ونوزع المقاسات القياسية
        if not replaced_files:
            for d in densities:
                folder_name = f"mipmap-{d}"
                target_dir = os.path.join(self.res_dir, folder_name)
                os.makedirs(target_dir, exist_ok=True)

                std_size = DENSITY_SIZES[d]["standard"]
                icon_path = os.path.join(target_dir, f"{main_icon_name}.png")
                icon_img = self._prepare_sized_icon(source_img, (std_size, std_size))
                icon_img.save(icon_path, "PNG", optimize=True)
                replaced_files.append({"path": os.path.relpath(icon_path, self.project_dir).replace("\\", "/"), "width": std_size, "height": std_size, "type": "standard"})

                if generate_round and circular_source:
                    round_path = os.path.join(target_dir, f"{round_icon_name}.png")
                    round_img = self._prepare_sized_icon(circular_source, (std_size, std_size))
                    round_img.save(round_path, "PNG", optimize=True)
                    replaced_files.append({"path": os.path.relpath(round_path, self.project_dir).replace("\\", "/"), "width": std_size, "height": std_size, "type": "round"})

        # حفظ نسخة Web Store بحجم 512x512
        try:
            web_icon = self._prepare_sized_icon(source_img, (512, 512))
            web_path = os.path.join(self.project_dir, "ic_launcher-web.png")
            web_icon.save(web_path, "PNG", optimize=True)
            replaced_files.append({"path": "ic_launcher-web.png", "width": 512, "height": 512, "type": "web_store"})
        except Exception:
            pass

        return {
            "status": "success",
            "replaced_count": len(replaced_files),
            "files": replaced_files,
            "message": f"تم بنجاح توليد وتوزيع {len(replaced_files)} مقاساً للأيقونة عبر كافة كثافات الشاشة ومجلدات الموارد."
        }


# =============================================================================
# 3. خط أنابيب تعديل موارد الحزم الشامل (Standalone Pipeline CLI)
# =============================================================================

def run_apk_resource_pipeline(
    apk_path: str,
    output_apk: Optional[str] = None,
    new_icon_path: Optional[str] = None,
    string_updates: Optional[List[Dict[str, Any]]] = None,
    patches: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    تنفيذ دورة التعديل المتكاملة لحزمة APK:
    تفكيك الموارد -> استبدال الأيقونات -> تعديل النصوص -> ترقيع أمني (اختياري) -> إعادة بناء -> محاذاة -> توقيع.
    """
    if ApkModdingPipeline is None:
        return {"status": "error", "message": "محرك ApkModdingPipeline غير متوفر"}

    pipeline = ApkModdingPipeline()
    toolchain_status = pipeline.toolchain.get("status")
    if toolchain_status != "success":
        return {"status": "error", "message": "أدوات التعديل (Java, Apktool, Apksigner, Zipalign) غير مكتملة."}

    # مجلد عمل مؤقت
    work_dir = tempfile.mkdtemp(prefix="sabr_res_mod_")
    decompiled_dir = os.path.join(work_dir, "decompiled")

    if not output_apk:
        base_name = os.path.splitext(os.path.basename(apk_path))[0]
        output_apk = os.path.join(os.path.dirname(os.path.abspath(apk_path)), f"{base_name}_modified.apk")

    stages = []

    try:
        # مرحلة 1: التفكيك (إذا كان هناك ترقيع سمالي نفكك بالكامل، وإلا نفكك بدون سورس للسرعة الفائقة)
        needs_smali = bool(patches and any(p in ["FLAG_SECURE", "ROOT_BYPASS"] for p in patches))
        success, msg = pipeline.decompile(apk_path, decompiled_dir, no_src=not needs_smali)
        stages.append({"stage": "DECOMPILE", "success": success, "message": msg})
        if not success:
            return {"status": "error", "stages": stages, "message": f"فشل التفكيك: {msg}"}

        editor = ResourceEditor(decompiled_dir)

        # مرحلة 2: استبدال الأيقونات
        if new_icon_path and os.path.exists(new_icon_path):
            icon_res = editor.replace_icons(new_icon_path)
            stages.append({
                "stage": "ICON_REPLACEMENT",
                "success": icon_res.get("status") == "success",
                "message": icon_res.get("message", ""),
                "details": icon_res
            })

        # مرحلة 3: تعديل النصوص
        if string_updates:
            str_res = editor.save_strings(string_updates)
            stages.append({
                "stage": "STRINGS_LOCALIZATION",
                "success": str_res.get("status") == "success",
                "message": str_res.get("message", ""),
                "details": str_res
            })

        # مرحلة 4: الترقيعات الأمنية الاختيارية
        if patches and SecurityPatcher:
            patcher = SecurityPatcher(decompiled_dir)
            patch_reports = []
            for p in patches:
                if p == "FLAG_SECURE":
                    patch_reports.append(patcher.patch_flag_secure())
                elif p == "NETWORK_SECURITY":
                    patch_reports.append(patcher.patch_network_security())
                elif p == "DEBUGGABLE":
                    patch_reports.append(patcher.patch_debuggable())
                elif p == "ROOT_BYPASS":
                    patch_reports.append(patcher.patch_root_detection())

            stages.append({
                "stage": "SECURITY_PATCHES",
                "success": True,
                "message": f"تم تطبيق {len(patch_reports)} ترقيعات أمنية بنجاح.",
                "patches": patch_reports
            })

        # مرحلة 5: إعادة التجميع (Rebuild)
        unsigned_apk = os.path.join(work_dir, "unsigned.apk")
        success, msg = pipeline.rebuild(decompiled_dir, unsigned_apk)
        stages.append({"stage": "REBUILD", "success": success, "message": msg})
        if not success:
            return {"status": "error", "stages": stages, "message": f"فشل إعادة التجميع: {msg}"}

        # مرحلة 6: المحاذاة (ZipAlign)
        aligned_apk = os.path.join(work_dir, "aligned.apk")
        success, msg = pipeline.zipalign(unsigned_apk, aligned_apk)
        stages.append({"stage": "ZIPALIGN", "success": success, "message": msg})
        if not success:
            return {"status": "error", "stages": stages, "message": f"فشل المحاذاة: {msg}"}

        # مرحلة 7: التوقيع الرقمي (Sign)
        success, msg = pipeline.sign(aligned_apk, output_apk)
        stages.append({"stage": "SIGNING", "success": success, "message": msg})
        if not success:
            return {"status": "error", "stages": stages, "message": f"فشل التوقيع: {msg}"}

        return {
            "status": "success",
            "original_apk": apk_path,
            "output_apk": output_apk,
            "stages": stages,
            "message": f"تم تعديل وتوقيع الحزمة بنجاح: {os.path.basename(output_apk)}"
        }
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def ensure_project_dir(apk_or_dir: str) -> Tuple[bool, str, str]:
    """التأكد من توفر مجلد مشروع مفكك للموارد (إذا كان APK، يتم تفكيك موارده سريعاً في مجلد مؤقت)."""
    if os.path.isdir(apk_or_dir) and (os.path.exists(os.path.join(apk_or_dir, "res")) or os.path.exists(os.path.join(apk_or_dir, "AndroidManifest.xml"))):
        return True, os.path.abspath(apk_or_dir), "مجلد المشروع متوفر وجاهز"

    if os.path.isfile(apk_or_dir) and apk_or_dir.lower().endswith(".apk"):
        if ApkModdingPipeline is None:
            return False, "", "ApkModdingPipeline غير متوفر"
        pipeline = ApkModdingPipeline()
        base = os.path.splitext(os.path.basename(apk_or_dir))[0]
        size = os.path.getsize(apk_or_dir)
        cache_name = f"sabr_res_{base}_{size}"
        cache_dir = os.path.join(tempfile.gettempdir(), cache_name)
        if os.path.exists(os.path.join(cache_dir, "res")):
            return True, cache_dir, "تم استخدام كاش الموارد المفككة مسبقاً"

        os.makedirs(cache_dir, exist_ok=True)
        success, msg = pipeline.decompile(apk_or_dir, cache_dir, no_src=True)
        if success:
            return True, cache_dir, "تم تفكيك موارد الحزمة بنجاح"
        return False, "", f"فشل تفكيك موارد الحزمة: {msg}"

    return False, "", "المسار المحدد ليس حزمة APK صالحة أو مجلد مشروع مفكك"


def rebuild_and_sign_project(project_dir: str, output_apk: Optional[str] = None) -> Dict[str, Any]:
    """إعادة تجميع ومحاذاة وتوقيع مجلد المشروع في حزمة APK نهائية جاهزة للتثبيت."""
    if ApkModdingPipeline is None:
        return {"status": "error", "message": "ApkModdingPipeline غير متوفر"}

    pipeline = ApkModdingPipeline()
    if not output_apk:
        output_apk = os.path.join(os.path.dirname(os.path.abspath(project_dir)), "sabr_output_signed.apk")

    work_dir = tempfile.mkdtemp(prefix="sabr_rebuild_")
    try:
        unsigned = os.path.join(work_dir, "unsigned.apk")
        aligned = os.path.join(work_dir, "aligned.apk")

        ok, msg = pipeline.rebuild(project_dir, unsigned)
        if not ok:
            return {"status": "error", "message": f"فشل إعادة التجميع: {msg}"}

        ok, msg = pipeline.zipalign(unsigned, aligned)
        if not ok:
            return {"status": "error", "message": f"فشل المحاذاة: {msg}"}

        ok, msg = pipeline.sign(aligned, output_apk)
        if not ok:
            return {"status": "error", "message": f"فشل التوقيع: {msg}"}

        return {
            "status": "success",
            "output_apk": output_apk,
            "message": f"تم بنجاح بناء وتوقيع الحزمة: {os.path.basename(output_apk)}"
        }
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Sabr Visual Resource Studio Engine")
    subparsers = parser.add_subparsers(dest="action", help="Action to perform")

    # 1. list-strings
    p_ls = subparsers.add_parser("list-strings", help="List strings from decompiled project")
    p_ls.add_argument("--project-dir", required=True, help="Path to decompiled project folder")
    p_ls.add_argument("--locale", default=None, help="Filter by locale (e.g. default, ar)")
    p_ls.add_argument("--query", default=None, help="Search query in key or value")

    # 2. save-strings
    p_ss = subparsers.add_parser("save-strings", help="Save or update strings")
    p_ss.add_argument("--project-dir", required=True, help="Path to decompiled project folder")
    p_ss.add_argument("--updates-json", required=True, help="JSON file or string containing array of updates")

    # 3. get-icons
    p_gi = subparsers.add_parser("get-icons", help="Get inventory of app icons")
    p_gi.add_argument("--project-dir", required=True, help="Path to decompiled project folder")

    # 4. replace-icons
    p_ri = subparsers.add_parser("replace-icons", help="Replace app icons across all densities")
    p_ri.add_argument("--project-dir", required=True, help="Path to decompiled project folder")
    p_ri.add_argument("--image", required=True, help="Path to new source image (PNG/JPG)")
    p_ri.add_argument("--no-round", action="store_true", help="Do not generate round icons")
    p_ri.add_argument("--no-foreground", action="store_true", help="Do not update adaptive icon foreground")

    # 5. mod-pipeline
    p_mod = subparsers.add_parser("mod-pipeline", help="Run full pipeline on an APK")
    p_mod.add_argument("--apk", required=True, help="Path to source APK")
    p_mod.add_argument("--output", default=None, help="Path to output modified APK")
    p_mod.add_argument("--new-icon", default=None, help="Path to new app icon image")
    p_mod.add_argument("--updates-json", default=None, help="JSON file with string updates")
    p_mod.add_argument("--patches", default=None, help="Comma-separated patches: FLAG_SECURE,NETWORK_SECURITY,DEBUGGABLE,ROOT_BYPASS")

    # 6. rebuild-project
    p_reb = subparsers.add_parser("rebuild-project", help="Rebuild, zipalign and sign project")
    p_reb.add_argument("--project-dir", required=True, help="Path to project directory")
    p_reb.add_argument("--output", default=None, help="Output APK path")

    args = parser.parse_args()

    # تحويل مسار الحزمة أو المجلد تلقائياً
    if hasattr(args, "project_dir") and args.project_dir:
        ok, p_dir, msg = ensure_project_dir(args.project_dir)
        if not ok:
            print(json.dumps({"status": "error", "message": msg}, ensure_ascii=False))
            sys.exit(1)
        args.project_dir = p_dir

    if args.action == "list-strings":
        editor = ResourceEditor(args.project_dir)
        res = editor.list_strings(locale_filter=args.locale, search_query=args.query)
        res["project_dir"] = args.project_dir
        print(json.dumps(res, ensure_ascii=False, indent=2))

    elif args.action == "save-strings":
        editor = ResourceEditor(args.project_dir)
        try:
            if os.path.exists(args.updates_json):
                with open(args.updates_json, "r", encoding="utf-8") as f:
                    updates = json.load(f)
            else:
                updates = json.loads(args.updates_json)
        except Exception as e:
            print(json.dumps({"status": "error", "message": f"فشل قراءة بيانات التحديثات: {str(e)}"}, ensure_ascii=False))
            sys.exit(1)

        res = editor.save_strings(updates)
        res["project_dir"] = args.project_dir
        print(json.dumps(res, ensure_ascii=False, indent=2))

    elif args.action == "get-icons":
        editor = ResourceEditor(args.project_dir)
        res = editor.get_icon_inventory()
        res["project_dir"] = args.project_dir
        print(json.dumps(res, ensure_ascii=False, indent=2))

    elif args.action == "replace-icons":
        editor = ResourceEditor(args.project_dir)
        res = editor.replace_icons(
            source_image_path=args.image,
            generate_round=not args.no_round,
            update_foreground=not args.no_foreground
        )
        res["project_dir"] = args.project_dir
        print(json.dumps(res, ensure_ascii=False, indent=2))

    elif args.action == "rebuild-project":
        res = rebuild_and_sign_project(args.project_dir, args.output)
        print(json.dumps(res, ensure_ascii=False, indent=2))

    elif args.action == "mod-pipeline":
        updates = None
        if args.updates_json:
            try:
                if os.path.exists(args.updates_json):
                    with open(args.updates_json, "r", encoding="utf-8") as f:
                        updates = json.load(f)
                else:
                    updates = json.loads(args.updates_json)
            except Exception:
                pass

        patches = [p.strip() for p in args.patches.split(",")] if args.patches else None

        res = run_apk_resource_pipeline(
            apk_path=args.apk,
            output_apk=args.output,
            new_icon_path=args.new_icon,
            string_updates=updates,
            patches=patches
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
