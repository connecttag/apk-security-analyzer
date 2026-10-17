#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apk_patcher.py - محرك الترقيع الأمني الذكي وإعادة بناء حزم أندرويد (Sabr Smart Patcher)
يوفر دورة العمل المتكاملة:
1. التفكيك عبر Apktool (Decompile).
2. تطبيق الترقيعات الأمنية التلقائية (Security Patches):
   - إزالة قيود لقطات الشاشة (Disable FLAG_SECURE).
   - تجاوز فحص الشهادات وتمكين التنصت (Network Security Config & SSL Bypass).
   - تفعيل وضع التصحيح (Force Debuggable).
   - تحييد دوال كشف الروت (Root Detection Neutralizer).
3. إعادة التجميع (Rebuild عبر AAPT2).
4. محاذاة الحزمة (ZipAlign 4-Byte).
5. التوقيع الرقمي (Apksigner مع demo.jks أو مفتاح مخصص).
6. التثبيت والتشغيل المباشر على الهاتف عبر ADB.
"""

import os
import sys
import re
import json
import shutil
import argparse
import subprocess
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

try:
    from toolchain_detector import detect_toolchain
except ImportError:
    from tools.analyzer.toolchain_detector import detect_toolchain


class SecurityPatcher:
    """محرك تطبيق الترقيعات الأمنية على المشروع المفكك."""

    def __init__(self, project_dir: str):
        self.project_dir = os.path.abspath(project_dir)
        self.manifest_path = os.path.join(self.project_dir, "AndroidManifest.xml")
        self.res_dir = os.path.join(self.project_dir, "res")

    def patch_flag_secure(self) -> Dict[str, Any]:
        """إزالة قيود منع لقطات الشاشة (FLAG_SECURE = 0x2000)."""
        modified_files = []
        occurrences = 0

        # البحث في جميع مجلدات smali (smali, smali_classes2, smali_classes3...)
        for root, _, files in os.walk(self.project_dir):
            if not os.path.basename(root).startswith("smali"):
                # نتحقق أيضاً من المسارات الفرعية داخل smali
                if "smali" not in root:
                    continue

            for f in files:
                if not f.endswith(".smali"):
                    continue

                f_path = os.path.join(root, f)
                try:
                    with open(f_path, "r", encoding="utf-8", errors="ignore") as fp:
                        content = fp.read()

                    # فحص دقيق: فقط في الملفات التي تتعامل مع النوافذ والشاشات
                    if "Landroid/view/Window;" not in content and "FLAG_SECURE" not in content and "setFlags" not in content:
                        continue

                    # فحص وجود استدعاءات FLAG_SECURE (0x2000 = 8192)
                    # استبدال سليم: تحويل const/16 vX, 0x2000 إلى const/4 vX, 0x0
                    pattern = re.compile(r'const/16\s+([vp]\d+),\s*0x2000')
                    if pattern.search(content):
                        new_content, count = pattern.subn(r'const/4 \1, 0x0', content)
                        if count > 0:
                            with open(f_path, "w", encoding="utf-8") as fp:
                                fp.write(new_content)
                            modified_files.append(os.path.relpath(f_path, self.project_dir))
                            occurrences += count
                except Exception:
                    pass

        return {
            "patch": "FLAG_SECURE",
            "success": True,
            "occurrences": occurrences,
            "modified_files_count": len(modified_files),
            "sample_files": modified_files[:10],
            "description": f"تم تحييد {occurrences} استدعاء لحماية الشاشة (FLAG_SECURE) في {len(modified_files)} ملف Smali."
        }

    def patch_network_security(self, trust_user_certs: bool = True, allow_cleartext: bool = True) -> Dict[str, Any]:
        """تعديل تكوين أمان الشبكة للسماح بفحص ترافيك HTTP والوثوق بشهادات المستخدم (Burp/Charles)."""
        if not os.path.exists(self.manifest_path):
            return {"patch": "NETWORK_SECURITY", "success": False, "error": "AndroidManifest.xml غير موجود"}

        # 1. إنشاء أو استبدال ملف network_security_config.xml
        xml_dir = os.path.join(self.res_dir, "xml")
        os.makedirs(xml_dir, exist_ok=True)
        config_path = os.path.join(xml_dir, "network_security_config.xml")

        config_content = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
"""
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(config_content)

        # 2. تعديل AndroidManifest.xml لربط الملف والسماح بـ Cleartext
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                manifest_text = f.read()

            # التأكد من إضافة سمات networkSecurityConfig و usesCleartextTraffic في وسم <application>
            if 'android:networkSecurityConfig=' not in manifest_text:
                manifest_text = re.sub(
                    r'(<application\s+)',
                    r'\1android:networkSecurityConfig="@xml/network_security_config" ',
                    manifest_text,
                    count=1
                )

            if 'android:usesCleartextTraffic=' in manifest_text:
                manifest_text = re.sub(
                    r'android:usesCleartextTraffic="false"',
                    r'android:usesCleartextTraffic="true"',
                    manifest_text
                )
            else:
                manifest_text = re.sub(
                    r'(<application\s+)',
                    r'\1android:usesCleartextTraffic="true" ',
                    manifest_text,
                    count=1
                )

            with open(self.manifest_path, "w", encoding="utf-8") as f:
                f.write(manifest_text)

            return {
                "patch": "NETWORK_SECURITY",
                "success": True,
                "config_created": "res/xml/network_security_config.xml",
                "cleartext_enabled": True,
                "user_ca_trusted": True,
                "description": "تم حقن ملف Network Security Config وتمكين الوثوق بشهادات المستخدم والمرور غير المشفر."
            }
        except Exception as e:
            return {"patch": "NETWORK_SECURITY", "success": False, "error": str(e)}

    def patch_debuggable(self) -> Dict[str, Any]:
        """تفعيل وضع التصحيح في المانيفست (android:debuggable="true")."""
        if not os.path.exists(self.manifest_path):
            return {"patch": "DEBUGGABLE", "success": False, "error": "AndroidManifest.xml غير موجود"}

        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                manifest_text = f.read()

            if 'android:debuggable=' in manifest_text:
                manifest_text = re.sub(
                    r'android:debuggable="false"',
                    r'android:debuggable="true"',
                    manifest_text
                )
            else:
                manifest_text = re.sub(
                    r'(<application\s+)',
                    r'\1android:debuggable="true" ',
                    manifest_text,
                    count=1
                )

            # إزالة testOnly إن وجدت
            manifest_text = re.sub(r'android:testOnly="true"', r'android:testOnly="false"', manifest_text)

            with open(self.manifest_path, "w", encoding="utf-8") as f:
                f.write(manifest_text)

            return {
                "patch": "DEBUGGABLE",
                "success": True,
                "description": "تم تفعيل خاصية android:debuggable='true' للتنقيح وربط jdb و Frida."
            }
        except Exception as e:
            return {"patch": "DEBUGGABLE", "success": False, "error": str(e)}

    def patch_root_detection(self) -> Dict[str, Any]:
        """تحييد دوال فحص الروت الشائعة (RootBeer, isRooted)."""
        modified_methods = 0
        modified_files = []

        root_method_names = [
            "isRooted", "isRootedWithBusyBoxCheck", "isRootedWithoutBusyBoxCheck",
            "checkSuBinary", "isRootAvailable", "detectRootManagementApps"
        ]

        for root, _, files in os.walk(self.project_dir):
            if "smali" not in root:
                continue

            for f in files:
                if not f.endswith(".smali"):
                    continue

                f_path = os.path.join(root, f)
                try:
                    with open(f_path, "r", encoding="utf-8", errors="ignore") as fp:
                        lines = fp.readlines()

                    new_lines = []
                    in_target_method = False
                    file_modified = False

                    for line in lines:
                        new_lines.append(line)
                        if line.strip().startswith(".method") and any(m in line for m in root_method_names) and ")Z" in line:
                            # طريقة ترجع boolean فحص روت
                            in_target_method = True
                            modified_methods += 1
                            file_modified = True
                        elif in_target_method and (".locals" in line or ".registers" in line):
                            # حقن return false فوراً في بداية الدالة
                            new_lines.append("    const/4 v0, 0x0\n")
                            new_lines.append("    return v0\n")
                            in_target_method = False
                        elif line.strip().startswith(".end method"):
                            in_target_method = False

                    if file_modified:
                        with open(f_path, "w", encoding="utf-8") as fp:
                            fp.writelines(new_lines)
                        modified_files.append(os.path.relpath(f_path, self.project_dir))
                except Exception:
                    pass

        return {
            "patch": "ROOT_BYPASS",
            "success": True,
            "modified_methods": modified_methods,
            "modified_files_count": len(modified_files),
            "sample_files": modified_files[:10],
            "description": f"تم تحييد {modified_methods} دالة كشف روت في {len(modified_files)} ملف Smali."
        }


class ApkModdingPipeline:
    """إدارة دورة التفكيك، الترقيع، إعادة التجميع، المحاذاة، والتوقيع."""

    def __init__(self):
        self.toolchain = detect_toolchain()
        self.tools = self.toolchain.get("tools", {})
        self.java_exe = self.tools.get("java", {}).get("path")
        self.apktool_jar = self.tools.get("apktool", {}).get("path")
        self.apksigner_jar = self.tools.get("apksigner", {}).get("path")
        self.zipalign_exe = self.tools.get("zipalign", {}).get("path")
        self.adb_exe = self.tools.get("adb", {}).get("path")
        self.demo_keystore = self.tools.get("keystore", {}).get("path")

    def decompile(self, apk_path: str, output_dir: str, no_src: bool = False, force: bool = True) -> Tuple[bool, str]:
        """تفكيك الـ APK عبر Apktool."""
        if not self.java_exe or not self.apktool_jar:
            return False, "أداة Java أو Apktool غير متوفرة."

        cmd = [self.java_exe, "-jar", self.apktool_jar, "d", apk_path, "-o", output_dir]
        if force:
            cmd.append("-f")
        if no_src:
            cmd.append("--no-src")

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if proc.returncode == 0:
                return True, "تم تفكيك الـ APK بنجاح."
            return False, f"فشل Apktool: {proc.stderr or proc.stdout}"
        except Exception as e:
            return False, str(e)

    def rebuild(self, project_dir: str, output_apk: str, use_aapt2: bool = True) -> Tuple[bool, str]:
        """إعادة تجميع المشروع عبر Apktool."""
        if not self.java_exe or not self.apktool_jar:
            return False, "أداة Java أو Apktool غير متوفرة."

        os.makedirs(os.path.dirname(os.path.abspath(output_apk)), exist_ok=True)
        cmd = [self.java_exe, "-jar", self.apktool_jar, "b", project_dir, "-o", output_apk]
        if use_aapt2:
            cmd.append("--use-aapt2")

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if proc.returncode == 0 and os.path.exists(output_apk):
                return True, "تمت إعادة بناء الـ APK بنجاح."
            return False, f"فشل إعادة البناء: {proc.stderr or proc.stdout}"
        except Exception as e:
            return False, str(e)

    def zipalign(self, input_apk: str, output_apk: str) -> Tuple[bool, str]:
        """محاذاة الـ APK عبر Zipalign (4-Byte boundary)."""
        if not self.zipalign_exe or not os.path.exists(self.zipalign_exe):
            return False, "أداة Zipalign غير متوفرة."

        os.makedirs(os.path.dirname(os.path.abspath(output_apk)), exist_ok=True)
        cmd = [self.zipalign_exe, "-p", "-f", "4", input_apk, output_apk]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if proc.returncode == 0 and os.path.exists(output_apk):
                return True, "تمت محاذاة الـ APK بنجاح."
            return False, f"فشل Zipalign: {proc.stderr or proc.stdout}"
        except Exception as e:
            return False, str(e)

    def sign(
        self,
        input_apk: str,
        output_apk: str,
        keystore_path: Optional[str] = None,
        keystore_pass: str = "android",
        key_alias: str = "androiddebugkey",
        key_pass: str = "android"
    ) -> Tuple[bool, str]:
        """توقيع الـ APK بحزم v1, v2, v3 عبر Apksigner."""
        if not self.java_exe or not self.apksigner_jar:
            return False, "أداة Java أو Apksigner غير متوفرة."

        ks = keystore_path or self.demo_keystore
        if not ks or not os.path.exists(ks):
            return False, "ملف المفاتيح (Keystore) غير موجود."

        # التعرف التلقائي على بيانات المفتاح الافتراضي لـ APK Editor Studio أو Android SDK
        if not keystore_path:
            if "demo.jks" in ks.lower():
                keystore_pass = "123456"
                key_alias = "demo"
                key_pass = "123456"
            elif "debug.keystore" in ks.lower():
                keystore_pass = "android"
                key_alias = "androiddebugkey"
                key_pass = "android"

        os.makedirs(os.path.dirname(os.path.abspath(output_apk)), exist_ok=True)
        # إن كان المسار مختلفاً عن المدخل ننسخه أولاً
        if os.path.abspath(input_apk) != os.path.abspath(output_apk):
            shutil.copy2(input_apk, output_apk)

        cmd = [
            self.java_exe, "-jar", self.apksigner_jar, "sign",
            "--ks", ks,
            "--ks-pass", f"pass:{keystore_pass}",
            "--ks-key-alias", key_alias,
            "--key-pass", f"pass:{key_pass}",
            "--v1-signing-enabled", "true",
            "--v2-signing-enabled", "true",
            "--v3-signing-enabled", "true",
            output_apk
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if proc.returncode == 0:
                return True, "تم التوقيع الرقمي بنجاح."
            return False, f"فشل Apksigner: {proc.stderr or proc.stdout}"
        except Exception as e:
            return False, str(e)

    def install_to_device(self, apk_path: str, package_name: Optional[str] = None) -> Tuple[bool, str]:
        """تثبيت الـ APK على الهاتف المتصل عبر ADB."""
        if not self.adb_exe or not os.path.exists(self.adb_exe):
            return False, "أداة ADB غير متوفرة."

        cmd = [self.adb_exe, "install", "-r", "-d", apk_path]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            out = (proc.stdout or "") + (proc.stderr or "")
            if "Success" in out:
                return True, "تم التثبيت على الهاتف بنجاح!"
            return False, f"فشل التثبيت عبر ADB: {out.strip()}"
        except Exception as e:
            return False, str(e)

    def run_full_pipeline(
        self,
        apk_path: str,
        output_apk: str,
        patches: List[str],
        use_aapt2: bool = True,
        install: bool = False
    ) -> Dict[str, Any]:
        """تنفيذ دورة العمل الكاملة بنقرة واحدة."""
        if not os.path.exists(apk_path):
            return {"status": "error", "message": f"ملف APK غير موجود: {apk_path}"}

        temp_workspace = tempfile.mkdtemp(prefix="sabr_mod_")
        project_dir = os.path.join(temp_workspace, "decompiled")
        built_apk = os.path.join(temp_workspace, "unsigned.apk")
        aligned_apk = os.path.join(temp_workspace, "aligned.apk")

        results = {
            "status": "processing",
            "original_apk": apk_path,
            "output_apk": output_apk,
            "stages": []
        }

        try:
            # المرحلة 1: التفكيك
            success, msg = self.decompile(apk_path, project_dir)
            results["stages"].append({"stage": "DECOMPILE", "success": success, "message": msg})
            if not success:
                results["status"] = "error"
                results["error"] = msg
                return results

            # المرحلة 2: تطبيق الترقيعات
            patcher = SecurityPatcher(project_dir)
            patch_reports = []

            if "flag_secure" in patches:
                rep = patcher.patch_flag_secure()
                patch_reports.append(rep)

            if "network_security" in patches:
                rep = patcher.patch_network_security()
                patch_reports.append(rep)

            if "debuggable" in patches:
                rep = patcher.patch_debuggable()
                patch_reports.append(rep)

            if "root_bypass" in patches:
                rep = patcher.patch_root_detection()
                patch_reports.append(rep)

            results["stages"].append({"stage": "PATCHING", "success": True, "patches": patch_reports})

            # المرحلة 3: إعادة التجميع
            success, msg = self.rebuild(project_dir, built_apk, use_aapt2=use_aapt2)
            results["stages"].append({"stage": "REBUILD", "success": success, "message": msg})
            if not success:
                results["status"] = "error"
                results["error"] = msg
                return results

            # المرحلة 4: المحاذاة Zipalign
            success, msg = self.zipalign(built_apk, aligned_apk)
            results["stages"].append({"stage": "ZIPALIGN", "success": success, "message": msg})
            if not success:
                results["status"] = "error"
                results["error"] = msg
                return results

            # المرحلة 5: التوقيع الرقمي Apksigner
            success, msg = self.sign(aligned_apk, output_apk)
            results["stages"].append({"stage": "SIGNING", "success": success, "message": msg})
            if not success:
                results["status"] = "error"
                results["error"] = msg
                return results

            # المرحلة 6: التثبيت الاختياري عبر ADB
            if install:
                success, msg = self.install_to_device(output_apk)
                results["stages"].append({"stage": "INSTALL", "success": success, "message": msg})

            results["status"] = "success"
            results["message"] = f"تم بناء وترقيع وتوقيع الـ APK بنجاح وحفظه في: {output_apk}"
            return results

        finally:
            # تنظيف مسار العمل المؤقت
            try:
                shutil.rmtree(temp_workspace, ignore_errors=True)
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description="Sabr APK Smart Patcher & Modding Pipeline")
    subparsers = parser.add_subparsers(dest="command")

    # أمر pipeline الكامل
    pipe_parser = subparsers.add_parser("pipeline", help="تشغيل المسار الكامل (تفكيك + ترقيع + بناء + توقيع)")
    pipe_parser.add_argument("apk_path", help="مسار ملف APK الأصلي")
    pipe_parser.add_argument("-o", "--output", required=True, help="مسار ملف APK المعدل الناتج")
    pipe_parser.add_argument("--flag-secure", action="store_true", help="إلغاء قيود لقطات الشاشة FLAG_SECURE")
    pipe_parser.add_argument("--network-security", action="store_true", help="تجاوز قيود فحص الشهادات والوثوق بـ User CA")
    pipe_parser.add_argument("--debuggable", action="store_true", help="تفعيل وضع التصحيح debuggable=true")
    pipe_parser.add_argument("--root-bypass", action="store_true", help="تحييد فحص الروت والمحاكيات")
    pipe_parser.add_argument("--install", action="store_true", help="تثبيت الناتج على الهاتف المتصل عبر ADB")
    pipe_parser.add_argument("--no-aapt2", action="store_true", help="عدم استخدام AAPT2 في البناء")

    # أمر patch فقط
    patch_parser = subparsers.add_parser("patch", help="تطبيق الترقيعات على مجلد مفكك مسبقاً")
    patch_parser.add_argument("project_dir", help="مسار مجلد المشروع المفكك")
    patch_parser.add_argument("--flag-secure", action="store_true")
    patch_parser.add_argument("--network-security", action="store_true")
    patch_parser.add_argument("--debuggable", action="store_true")
    patch_parser.add_argument("--root-bypass", action="store_true")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "pipeline":
        patches = []
        if args.flag_secure: patches.append("flag_secure")
        if args.network_security: patches.append("network_security")
        if args.debuggable: patches.append("debuggable")
        if args.root_bypass: patches.append("root_bypass")

        if not patches:
            # افتراضياً نطبق كافة الترقيعات إن لم يحدد المستخدم
            patches = ["flag_secure", "network_security", "debuggable", "root_bypass"]

        pipeline = ApkModdingPipeline()
        res = pipeline.run_full_pipeline(
            apk_path=args.apk_path,
            output_apk=args.output,
            patches=patches,
            use_aapt2=not args.no_aapt2,
            install=args.install
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))

    elif args.command == "patch":
        patcher = SecurityPatcher(args.project_dir)
        reports = []
        if args.flag_secure: reports.append(patcher.patch_flag_secure())
        if args.network_security: reports.append(patcher.patch_network_security())
        if args.debuggable: reports.append(patcher.patch_debuggable())
        if args.root_bypass: reports.append(patcher.patch_root_detection())
        print(json.dumps({"status": "success", "patches": reports}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
