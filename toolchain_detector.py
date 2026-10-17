#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
toolchain_detector.py - كاشف ومدير الأدوات الخارجية للهندسة العكسية والتجميع
يكتشف تلقائياً أدوات: Java, Apktool, Apksigner, Zipalign, ADB, ومفتاح التوقيع demo.jks.
يبحث أولاً في مجلد APK Editor Studio، ثم مسار JAVA_HOME و Android SDK و System PATH.
"""

import os
import sys
import json
import shutil
import subprocess
from typing import Dict, Any, Optional

APK_EDITOR_STUDIO_DIR = r"C:\Program Files (x86)\APK Editor Studio\tools"

def find_java() -> Optional[Dict[str, str]]:
    """البحث عن مفسر الجافا والتحقق من إصداره."""
    candidates = []
    
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidates.append(os.path.join(java_home, "bin", "java.exe"))
        candidates.append(os.path.join(java_home, "bin", "java"))
        
    # مسار Android Studio JBR المعتاد
    candidates.append(r"C:\Program Files\Android\Android Studio\jbr\bin\java.exe")
    candidates.append(r"C:\Program Files\Android\Android Studio\jre\bin\java.exe")
    
    # مسار النظام PATH
    sys_java = shutil.which("java")
    if sys_java:
        candidates.append(sys_java)
        
    for p in candidates:
        if p and os.path.exists(p):
            try:
                proc = subprocess.run([p, "-version"], capture_output=True, text=True, timeout=5)
                out = (proc.stderr or proc.stdout).strip().splitlines()
                ver = out[0] if out else "Unknown Java version"
                return {
                    "path": p,
                    "version": ver,
                    "is_available": True,
                    "source": "JAVA_HOME" if java_home and java_home in p else "ANDROID_STUDIO_JBR" if "Android Studio" in p else "SYSTEM_PATH"
                }
            except Exception:
                pass
                
    return None

def find_apktool(java_info: Optional[Dict[str, str]] = None) -> Optional[Dict[str, str]]:
    """البحث عن ملف apktool.jar والتحقق من جاهزيته."""
    candidates = [
        (os.path.join(APK_EDITOR_STUDIO_DIR, "apktool.jar"), "APK_EDITOR_STUDIO"),
        (r"tools\analyzer\bin\apktool.jar", "LOCAL_BIN"),
        (shutil.which("apktool.jar") or "", "SYSTEM_PATH"),
        (shutil.which("apktool") or "", "SYSTEM_PATH")
    ]
    
    java_bin = java_info["path"] if java_info and java_info.get("is_available") else "java"
    
    for p, src in candidates:
        if p and os.path.exists(p):
            ver = "Unknown"
            if p.endswith(".jar") and java_bin:
                try:
                    proc = subprocess.run([java_bin, "-jar", p, "--version"], capture_output=True, text=True, timeout=8)
                    ver = proc.stdout.strip() or "Apktool 2.x"
                except Exception:
                    ver = "Apktool (Jar exists)"
            return {
                "path": p,
                "version": ver,
                "is_available": True,
                "source": src
            }
    return None

def find_apksigner(java_info: Optional[Dict[str, str]] = None) -> Optional[Dict[str, str]]:
    """البحث عن apksigner والتحقق من إصدارها."""
    candidates = [
        (os.path.join(APK_EDITOR_STUDIO_DIR, "apksigner.jar"), "APK_EDITOR_STUDIO"),
        (shutil.which("apksigner.bat") or "", "SYSTEM_PATH"),
        (shutil.which("apksigner") or "", "SYSTEM_PATH")
    ]
    
    java_bin = java_info["path"] if java_info and java_info.get("is_available") else "java"
    
    for p, src in candidates:
        if p and os.path.exists(p):
            ver = "0.9+"
            if p.endswith(".jar") and java_bin:
                try:
                    proc = subprocess.run([java_bin, "-jar", p, "--version"], capture_output=True, text=True, timeout=5)
                    ver = proc.stdout.strip() or ver
                except Exception:
                    pass
            return {
                "path": p,
                "version": ver,
                "is_available": True,
                "source": src
            }
    return None

def find_zipalign() -> Optional[Dict[str, str]]:
    """البحث عن أداة المحاذاة zipalign."""
    candidates = [
        (os.path.join(APK_EDITOR_STUDIO_DIR, "zipalign.exe"), "APK_EDITOR_STUDIO"),
        (shutil.which("zipalign.exe") or "", "SYSTEM_PATH"),
        (shutil.which("zipalign") or "", "SYSTEM_PATH")
    ]
    
    for p, src in candidates:
        if p and os.path.exists(p):
            return {
                "path": p,
                "version": "Android ZipAlign v1.0",
                "is_available": True,
                "source": src
            }
    return None

def find_adb() -> Optional[Dict[str, str]]:
    """البحث عن أداة جسر أندرويد ADB."""
    candidates = [
        (os.path.join(APK_EDITOR_STUDIO_DIR, "adb.exe"), "APK_EDITOR_STUDIO"),
        (shutil.which("adb.exe") or "", "SYSTEM_PATH"),
        (shutil.which("adb") or "", "SYSTEM_PATH")
    ]
    
    for p, src in candidates:
        if p and os.path.exists(p):
            ver = "ADB"
            try:
                proc = subprocess.run([p, "version"], capture_output=True, text=True, timeout=5)
                lines = proc.stdout.strip().splitlines()
                ver = lines[0] if lines else "ADB"
            except Exception:
                pass
            return {
                "path": p,
                "version": ver,
                "is_available": True,
                "source": src
            }
    return None

def find_demo_keystore() -> Optional[Dict[str, str]]:
    """البحث عن شهادة ومفتاح التوقيع الجاهز demo.jks."""
    candidates = [
        (os.path.join(APK_EDITOR_STUDIO_DIR, "demo.jks"), "APK_EDITOR_STUDIO"),
        (r"tools\analyzer\bin\demo.jks", "LOCAL_BIN")
    ]
    
    for p, src in candidates:
        if p and os.path.exists(p):
            return {
                "path": p,
                "version": "JKS Keystore (pass: android / alias: androiddebugkey)",
                "is_available": True,
                "source": src
            }
    return None

def detect_toolchain() -> Dict[str, Any]:
    """فحص شامل لجميع الأدوات وتوليد تقرير بحالة الجاهزية للتعديل والبناء."""
    java = find_java()
    apktool = find_apktool(java)
    apksigner = find_apksigner(java)
    zipalign = find_zipalign()
    adb = find_adb()
    demo_ks = find_demo_keystore()
    
    can_decompile = bool(java and apktool)
    can_rebuild = bool(java and apktool)
    can_align = bool(zipalign)
    can_sign = bool(java and apksigner and demo_ks)
    
    is_ready = can_decompile and can_rebuild and can_align and can_sign
    
    suite_dir = APK_EDITOR_STUDIO_DIR if os.path.exists(APK_EDITOR_STUDIO_DIR) else None
    
    return {
        "status": "success",
        "is_ready_for_modding": is_ready,
        "can_decompile": can_decompile,
        "can_rebuild": can_rebuild,
        "can_align": can_align,
        "can_sign": can_sign,
        "detected_suite_path": suite_dir,
        "tools": {
            "java": java or {"is_available": False, "error": "Java Runtime (JRE/JDK) not found"},
            "apktool": apktool or {"is_available": False, "error": "apktool.jar not found"},
            "apksigner": apksigner or {"is_available": False, "error": "apksigner.jar not found"},
            "zipalign": zipalign or {"is_available": False, "error": "zipalign.exe not found"},
            "adb": adb or {"is_available": False, "error": "adb.exe not found"},
            "keystore": demo_ks or {"is_available": False, "error": "demo.jks not found"}
        }
    }

def main():
    res = detect_toolchain()
    print(json.dumps(res, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
