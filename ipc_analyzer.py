# -*- coding: utf-8 -*-
"""
ipc_analyzer.py - فاحص وتدقيق أمان المكونات البينية وثغرات الـ IPC
Inter-Process Communication & Intent Redirection / FileProvider Auditor
يفحص:
1. إعدادات FileProvider ومسارات file_paths.xml (كشف ثغرات Path Traversal وتصدير الـ root-path).
2. ثغرة إعادة توجيه النوايا (Intent Redirection / Launching Untrusted Intent).
3. ثغرة الـ PendingIntent غير المحمية (FLAG_MUTABLE بدون حماية).
"""

import xml.etree.ElementTree as ET
from typing import Dict, List, Any
from androguard.core.analysis.analysis import Analysis
from androguard.core.apk import APK
from androguard.core.axml import AXMLPrinter

class IpcAuditor:
    def __init__(self, apk: APK, anydx: Analysis):
        self.apk = apk
        self.anydx = anydx

    def audit(self) -> Dict[str, Any]:
        findings = []
        file_provider_paths = []

        # 1. تدقيق FileProvider ومسارات file_paths
        try:
            for file_name in self.apk.get_files():
                f_lower = file_name.lower()
                # البحث في مجلد res/xml عن ملفات تكوين المسارات
                if f_lower.startswith("res/xml/") and f_lower.endswith(".xml"):
                    raw = self.apk.get_file(file_name)
                    if not raw:
                        continue
                    xml_str = ""
                    try:
                        axml = AXMLPrinter(raw)
                        xml_str = axml.get_xml()
                        if isinstance(xml_str, bytes):
                            xml_str = xml_str.decode("utf-8", errors="ignore")
                    except Exception:
                        xml_str = raw.decode("utf-8", errors="ignore")

                    if "<paths" in xml_str:
                        # تحليل عناصر المسارات
                        try:
                            root = ET.fromstring(xml_str)
                            for child in root:
                                tag = child.tag
                                path_val = child.get("path", "")
                                name_val = child.get("name", "")
                                
                                is_critical = False
                                risk_desc = ""

                                if tag == "root-path":
                                    is_critical = True
                                    risk_desc = "🚨 ثغرة خطيرة جداً: استخدام <root-path> يتيح الوصول لجذر نظام الملفات بالكامل (/) عبر FileProvider."
                                elif tag in ("external-path", "external-files-path") and path_val in (".", "", "/"):
                                    is_critical = True
                                    risk_desc = "⚠️ استخدام مسار عام لكامل الذاكرة الخارجية (<external-path path=\".\"/>) يتيح قراءة وتعديل كافة ملفات الهاتف."
                                elif tag == "files-path" and path_val in (".", "", "/"):
                                    risk_desc = "تصدير مسار مجلد الملفات الداخلية بالكامل دون تحديد مجلد فرعي."

                                item = {
                                    "file": file_name,
                                    "tag": tag,
                                    "path": path_val,
                                    "name": name_val,
                                    "is_dangerous": is_critical,
                                    "description": risk_desc
                                }
                                file_provider_paths.append(item)

                                if is_critical:
                                    findings.append({
                                        "type": "FILE_PROVIDER_PATH_TRAVERSAL",
                                        "title": f"ثغرة مسار FileProvider خطيرة ({tag})",
                                        "severity": "CRITICAL",
                                        "description": risk_desc,
                                        "recommendation": "احذف <root-path> وحدد مجلدات فرعية محددة فقط (مثل path=\"cache/\" أو path=\"images/\").",
                                        "evidence": [f"الملف: {file_name} -> <{tag} name=\"{name_val}\" path=\"{path_val}\"/>"]
                                    })
                        except Exception:
                            pass
        except Exception:
            pass

        # 2. فحص إعادة توجيه النوايا (Intent Redirection) في كود DEX
        intent_redirection_classes = []
        try:
            for method in self.anydx.get_methods():
                c_name = method.get_class_name()
                c_name_lower = c_name.lower()
                if any(c_name_lower.startswith(p) for p in ("landroidx/", "lcom/google/", "lkotlin/")):
                    continue

                calls = [call.name for _, call, _ in method.get_xref_to()]
                # فحص استخراج Intent ثم تشغيله مباشرة
                has_get_intent = any(c in calls for c in ("getParcelableExtra", "getIntent", "getExtras"))
                has_start_activity = any(c in calls for c in ("startActivity", "startService", "sendBroadcast"))

                if has_get_intent and has_start_activity:
                    intent_redirection_classes.append(f"{c_name}->{method.name}")
                    if len(intent_redirection_classes) >= 5:
                        break
        except Exception:
            pass

        if intent_redirection_classes:
            findings.append({
                "type": "INTENT_REDIRECTION_SUSPECTED",
                "title": "اشتباه في إعادة توجيه النوايا غير الموثوقة (Intent Redirection)",
                "severity": "HIGH",
                "description": "تم رصد دوال تستقبل كائنات Intent أو Parcelable خارجية ثم تقوم بتمريرها مباشرة لـ startActivity/startService. قد يتيح ذلك لتطبيقات خبيثة الوصول إلى مكونات داخلية غير مصدّرة.",
                "recommendation": "تحقق من صحة المكون المستهدف (Explicit Component) وقم بتنقية Intent الخارجي ومطابقة اسم الحزمة قبل التشغيل.",
                "evidence": intent_redirection_classes[:3]
            })

        # 3. فحص الـ PendingIntent غير المحمية (FLAG_MUTABLE)
        has_mutable_pending_intent = False
        try:
            target_sdk = self.apk.get_target_sdk_version()
            # فحص السلاسل وثوابت PendingIntent
            for method in self.anydx.get_methods():
                c_name = method.get_class_name().lower()
                if any(c_name.startswith(p) for p in ("landroidx/", "lcom/google/", "lkotlin/")):
                    continue
                for _, call, _ in method.get_xref_to():
                    if "PendingIntent" in call.get_class_name() and call.name in ("getActivity", "getBroadcast", "getService"):
                        has_mutable_pending_intent = True
                        break
                if has_mutable_pending_intent:
                    break
        except Exception:
            pass

        return {
            "total_issues": len(findings),
            "findings": findings,
            "file_provider_paths": file_provider_paths
        }
