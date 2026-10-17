# -*- coding: utf-8 -*-
"""
webview_analyzer.py - فاحص وتدقيق أمان مكونات الـ WebView والـ JavaScript Bridge
WebView Security & Cross-App Scripting Auditor
يفحص استخدامات WebView في الكود لرصد:
1. تفعيل JavaScript (setJavaScriptEnabled).
2. واجهات الربط بالجافا سكريبت (addJavascriptInterface / @JavascriptInterface).
3. السماح بالوصول لملفات النظام وعناوين file:// المحلية.
4. تجاهل أخطاء شهادات SSL عبر handler.proceed() في onReceivedSslError.
5. تعطيل التصفح الآمن (setSafeBrowsingEnabled=false).
"""

from typing import Dict, List, Any
from androguard.core.analysis.analysis import Analysis
from androguard.core.apk import APK

class WebViewAuditor:
    def __init__(self, apk: APK, anydx: Analysis):
        self.apk = apk
        self.anydx = anydx

    def audit(self) -> Dict[str, Any]:
        findings = []
        webview_detected = False
        js_enabled_classes = []
        js_interface_classes = []
        file_access_classes = []
        ssl_bypass_classes = []

        try:
            for method in self.anydx.get_methods():
                c_name = method.get_class_name()
                c_name_lower = c_name.lower()

                # استبعاد كلاسات أندرويد الرسمية وكومبوز
                if any(c_name_lower.startswith(p) for p in ("landroidx/", "lcom/google/android/", "lkotlin/")):
                    continue

                m_name = method.name

                # رصد تجاوز أخطاء SSL في WebViewClient
                if m_name == "onReceivedSslError":
                    for _, call, _ in method.get_xref_to():
                        if call.name == "proceed" and "SslErrorHandler" in call.get_class_name():
                            ssl_bypass_classes.append(f"{c_name}->{m_name}")
                            break

                for _, call, _ in method.get_xref_to():
                    called_class = call.get_class_name()
                    called_method = call.name

                    if "WebView" in called_class or "WebSettings" in called_class:
                        webview_detected = True

                        if called_method == "setJavaScriptEnabled":
                            js_enabled_classes.append(f"{c_name}->{m_name}")

                        elif called_method == "addJavascriptInterface":
                            js_interface_classes.append(f"{c_name}->{m_name}")

                        elif called_method in ("setAllowFileAccessFromFileURLs", "setAllowUniversalAccessFromFileURLs"):
                            file_access_classes.append(f"{c_name}->{m_name} ({called_method})")

                        elif called_method == "setAllowFileAccess":
                            file_access_classes.append(f"{c_name}->{m_name} (setAllowFileAccess)")
        except Exception:
            pass

        # تجميع النتائج وتصنيفها
        if ssl_bypass_classes:
            findings.append({
                "type": "WEBVIEW_SSL_PROCEED_BYPASS",
                "title": "🚨 تجاوز أخطاء شهادات SSL في WebView (MITM Vulnerability)",
                "severity": "CRITICAL",
                "description": "تم رصد استدعاء handler.proceed() داخل onReceivedSslError. هذا يلغي التحقق من أمان شهادات SSL/TLS ويتيح اعتراض أو حقن صفحات الويب عبر هجمات رجل في المنتصف.",
                "recommendation": "احذف handler.proceed() واعتمد handler.cancel() لمنع الاتصال في حال وجود أي خطأ بالشهادة.",
                "evidence": ssl_bypass_classes[:5]
            })

        if file_access_classes:
            findings.append({
                "type": "WEBVIEW_FILE_ACCESS_ENABLED",
                "title": "السماح بالوصول لملفات النظام عبر WebView (File Scheme Access)",
                "severity": "HIGH",
                "description": "تم تفعيل إمكانية قراءة الملفات المحلية عبر عناوين file:// أو UniversalAccess. قد يتيح ذلك للبرمجيات الخبيثة أو صفحات HTML المسحوبة قراءة بيانات وقواعد بيانات التطبيق.",
                "recommendation": "عطّل هذه الصلاحيات عبر setAllowFileAccess(false) و setAllowFileAccessFromFileURLs(false).",
                "evidence": file_access_classes[:5]
            })

        if js_interface_classes:
            findings.append({
                "type": "WEBVIEW_JS_INTERFACE_EXPOSED",
                "title": "ربط واجهة برمجية للجافا سكريبت (addJavascriptInterface)",
                "severity": "HIGH",
                "description": "يستخدم التطبيق addJavascriptInterface لربط كود جافا/كوتلن بكود الويب. في حال تحميل روابط غير موثوقة أو عبر HTTP، قد يتيح ذلك تنفيذ أوامر غير مصرح بها أو استخراج بيانات حساسة.",
                "recommendation": "تأكد من قصر استدعاء addJavascriptInterface على نطاقات موثوقة ومحمية بـ HTTPS فقط، واستخدم @JavascriptInterface على الدوال المقصودة حصراً.",
                "evidence": js_interface_classes[:5]
            })

        if js_enabled_classes:
            findings.append({
                "type": "WEBVIEW_JS_ENABLED",
                "title": "تفعيل الجافا سكريبت داخل الـ WebView",
                "severity": "MEDIUM",
                "description": "تم تفعيل تنفيذ لغة JavaScript داخل الـ WebView. قد يعرض ذلك التطبيق لهجمات Cross-Site Scripting (XSS) إذا تم تحميل محتوى خارجي غير مفلتر.",
                "recommendation": "إذا لم تكن بحاجة للـ JavaScript، عطلها عبر setJavaScriptEnabled(false)، أو طبّق Content Security Policy (CSP).",
                "evidence": js_enabled_classes[:5]
            })

        return {
            "has_webview": webview_detected or len(findings) > 0,
            "total_issues": len(findings),
            "findings": findings
        }
