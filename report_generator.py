# report_generator.py
# -*- coding: utf-8 -*-
"""
مولد التقارير المستقل لـ AdbLite APK Inspector.
يولد تقارير HTML تفاعلية (أوفلاين بالكامل مع CSS داخلي) وتقارير Markdown موثقة.
"""

import os
from datetime import datetime
from typing import Dict, Any

class ReportGenerator:
    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.basic = data.get("basic_info", {})
        self.hashes = data.get("hashes", {})
        self.security = data.get("security", {})
        self.risk = self.security.get("risk_assessment", {})
        self.permissions = data.get("permissions", {})
        self.network = data.get("network", {})
        self.dev = data.get("development", {})
        self.components = data.get("components", {})
        self.manifest_security = data.get("manifest_security", {})
        self.app_defenses = data.get("app_defenses", {})
        self.deep_links = data.get("deep_links", {})
        self.native_libs = data.get("native_libraries", {})

    def generate_markdown(self) -> str:
        """توليد تقرير بتنسيق Markdown."""
        app_name = self.basic.get("app_name") or "تطبيق غير معروف"
        package_name = self.basic.get("package_name", "N/A")
        ver_name = self.basic.get("version", {}).get("name", "N/A")
        ver_code = self.basic.get("version", {}).get("code", "N/A")
        risk_level = self.risk.get("risk_level", "LOW")
        risk_score = self.risk.get("risk_score", 0)

        lines = [
            f"# تقرير التدقيق الأمني والفني: {app_name}",
            f"> تاريخ الفحص: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## 1. ملخص التطبيق ومؤشر الأمان",
            f"- **اسم الحزمة**: `{package_name}`",
            f"- **الإصدار**: {ver_name} (كود: {ver_code})",
            f"- **تصنيف التطبيق التلقائي**: `{self.basic.get('inferred_category', 'Tools')}`",
            f"- **حجم الملف**: {self.basic.get('size_mb', 0)} MB",
            f"- **الحد الأدنى لـ SDK**: Android {self.basic.get('sdk_versions', {}).get('min', 'N/A')}",
            f"- **مستوى الخطورة الإجمالي**: **{risk_level}** (درجة الخطر: {risk_score}/100)",
        ]

        ff = self.basic.get("form_factors", {})
        target_devices = []
        if ff.get("is_phone_tablet", True): target_devices.append("الهواتف والأجهزة اللوحية")
        if ff.get("is_wearable"): target_devices.append("ساعات ذكية (Wear OS)")
        if ff.get("is_android_tv"): target_devices.append("تلفزيونات أندرويد (Android TV)")
        if target_devices:
            lines.append(f"- **المنصات المدعومة**: {', '.join(target_devices)}")

        nat_ar = self.basic.get("natural_summary_ar")
        if nat_ar:
            lines.extend([
                "",
                "### 📋 الملخص التنفيذي للقدرات والعتاد:",
                f"> {nat_ar}",
            ])

        lines.extend([
            "",
            "### أسباب التقييم الأمني:",
        ])

        reasons = self.risk.get("reasons", [])
        if reasons:
            for r in reasons:
                lines.append(f"- ⚠️ {r}")
        else:
            lines.append("- ✅ لا توجد مؤشرات خطورة بارزة.")

        lines.extend([
            "",
            "## 2. البصمات الرقمية (Hashes)",
            f"- **SHA-256**: `{self.hashes.get('sha256', 'N/A')}`",
            f"- **SHA-1**: `{self.hashes.get('sha1', 'N/A')}`",
            f"- **MD5**: `{self.hashes.get('md5', 'N/A')}`",
            "",
            "## 3. الصلاحيات والخصوصية",
            f"- **إجمالي الصلاحيات**: {len(self.permissions.get('all_permissions', []))}",
            f"- **الصلاحيات الخطرة**: {len(self.permissions.get('dangerous_permissions', []))}",
        ])

        dangerous = self.permissions.get("dangerous_permissions", [])
        if dangerous:
            lines.append("\n### قائمة الصلاحيات الخطرة:")
            for p in dangerous:
                lines.append(f"- 🔴 `{p}`")

        # التوقيع الرقمي
        sig = self.security.get("signatures", {})
        lines.extend([
            "",
            "## 4. التوقيع الرقمي والشهادات",
            f"- **حالة التوقيع**: {'✅ موقّع' if sig.get('is_signed') else '❌ غير موقّع'}",
        ])
        for cert in sig.get("certificates", []):
            lines.append(f"- **جهة الإصدار**: {cert.get('issuer')}")
            lines.append(f"- **بصمة الشهادة (SHA-256)**: `{cert.get('sha256')}`")

        # الشبكة والاتصالات
        lines.extend([
            "",
            "## 5. عناوين IP والنطاقات المستخرجة",
            f"- **عناوين IP المكتشفة**: {len(self.network.get('ip_addresses', []))}",
        ])
        for ip in self.network.get("ip_addresses", [])[:15]:
            lines.append(f"- `{ip}`")

        # البيئة البرمجية والمعمارية
        frameworks = self.dev.get("languages_frameworks", {})
        arch = self.dev.get("architecture", {})
        lines.extend([
            "",
            "## 6. بيئة التطوير والمعمارية البرمجية",
            f"- **لغة البرمجة**: {'Kotlin' if frameworks.get('is_kotlin') else ''} {'Java' if frameworks.get('is_java') else ''}".strip(),
            f"- **إطار العمل**: {'Flutter' if frameworks.get('is_flutter') else ''} {'React Native' if frameworks.get('is_react_native') else ''} {'Jetpack Compose' if frameworks.get('has_compose') else ''}".strip(),
            f"- **شبكات الإعلانات**: {'نعم' if self.dev.get('ads', {}).get('has_ads') else 'خالي من الإعلانات'}",
        ])

        if arch:
            lines.append("\n### المعمارية البرمجية وطبقات البناء (Architecture Profile):")
            if arch.get("local_storage"):
                lines.append(f"- **التخزين وقواعد البيانات**: {', '.join(arch.get('local_storage'))}")
            if arch.get("state_management"):
                lines.append(f"- **إدارة الحالة**: {', '.join(arch.get('state_management'))}")
            if arch.get("dependency_injection"):
                lines.append(f"- **حقن التبعيات (DI)**: {', '.join(arch.get('dependency_injection'))}")
            if arch.get("background_tasks"):
                lines.append(f"- **معالجة المهام الخلفية**: {', '.join(arch.get('background_tasks'))}")
            if arch.get("networking_stack"):
                lines.append(f"- **مكتبات الاتصال والشبكات**: {', '.join(arch.get('networking_stack'))}")

        # التوطين واللغات المدعومة
        loc = self.data.get("resources_summary", {}).get("localization", {})
        if loc:
            lines.extend([
                "",
                "### 🌐 التوطين واللغات المدعومة:",
                f"- **دعم اللغة العربية**: {'✅ مدعومة بالكامل' if loc.get('supports_arabic') else '❌ غير مدعومة'}",
                f"- **اللغة الافتراضية**: `{loc.get('default_language', 'en')}`",
                f"- **إجمالي اللغات المتوفرة**: {loc.get('total_locales', 0)} لغة",
            ])
            sample_locales = loc.get("supported_locales", [])[:20]
            if sample_locales:
                lines.append(f"- **نماذج من اللغات**: `{', '.join(sample_locales)}`")

        # الأسرار ومفاتيح الـ API المسربة
        secrets = self.data.get("secrets", [])
        if secrets:
            lines.extend([
                "",
                f"## 7. كشف الأسرار ومفاتيح الـ API المسربة ({len(secrets)})",
            ])
            for s in secrets:
                lines.append(f"- ⚠️ **{s.get('name')}** [{s.get('severity')}]: `{s.get('masked_value')}` (الموقع: {s.get('location')})")
                lines.append(f"  - *الوصف*: {s.get('description')}")

        # 8. فحص ثغرة Janus ومفتاح التصحيح والـ Keystores المنسية
        janus = self.security.get("janus_vulnerability", {})
        debug_cert = self.security.get("debug_certificate", {})
        leaked_ks = self.security.get("leaked_keystores", {})
        lines.extend([
            "",
            "## 8. تدقيق الشهادات وثغرة Janus والملفات المسربة",
            f"- **ثغرة Janus (CVE-2017-13156)**: {'🚨 عرضة للاختراق!' if janus.get('is_vulnerable') else '✅ محصن (v2/v3)'}",
            f"  - *التفاصيل*: {janus.get('description', 'N/A')}",
            f"- **شهادة التصحيح الافتراضية**: {'🚨 موقّع بمفتاح Debug!' if debug_cert.get('is_debug_signed') else '✅ مفتاح إصدار رسمي'}",
            f"- **ملفات المفاتيح والشهادات المنسية**: {leaked_ks.get('total_leaked', 0)} ملف",
        ])
        for kf in leaked_ks.get("files", []):
            lines.append(f"  - 🔴 `{kf.get('path')}` ({round(kf.get('size_bytes', 0)/1024, 1)} KB) - {kf.get('description')}")

        # 9. التدقيق العميق للمانيفست والمكونات المكشوفة
        manifest_audit = self.data.get("manifest_audit", {})
        if manifest_audit:
            lines.extend([
                "",
                "## 9. التدقيق العميق للمانيفست والمكونات المكشوفة",
                f"- **إجمالي المكونات**: {manifest_audit.get('total_components', 0)}",
                f"- **المكونات المصدرة (Exported)**: {manifest_audit.get('exported_count', 0)}",
                f"- **المكونات المكشوفة دون حماية**: {manifest_audit.get('unprotected_count', 0)}",
            ])
            for comp in manifest_audit.get("components", []):
                if comp.get("is_exported") and comp.get("risk_level") in ("DANGEROUS", "WARNING"):
                    lines.append(f"- ⚠️ `[{comp.get('type')}]` **{comp.get('name')}** - {comp.get('warning_message')}")

        # 10. فحص تكوين أمان الشبكة
        nsc = self.network.get("security_config", {})
        if nsc:
            lines.extend([
                "",
                "## 10. فحص تكوين أمان الشبكة (Network Security Config)",
                f"- **ملف التكوين**: {'✅ موجود: ' + str(nsc.get('config_path')) if nsc.get('has_config') else 'غير مخصص'}",
                f"- **حركة المرور غير المشفرة (Cleartext HTTP)**: {'⚠️ مسموح' if nsc.get('cleartext_traffic_permitted') else '🛡️ محظورة'}",
                f"- **الوثوق بشهادات المستخدم (User CA)**: {'🚨 مسموح (عرضة لـ MITM)' if nsc.get('user_certificates_trusted') else '✅ شهادات النظام فقط'}",
                f"- **تثبيت الشهادات (Certificate Pinning)**: {'🔒 مفعل' if nsc.get('has_pin_set') else 'غير مفعل'}",
            ])
            for finding in nsc.get("findings", []):
                lines.append(f"  - {finding}")

        # 11. متتبعات الخصوصية (Exodus Privacy)
        exodus = self.dev.get("exodus_trackers", {})
        if exodus:
            lines.extend([
                "",
                f"## 11. متتبعات الخصوصية وشبكات التتبع المكتشفة ({exodus.get('total_detected', 0)})",
            ])
            for t in exodus.get("trackers", []):
                cats = ", ".join(t.get("categories", []))
                lines.append(f"- 🕵️ **{t.get('name')}** ({cats}) - [الموقع]({t.get('website')})")

        # 12. تدقيق سمات الأمان في المانيفست (Manifest Security Flags)
        if self.manifest_security:
            flags = self.manifest_security.get("flags", {})
            findings = self.manifest_security.get("findings", [])
            lines.extend([
                "",
                "## 12. سمات الأمان في المانيفست (Manifest Security Flags)",
                f"- **وضع التصحيح (Debuggable)**: {'🚨 مفعل (خطر حرج)' if flags.get('debuggable') else '✅ معطل (آمن)'}",
                f"- **النسخ الاحتياطي (AllowBackup)**: {'⚠️ مفعل (يمكن استخراج البيانات)' if flags.get('allow_backup') else '✅ معطل (محمي)'}",
                f"- **حركة المرور غير المشفرة (Cleartext HTTP)**: {'⚠️ مسموح' if flags.get('uses_cleartext_traffic') else '🛡️ غير مسموح'}",
                f"- **نسخة اختبارية (TestOnly)**: {'⚠️ نعم' if flags.get('test_only') else '✅ لا'}",
                f"- **حماية النوافذ من التراكب (Tapjacking)**: {flags.get('tapjacking_protected_activities', 0)} من أصل {flags.get('total_activities', 0)} أنشطة محمية",
            ])
            if findings:
                lines.append("\n### ملاحظات وتنبيهات السمات:")
                for f in findings:
                    sev = f.get("severity", "INFO")
                    icon = "🚨" if sev == "CRITICAL" else "⚠️" if sev in ("HIGH", "WARNING") else "✅"
                    lines.append(f"- {icon} `[{f.get('flag')}]`: {f.get('message')}")

        # 13. آليات الدفاع الذاتي والحماية من التلاعب (Anti-Tampering & Security Defenses)
        if self.app_defenses:
            root = self.app_defenses.get("root_detection", {})
            emu = self.app_defenses.get("emulator_detection", {})
            dbg = self.app_defenses.get("anti_debugging", {})
            screen = self.app_defenses.get("screen_security", {})
            lines.extend([
                "",
                "## 13. آليات الدفاع الذاتي والحماية من التلاعب (App Defenses)",
                f"- **كشف كسر الحماية (Root Detection)**: {'🛡️ مفعل (درجة الثقة: ' + root.get('confidence', 'NONE') + ')' if root.get('enabled') else '❌ غير مكتشف'}",
                f"- **كشف بيئات المحاكاة (Emulator Detection)**: {'🛡️ مفعل (درجة الثقة: ' + emu.get('confidence', 'NONE') + ')' if emu.get('enabled') else '❌ غير مكتشف'}",
                f"- **مكافحة التنقيح (Anti-Debugging)**: {'🛡️ مفعل' if dbg.get('enabled') else '❌ غير مكتشف'}",
                f"- **حماية الشاشة ولقطات النوافذ (FLAG_SECURE)**: {'🛡️ مفعل' if screen.get('enabled') else '❌ غير مكتشف'}",
            ])
            all_indicators = []
            for def_name, def_obj in [("الروت", root), ("المحاكي", emu), ("التنقيح", dbg), ("الشاشة", screen)]:
                if def_obj.get("indicators"):
                    all_indicators.append(f"- **مؤشرات {def_name}**: " + ", ".join([f"`{i}`" for i in def_obj.get("indicators")[:5]]))
            if all_indicators:
                lines.append("\n### المؤشرات المكتشفة:")
                lines.extend(all_indicators)

        # 14. الروابط العميقة وروابط التطبيقات (Deep Links & App Links)
        if self.deep_links:
            total_dl = self.deep_links.get("total_deep_links", 0)
            schemes = self.deep_links.get("unique_schemes", [])
            hosts = self.deep_links.get("unique_hosts", [])
            links = self.deep_links.get("links", [])
            lines.extend([
                "",
                f"## 14. الروابط العميقة وروابط التطبيقات ({total_dl})",
                f"- **المخططات المدعومة (Schemes)**: {', '.join([f'`{s}`' for s in schemes]) if schemes else 'لا يوجد'}",
                f"- **النطاقات المستهدفة (Hosts)**: {', '.join([f'`{h}`' for h in hosts]) if hosts else 'لا يوجد'}",
            ])
            if links:
                lines.append("\n### عينة من الروابط العميقة:")
                for l in links[:12]:
                    av_badge = " [AutoVerify]" if l.get("auto_verify") else ""
                    lines.append(f"- 🔗 `{l.get('full_uri')}` -> **{l.get('activity')}**{av_badge}")

        # 15. المكتبات البرمجية الأصلية C/C++ (Native Libraries)
        if self.native_libs:
            has_native = self.native_libs.get("has_native_libraries", False)
            abis = self.native_libs.get("architectures", [])
            tot_libs = self.native_libs.get("total_libraries", 0)
            libs_sample = self.native_libs.get("libraries_sample", [])
            sens_strings = self.native_libs.get("extracted_sensitive_strings", [])
            lines.extend([
                "",
                f"## 15. المكتبات البرمجية الأصلية C/C++ (Native Libraries)",
                f"- **تحتوي مكتبات أصلية (.so)**: {'نعم' if has_native else 'لا'}",
                f"- **المعماريات المدعومة (ABIs)**: {', '.join([f'`{a}`' for a in abis]) if abis else 'N/A'}",
                f"- **إجمالي ملفات .so**: {tot_libs}",
            ])
            if libs_sample:
                lines.append("\n### عينة من المكتبات:")
                for lib in libs_sample[:8]:
                    lines.append(f"- ⚙️ `{lib.get('name')}` (`{lib.get('abi')}`) - {lib.get('size_kb')} KB")
            if sens_strings:
                lines.append("\n### نصوص وعناوين مستخرجة من المكتبات الأصلية:")
                for s in sens_strings[:10]:
                    lines.append(f"- 🔍 `{s}`")

        lines.extend([
            "",
            "---",
            f"تم توليد التقرير تلقائياً بواسطة AdbLite Inspector v2.0 - Connect Tag",
        ])

        return "\n".join(lines)

    def generate_html(self) -> str:
        """توليد تقرير تفاعلي HTML مستقل تماماً وأوفلاين مع واجهة RTL احترافية."""
        app_name = self.basic.get("app_name") or "تطبيق غير معروف"
        package_name = self.basic.get("package_name", "N/A")
        ver_name = self.basic.get("version", {}).get("name", "N/A")
        ver_code = self.basic.get("version", {}).get("code", "N/A")
        risk_level = self.risk.get("risk_level", "LOW").upper()
        risk_score = self.risk.get("risk_score", 0)

        risk_color = {
            "CRITICAL": "#d32f2f",
            "HIGH": "#e64a19",
            "MEDIUM": "#f57c00",
            "LOW": "#388e3c"
        }.get(risk_level, "#388e3c")

        dangerous_perms = self.permissions.get("dangerous_permissions", [])
        all_perms = self.permissions.get("all_permissions", [])
        ips = self.network.get("ip_addresses", [])
        certs = self.security.get("signatures", {}).get("certificates", [])
        sig_signed = self.security.get("signatures", {}).get("is_signed", False)

        dangerous_html = "".join([f"<li class='danger-item'>{p}</li>" for p in dangerous_perms]) or "<li>لا توجد صلاحيات خطرة</li>"
        all_perms_html = "".join([f"<li>{p}</li>" for p in all_perms]) or "<li>لا توجد صلاحيات مطلوبة</li>"
        ips_html = "".join([f"<code>{ip}</code> " for ip in ips[:30]]) or "لم يتم العثور على عناوين IP ثابتة"

        reasons_html = "".join([f"<li>{r}</li>" for r in self.risk.get("reasons", [])]) or "<li>لم تُسجل أي مؤشرات خطورة</li>"

        certs_html = ""
        for c in certs:
            certs_html += f"""
            <div class="cert-box">
                <p><strong>جهة الإصدار:</strong> {c.get('issuer')}</p>
                <p><strong>بصمة SHA-256:</strong> <code>{c.get('sha256')}</code></p>
            </div>
            """

        secrets = self.data.get("secrets", [])
        if secrets:
            secrets_items = []
            for s in secrets:
                sev_color = "#ef4444" if s.get("severity") == "CRITICAL" else "#f97316"
                secrets_items.append(f"<li style='margin-bottom:8px;'><span style='color:{sev_color}; font-weight:bold;'>[{s.get('severity')}] {s.get('name')}</span>: <code>{s.get('masked_value')}</code><br><small style='color:var(--text-secondary);'>الموقع: {s.get('location')} | {s.get('description')}</small></li>")
            secrets_html = f"""
            <div class="card" style="margin-bottom: 24px; border: 1px solid #ef4444; background: rgba(239, 68, 68, 0.05);">
                <h3 style="color: #f87171; border-color: rgba(239, 68, 68, 0.3);">🚨 كشف الأسرار ومفاتيح الـ API المسربة ({len(secrets)})</h3>
                <ul>{''.join(secrets_items)}</ul>
            </div>
            """
        else:
            secrets_html = ""

        # فحص ثغرة Janus ومفتاح التصحيح والـ Keystores
        janus = self.security.get("janus_vulnerability", {})
        debug_cert = self.security.get("debug_certificate", {})
        leaked_ks = self.security.get("leaked_keystores", {})

        alerts_html = ""
        if janus.get("is_vulnerable"):
            alerts_html += f"""
            <div class="card" style="margin-bottom: 16px; border: 1px solid #ef4444; background: rgba(239, 68, 68, 0.08);">
                <h3 style="color: #f87171;">🚨 تنبيه: ثغرة Janus (CVE-2017-13156) مكتشفة!</h3>
                <p style="font-size:13px;">{janus.get('description')}</p>
            </div>
            """
        if debug_cert.get("is_debug_signed"):
            alerts_html += f"""
            <div class="card" style="margin-bottom: 16px; border: 1px solid #ef4444; background: rgba(239, 68, 68, 0.08);">
                <h3 style="color: #f87171;">🚨 تحذير حرج: توقيع بشهادة التصحيح الافتراضية (Debug Key)</h3>
                <p style="font-size:13px;">{debug_cert.get('message')}</p>
            </div>
            """
        if leaked_ks.get("has_leaked_keystores"):
            ks_items = "".join([f"<li><code>{f.get('path')}</code> ({round(f.get('size_bytes', 0)/1024, 1)} KB) - <strong style='color:#f87171;'>[{f.get('risk')}]</strong> {f.get('description')}</li>" for f in leaked_ks.get("files", [])])
            alerts_html += f"""
            <div class="card" style="margin-bottom: 16px; border: 1px solid #f97316; background: rgba(249, 115, 22, 0.08);">
                <h3 style="color: #fb923c;">🔑 ملفات مفاتيح وشهادات منسية ومسربة داخل الـ APK ({leaked_ks.get('total_leaked', 0)})</h3>
                <ul>{ks_items}</ul>
            </div>
            """

        # تدقيق المانيفست والمكونات المكشوفة
        manifest_audit = self.data.get("manifest_audit", {})
        manifest_html = ""
        if manifest_audit:
            unprotected = manifest_audit.get("unprotected_count", 0)
            exported = manifest_audit.get("exported_count", 0)
            total = manifest_audit.get("total_components", 0)
            comp_items = []
            for comp in manifest_audit.get("components", []):
                if comp.get("is_exported"):
                    color = "#f87171" if comp.get("risk_level") == "DANGEROUS" else "#fb923c" if comp.get("risk_level") == "WARNING" else "#4ade80"
                    comp_items.append(f"<li><span style='color:{color}; font-weight:bold;'>[{comp.get('type')}]</span> <code>{comp.get('name')}</code><br><small style='color:var(--text-secondary);'>{comp.get('warning_message')}</small></li>")

            manifest_html = f"""
            <div class="card" style="margin-bottom: 24px;">
                <h3>🧩 التدقيق الأمني لمكونات التطبيق والمانيفست</h3>
                <p>إجمالي المكونات: <strong>{total}</strong> | المكونات المصدرة: <strong>{exported}</strong> | المكشوفة دون حماية: <strong style='color:#f87171;'>{unprotected}</strong></p>
                <ul style="max-height: 250px; overflow-y: auto;">{''.join(comp_items[:30])}</ul>
            </div>
            """

        # تكوين أمان الشبكة
        nsc = self.network.get("security_config", {})
        nsc_html = ""
        if nsc:
            findings_html = "".join([f"<li>{f}</li>" for f in nsc.get("findings", [])])
            nsc_html = f"""
            <div class="card" style="margin-bottom: 24px;">
                <h3>🌐 تدقيق تكوين أمان الشبكة (Network Security Config)</h3>
                <p>الملف: <strong>{nsc.get('config_path') or 'تكوين افتراضي'}</strong> | Cleartext HTTP: <strong>{'⚠️ مسموح' if nsc.get('cleartext_traffic_permitted') else '🛡️ محظور'}</strong> | User CA: <strong>{'🚨 مسموح' if nsc.get('user_certificates_trusted') else '✅ محظور'}</strong></p>
                <ul>{findings_html}</ul>
            </div>
            """

        # متتبعات Exodus Privacy
        exodus = self.dev.get("exodus_trackers", {})
        exodus_html = ""
        if exodus:
            t_items = []
            for t in exodus.get("trackers", []):
                cats = ", ".join(t.get("categories", []))
                t_items.append(f"<li><strong>{t.get('name')}</strong> <span style='background:#334155; padding:2px 6px; border-radius:4px; font-size:11px;'>{cats}</span> - <a href='{t.get('website')}' target='_blank' style='color:#38bdf8;'>{t.get('website')}</a></li>")
            exodus_html = f"""
            <div class="card" style="margin-bottom: 24px;">
                <h3>🕵️ متتبعات الخصوصية وشبكات التتبع المكتشفة ({exodus.get('total_detected', 0)})</h3>
                <ul>{''.join(t_items) if t_items else '<li>لم يتم العثور على متتبعات خصوصية معروفة.</li>'}</ul>
            </div>
            """

        # 1. سمات الأمان في المانيفست (Manifest Security Flags)
        manifest_sec = self.manifest_security
        manifest_sec_html = ""
        if manifest_sec:
            flags = manifest_sec.get("flags", {})
            findings = manifest_sec.get("findings", [])

            dbg_bg = "#ef4444" if flags.get("debuggable") else "#22c55e"
            dbg_text = "🚨 مفعّل (خطر)" if flags.get("debuggable") else "✅ معطّل (آمن)"

            backup_bg = "#f97316" if flags.get("allow_backup") else "#22c55e"
            backup_text = "⚠️ مفعّل (ADB)" if flags.get("allow_backup") else "✅ معطّل"

            clear_bg = "#ef4444" if flags.get("uses_cleartext_traffic") else "#22c55e"
            clear_text = "⚠️ مسموح" if flags.get("uses_cleartext_traffic") else "🛡️ محظور"

            tapjack_count = flags.get("tapjacking_protected_activities", 0)
            total_acts = flags.get("total_activities", 0)

            findings_items = []
            for f in findings:
                sev = f.get("severity", "INFO")
                col = "#f87171" if sev == "CRITICAL" else "#fb923c" if sev in ("HIGH", "WARNING") else "#4ade80"
                findings_items.append(f"<li><span style='color:{col}; font-weight:bold;'>[{f.get('flag')}]</span> {f.get('message')}</li>")

            manifest_sec_html = f"""
            <div class="card" style="margin-bottom: 24px;">
                <h3>🛡️ سمات الأمان في المانيفست (Manifest Security Flags)</h3>
                <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 14px;">
                    <span style="background: {dbg_bg}; color: #fff; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: bold;">
                        Debuggable: {dbg_text}
                    </span>
                    <span style="background: {backup_bg}; color: #fff; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: bold;">
                        AllowBackup: {backup_text}
                    </span>
                    <span style="background: {clear_bg}; color: #fff; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: bold;">
                        Cleartext Traffic: {clear_text}
                    </span>
                    <span style="background: #334155; color: #fff; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: bold;">
                        حماية Tapjacking: {tapjack_count}/{total_acts} أنشطة
                    </span>
                </div>
                <ul>{''.join(findings_items) if findings_items else '<li>لم تسجل ملاحظات خاصة بالسمات.</li>'}</ul>
            </div>
            """

        # 2. آليات الدفاع الذاتي والحماية من التلاعب (App Defenses)
        app_def = self.app_defenses
        defenses_html = ""
        if app_def:
            root = app_def.get("root_detection", {})
            emu = app_def.get("emulator_detection", {})
            dbg = app_def.get("anti_debugging", {})
            screen = app_def.get("screen_security", {})

            def _def_block(obj, label):
                enabled = obj.get("enabled", False)
                conf = obj.get("confidence", "NONE")
                status = f"🛡️ مفعّل ({conf})" if enabled else "❌ غير مكتشف"
                col = "#22c55e" if enabled else "#64748b"
                inds = obj.get("indicators", [])
                inds_str = ", ".join(inds[:4]) if inds else "لا توجد مؤشرات"
                return f"""
                <div style="background: #090d16; padding: 12px; border-radius: 8px; border-right: 4px solid {col};">
                    <div style="font-weight: bold; font-size: 13px; color: #fff;">{label}</div>
                    <div style="font-size: 12px; color: {col}; margin: 4px 0;">{status}</div>
                    <small style="color: var(--text-secondary); display: block; font-size: 11px; word-break: break-all;">{inds_str}</small>
                </div>
                """

            defenses_html = f"""
            <div class="card" style="margin-bottom: 24px;">
                <h3>🛡️ آليات الدفاع الذاتي ومكافحة الهندسة العكسية (Anti-Tampering & App Defenses)</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px;">
                    {_def_block(root, "كشف كسر الحماية (Root)")}
                    {_def_block(emu, "كشف بيئات المحاكاة (Emulator)")}
                    {_def_block(dbg, "مكافحة التنقيح (Anti-Debug)")}
                    {_def_block(screen, "حماية الشاشة (FLAG_SECURE)")}
                </div>
            </div>
            """

        # 3. الروابط العميقة (Deep Links)
        dl = self.deep_links
        deep_links_html = ""
        if dl and dl.get("total_deep_links", 0) > 0:
            tot = dl.get("total_deep_links", 0)
            schemes = " ".join([f"<code>{s}</code>" for s in dl.get("unique_schemes", [])]) or "لا يوجد"
            hosts = " ".join([f"<code>{h}</code>" for h in dl.get("unique_hosts", [])]) or "لا يوجد"
            link_items = []
            for l in dl.get("links", [])[:20]:
                av = " <span style='background:#15803d; color:#fff; padding:1px 5px; border-radius:3px; font-size:10px;'>AutoVerify</span>" if l.get("auto_verify") else ""
                link_items.append(f"<li><code>{l.get('full_uri')}</code> &rarr; <strong>{l.get('activity')}</strong>{av}</li>")

            deep_links_html = f"""
            <div class="card" style="margin-bottom: 24px;">
                <h3>🔗 الروابط العميقة وروابط التطبيقات (Deep Links) ({tot})</h3>
                <p style="font-size: 13px;"><strong>المخططات:</strong> {schemes} | <strong>النطاقات:</strong> {hosts}</p>
                <ul style="max-height: 220px; overflow-y: auto;">{''.join(link_items)}</ul>
            </div>
            """

        # 4. المكتبات البرمجية الأصلية C/C++
        nl = self.native_libs
        native_libs_html = ""
        if nl and nl.get("has_native_libraries", False):
            tot = nl.get("total_libraries", 0)
            abis = " ".join([f"<span style='background:#334155; color:#38bdf8; padding:2px 8px; border-radius:4px; font-size:12px;'>{a}</span>" for a in nl.get("architectures", [])])
            lib_items = []
            for lib in nl.get("libraries_sample", [])[:15]:
                lib_items.append(f"<li><code>{lib.get('name')}</code> ({lib.get('abi')}) - <span style='color:var(--text-secondary);'>{lib.get('size_kb')} KB</span></li>")

            strings_html = ""
            sens = nl.get("extracted_sensitive_strings", [])
            if sens:
                s_items = "".join([f"<li><code>{s}</code></li>" for s in sens[:10]])
                strings_html = f"<div style='margin-top: 10px;'><strong style='color:#fb923c; font-size:12px;'>نصوص وعناوين مستخرجة من ملفات .so:</strong><ul style='max-height: 120px; overflow-y: auto;'>{s_items}</ul></div>"

            native_libs_html = f"""
            <div class="card" style="margin-bottom: 24px;">
                <h3>⚙️ المكتبات البرمجية الأصلية C/C++ ({tot})</h3>
                <div style="margin-bottom: 10px;"><strong>المعماريات المدعومة:</strong> {abis}</div>
                <ul style="max-height: 180px; overflow-y: auto;">{''.join(lib_items)}</ul>
                {strings_html}
            </div>
            """

        html_template = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تقرير التدقيق الأمني - {app_name}</title>
    <style>
        :root {{
            --primary: #1976d2;
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text: #f8fafc;
            --text-secondary: #94a3b8;
            --border: #334155;
            --risk-color: {risk_color};
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 24px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        .header-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
        }}
        .app-title {{
            margin: 0;
            font-size: 24px;
            color: #fff;
        }}
        .pkg-name {{
            font-family: monospace;
            color: var(--text-secondary);
            font-size: 14px;
            margin-top: 4px;
        }}
        .risk-badge {{
            background: var(--risk-color);
            color: #fff;
            padding: 8px 16px;
            border-radius: 8px;
            font-weight: bold;
            font-size: 16px;
            text-align: center;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
        }}
        h3 {{
            margin-top: 0;
            margin-bottom: 12px;
            font-size: 16px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
            color: #38bdf8;
        }}
        ul {{
            padding-right: 20px;
            margin: 0;
        }}
        li {{
            margin-bottom: 6px;
            font-size: 13px;
        }}
        .danger-item {{
            color: #f87171;
            font-weight: bold;
        }}
        code {{
            background: #090d16;
            padding: 3px 6px;
            border-radius: 4px;
            font-size: 12px;
            color: #38bdf8;
            word-break: break-all;
        }}
        .cert-box {{
            background: #090d16;
            padding: 10px;
            border-radius: 6px;
            margin-top: 8px;
            font-size: 12px;
        }}
        .footer {{
            text-align: center;
            color: var(--text-secondary);
            font-size: 12px;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header-card">
            <div>
                <h1 class="app-title">{app_name}</h1>
                <div class="pkg-name">{package_name}</div>
                <div style="font-size: 13px; color: var(--text-secondary); margin-top: 6px;">
                    الإصدار: {ver_name} ({ver_code}) | الحجم: {self.basic.get('size_mb', 0)} MB | Min SDK: {self.basic.get('sdk_versions', {}).get('min', 'N/A')}
                </div>
            </div>
            <div class="risk-badge">
                مستوى الخطورة<br>{risk_level} ({risk_score}%)
            </div>
        </div>

        {alerts_html}
        {secrets_html}

        <div class="grid">
            <div class="card">
                <h3>🛡️ تقييم الأمان والملاحظات</h3>
                <ul>{reasons_html}</ul>
            </div>

            <div class="card">
                <h3>🔐 التوقيع الرقمي والشهادات</h3>
                <p>الحالة: <strong>{'✅ موقّع برمجياً' if sig_signed else '❌ غير موقّع'}</strong></p>
                {certs_html}
            </div>

            <div class="card">
                <h3>⚠️ الصلاحيات الخطرة ({len(dangerous_perms)})</h3>
                <ul>{dangerous_html}</ul>
            </div>

            <div class="card">
                <h3>📋 بصمات الهاش (Hashes)</h3>
                <p><strong>SHA-256:</strong><br><code>{self.hashes.get('sha256', 'N/A')}</code></p>
                <p><strong>MD5:</strong><br><code>{self.hashes.get('md5', 'N/A')}</code></p>
            </div>
        </div>

        {manifest_sec_html}
        {defenses_html}
        {manifest_html}
        {nsc_html}
        {deep_links_html}
        {native_libs_html}
        {exodus_html}

        <div class="card" style="margin-bottom: 24px;">
            <h3>🌐 اتصالات الشبكة وعناوين IP المستخرجة</h3>
            <p>{ips_html}</p>
        </div>

        <div class="card">
            <h3>📑 كافة الصلاحيات المطلوبة ({len(all_perms)})</h3>
            <ul style="max-height: 200px; overflow-y: auto;">{all_perms_html}</ul>
        </div>

        <div class="footer">
            تم توليد هذا التقرير تلقائياً عبر منظومة AdbLite APK Inspector - Connect Tag &copy; {datetime.now().year}
        </div>
    </div>
</body>
</html>
"""
        return html_template
