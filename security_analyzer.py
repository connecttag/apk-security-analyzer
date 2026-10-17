# security_analyzer.py
import json
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Any
from androguard.core.apk import APK
from androguard.core.analysis.analysis import Analysis
from constants import BLACKLIST_FILE
from keywords import SENSITIVE_METHOD_KEYWORDS, VULNERABILITY_KEYWORDS
try:
    from elf_checksec import analyze_elf_bytes
except ImportError:
    analyze_elf_bytes = None

class SecurityAnalyzer:
    def __init__(self, apk: APK, anydx: Analysis):
        self.apk = apk
        self.anydx = anydx
        self.package_name = self.apk.get_package() or "unknown"

    def get_permissions_info(self) -> Dict[str, Any]:
        """يستخرج معلومات وتفاصيل الصلاحيات وتصنيفها."""
        all_perms = self.apk.get_permissions() or []
        declared_perms = self.apk.get_declared_permissions() or []
        implied_perms = self.apk.get_uses_implied_permission_list() or []
        details = self.apk.get_details_permissions() or {}

        dangerous_perms = []
        dangerous_keywords = [
            "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
            "READ_CONTACTS", "WRITE_CONTACTS", "READ_SMS", "SEND_SMS", "RECEIVE_SMS",
            "READ_CALL_LOG", "WRITE_CALL_LOG", "READ_PHONE_STATE", "SYSTEM_ALERT_WINDOW",
            "REQUEST_INSTALL_PACKAGES", "WRITE_SETTINGS", "MANAGE_EXTERNAL_STORAGE"
        ]

        for perm in all_perms:
            if any(kw in perm for kw in dangerous_keywords):
                dangerous_perms.append(perm)

        return {
            "all_permissions": all_perms,
            "dangerous_permissions": dangerous_perms,
            "declared_permissions": declared_perms,
            "implied_permissions": implied_perms,
            "details": details
        }

    def get_signature_info(self) -> Dict[str, Any]:
        """يستخرج معلومات التوقيع وإصداراته والشهادات الرقمية مع تدقيق قوة التشفير والمفاتيح."""
        try:
            is_signed = self.apk.is_signed()
        except Exception:
            is_signed = False

        if not is_signed:
            return {"is_signed": False, "signature_versions": {}, "certificates": []}

        sig_versions = {
            "v1": bool(self.apk.is_signed_v1()),
            "v2": bool(self.apk.is_signed_v2()),
            "v3": bool(self.apk.is_signed_v3()),
        }

        now = datetime.now(timezone.utc)
        certificates = []
        for cert in self.apk.get_certificates() or []:
            try:
                issuer = cert.issuer.human_friendly if hasattr(cert.issuer, 'human_friendly') else str(cert.issuer)
                subject = cert.subject.human_friendly if hasattr(cert.subject, 'human_friendly') else str(cert.subject)
                sha1_val = cert.sha1.hex() if isinstance(cert.sha1, (bytes, bytearray)) else str(cert.sha1)
                sha256_val = cert.sha256.hex() if isinstance(cert.sha256, (bytes, bytearray)) else str(cert.sha256)

                # خصائص وتدقيق قوة التشفير
                bit_size = 0
                algorithm = "UNKNOWN"
                if hasattr(cert, 'public_key') and cert.public_key:
                    bit_size = getattr(cert.public_key, 'bit_size', 0) or 0
                    algorithm = str(getattr(cert.public_key, 'algorithm', 'UNKNOWN')).upper()

                hash_algo = str(getattr(cert, 'hash_algo', 'UNKNOWN')).upper()

                # تواريخ الصلاحية
                valid_from = ""
                valid_to = ""
                not_before = getattr(cert, 'not_valid_before', None)
                not_after = getattr(cert, 'not_valid_after', None)
                if not_before:
                    try:
                        valid_from = not_before.strftime("%Y-%m-%d %H:%M:%S UTC")
                    except Exception:
                        valid_from = str(not_before)
                if not_after:
                    try:
                        valid_to = not_after.strftime("%Y-%m-%d %H:%M:%S UTC")
                    except Exception:
                        valid_to = str(not_after)

                # فحص الضعف والشذوذ
                is_weak_key = False
                is_weak_hash = False
                is_expired = False
                warnings = []

                # 1. ضعف طول المفتاح
                if algorithm in ("RSA", "DSA") and 0 < bit_size < 2048:
                    is_weak_key = True
                    warnings.append(f"طول المفتاح ({bit_size}-bit) ضعيف جداً وأقل من المعيار الآمن (2048-bit).")
                elif algorithm == "EC" and 0 < bit_size < 256:
                    is_weak_key = True
                    warnings.append(f"طول مفتاح المنحنى الإهليلجي ({bit_size}-bit) أقل من المعيار الآمن (256-bit).")

                # 2. ضعف خوارزمية التجزئة والتوقيع
                if any(w in hash_algo for w in ("MD5", "MD2", "SHA1", "SHA-1")):
                    is_weak_hash = True
                    warnings.append(f"خوارزمية التجزئة ({hash_algo}) مكسورة أمنياً وعرضة لهجمات التصادم الرقمي.")

                # 3. شذوذ الصلاحية (منتهية الصلاحية أو مستقبلية أو طويلة جداً)
                if not_after:
                    try:
                        cmp_after = not_after.replace(tzinfo=timezone.utc) if not_after.tzinfo is None else not_after
                        if cmp_after < now:
                            is_expired = True
                            warnings.append("الشهادة الرقمية منتهية الصلاحية (Expired Certificate).")
                    except Exception:
                        pass

                if not_before:
                    try:
                        cmp_before = not_before.replace(tzinfo=timezone.utc) if not_before.tzinfo is None else not_before
                        if cmp_before > now:
                            warnings.append("تاريخ بدء سريان الشهادة يبدأ في المستقبل!")
                    except Exception:
                        pass

                if not_before and not_after:
                    try:
                        diff = not_after - not_before
                        if diff.days > 365 * 30:
                            warnings.append("صلاحية الشهادة ممتدة لأكثر من 30 سنة (عمر غير اعتيادي).")
                    except Exception:
                        pass

                certificates.append({
                    "sha1": sha1_val,
                    "sha256": sha256_val,
                    "issuer": issuer,
                    "subject": subject,
                    "algorithm": algorithm,
                    "bit_size": bit_size,
                    "hash_algo": hash_algo,
                    "valid_from": valid_from,
                    "valid_to": valid_to,
                    "is_weak_key": is_weak_key,
                    "is_weak_hash": is_weak_hash,
                    "is_expired": is_expired,
                    "warnings": warnings
                })
            except Exception:
                continue

        return {
            "is_signed": True,
            "signature_versions": sig_versions,
            "certificates": certificates
        }

    def _filter_methods_by_keyword(self, keyword: str) -> List[Dict[str, str]]:
        """يُصفي الطرق (methods) حسب الكلمة المفتاحية."""
        methods = []
        for method in self.anydx.get_methods():
            if keyword.lower() in method.name.lower():
                methods.append({
                    'class_name': method.get_class_name(),
                    'method': method.name,
                })
        return methods

    def get_sensitive_methods(self) -> List[Dict[str, str]]:
        """يستخرج الطرق البرمجية الحساسة."""
        sensitive_methods = []
        for keyword in SENSITIVE_METHOD_KEYWORDS:
            sensitive_methods.extend(self._filter_methods_by_keyword(keyword))
        return sensitive_methods

    def get_vulnerabilities(self) -> Dict[str, List[Dict[str, str]]]:
        """كشف نقاط الضعف والممارسات البرمجية الشائعة مع استبعاد الإيجابيات الكاذبة (False Positives)."""
        vulnerabilities = {}

        # قوائم استبعاد كلاسات الواجهة والرسوميات التي تصادف وجود كلمات مفتاحية في أسمائها
        UI_EXCLUDE_PREFIXES = (
            "landroidx/compose/",
            "landroidx/ui/",
            "landroid/view/",
            "landroid/widget/",
            "lcom/google/android/material/",
            "lcafe/adriel/voyager/",
            "lkotlinx/coroutines/",
        )

        SQL_DB_INDICATORS = (
            "sqlite",
            "database",
            "sqldelight",
            "room",
            "contentresolver",
            "sqldriver",
            "db",
        )

        CRED_EXCLUDE_CLASSES = (
            "keyboardtype",
            "semanticsproperties",
            "inputtype",
            "transformationmethod",
            "passwordtransformationmethod",
        )

        for vuln_type, keywords in VULNERABILITY_KEYWORDS.items():
            matches = []
            for method in self.anydx.get_methods():
                m_name = method.name
                m_name_lower = m_name.lower()
                c_name = method.get_class_name()
                c_name_lower = c_name.lower()

                # استبعاد كلاسات الواجهة والرسوميات
                is_ui_class = any(c_name_lower.startswith(prefix) for prefix in UI_EXCLUDE_PREFIXES)

                if vuln_type == "sql_injection":
                    if is_ui_class:
                        continue
                    # يجب أن يكون الكلاس معنياً بالـ DB أو الدالة SQL صريحة
                    is_db_class = any(db_ind in c_name_lower for db_ind in SQL_DB_INDICATORS)
                    if not is_db_class:
                        continue
                    if any(kw.lower() in m_name_lower for kw in keywords):
                        matches.append({'class_name': c_name, 'method': m_name})

                elif vuln_type == "hardcoded_credentials":
                    if any(ex in c_name_lower for ex in CRED_EXCLUDE_CLASSES):
                        continue
                    if is_ui_class:
                        continue
                    if any(kw.lower() in m_name_lower for kw in keywords):
                        matches.append({'class_name': c_name, 'method': m_name})

                elif vuln_type == "weak_cryptography":
                    if any(kw.lower() in m_name_lower for kw in keywords) or any(kw.lower() in c_name_lower for kw in keywords):
                        matches.append({'class_name': c_name, 'method': m_name})

                else:
                    if is_ui_class:
                        continue
                    if any(kw.lower() in m_name_lower for kw in keywords):
                        matches.append({'class_name': c_name, 'method': m_name})

                if len(matches) >= 20:
                    break

            if matches:
                vulnerabilities[vuln_type] = matches[:15]
        return vulnerabilities

    def check_blacklist(self) -> bool:
        """يتحقق من وجود الحزمة في القائمة السوداء المحلية."""
        try:
            if os.path.exists(BLACKLIST_FILE):
                with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
                    blacklist_data = json.load(f)
                    return self.package_name in blacklist_data
        except Exception:
            pass
        return False

    def audit_components(self) -> Dict[str, Any]:
        """التدقيق العميق لمكونات التطبيق (الأنشطة، الخدمات، المستقبلات، موفرو المحتوى) وكشف المكشوف منها دون حماية."""
        def _get_attr(elem, attr: str):
            val = elem.get(f"{{http://schemas.android.com/apk/res/android}}{attr}")
            if val is None:
                val = elem.get(f"android:{attr}")
            if val is None:
                val = elem.get(attr)
            return str(val).strip() if val is not None else None

        SYSTEM_PROTECTED_PERMS = {
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.BIND_INPUT_METHOD",
            "android.permission.BIND_VOICE_INTERACTION",
            "android.permission.BIND_CARRIER_SERVICES",
            "android.permission.BIND_JOB_SERVICE",
            "android.permission.BIND_WALLPAPER"
        }

        component_tags = [
            ("activity", "activity"),
            ("activity-alias", "activity"),
            ("service", "service"),
            ("receiver", "receiver"),
            ("provider", "provider")
        ]

        target_sdk = 0
        try:
            target_sdk = int(self.apk.get_target_sdk_version() or 0)
        except Exception:
            pass

        items = []
        exported_count = 0
        unprotected_count = 0
        critical_count = 0

        for tag_name, comp_type in component_tags:
            for elem in self.apk.find_tags(tag_name) or []:
                name = _get_attr(elem, "name") or "unknown"
                exported_attr = _get_attr(elem, "exported")
                permission = _get_attr(elem, "permission")
                read_permission = _get_attr(elem, "readPermission")
                write_permission = _get_attr(elem, "writePermission")
                grant_uri_attr = _get_attr(elem, "grantUriPermissions")
                grant_uri = grant_uri_attr.lower() in ("true", "1") if grant_uri_attr else False

                intent_filters = [c for c in list(elem) if "intent-filter" in str(c.tag).lower()]
                has_filters = len(intent_filters) > 0

                # فحص ما إذا كان النشاط هو الواجهة الرئيسية Launching Activity
                is_main_launcher = False
                for flt in intent_filters:
                    actions = [
                        _get_attr(act, "name")
                        for act in list(flt)
                        if "action" in str(act.tag).lower()
                    ]
                    if "android.intent.action.MAIN" in actions:
                        is_main_launcher = True
                        break

                # تحديد حالة التصدير (Export Status)
                if exported_attr is not None:
                    if exported_attr.lower() in ("true", "1"):
                        is_exported = True
                        export_type = "EXPLICIT"
                    else:
                        is_exported = False
                        export_type = "NONE"
                else:
                    # السمة غير محددة صراحة
                    if comp_type == "provider":
                        # في أندرويد القديم (targetSdk <= 16) كان موفر المحتوى يصدّر افتراضياً
                        if 0 < target_sdk <= 16:
                            is_exported = True
                            export_type = "IMPLICIT"
                        else:
                            is_exported = False
                            export_type = "NONE"
                    else:
                        if has_filters:
                            is_exported = True
                            export_type = "IMPLICIT"
                        else:
                            is_exported = False
                            export_type = "NONE"

                if is_exported:
                    exported_count += 1

                # تقييم المخاطر لكل مكون
                risk_level = "SAFE"
                warning_message = "مكون داخلي مغلق (غير مكشوف للتطبيقات الخارجية)."

                if is_exported:
                    if comp_type == "provider":
                        has_perm = bool(permission or (read_permission and write_permission))
                        if not has_perm:
                            unprotected_count += 1
                            critical_count += 1
                            risk_level = "DANGEROUS"
                            warning_message = "موفر محتوى مكشوف للعلن دون أي صلاحيات حماية! يتيح لأي تطبيق قراءة أو تعديل البيانات."
                        elif not read_permission or not write_permission:
                            risk_level = "WARNING"
                            warning_message = "موفر محتوى مكشوف مع حماية جزئية (إحدى صلاحيات القراءة أو الكتابة غير مقيدة صراحة)."
                        else:
                            risk_level = "SAFE"
                            warning_message = f"محمي بصلاحيات مخصصة (قراءة: {read_permission or permission}, كتابة: {write_permission or permission})."

                        if grant_uri:
                            warning_message += " [يسمح بمنح أذونات URI مؤقتة]"
                    else:
                        if is_main_launcher:
                            risk_level = "SAFE"
                            warning_message = "نقطة الدخول الرئيسية للتطبيق (Main Launcher Activity)."
                        elif permission:
                            if permission in SYSTEM_PROTECTED_PERMS:
                                risk_level = "SAFE"
                                warning_message = f"محمي بصلاحية نظام حصرية ({permission.split('.')[-1]})."
                            else:
                                risk_level = "WARNING"
                                warning_message = f"مكون مكشوف محمي بالصلاحية: {permission}."
                        else:
                            unprotected_count += 1
                            critical_count += 1
                            risk_level = "DANGEROUS"
                            if export_type == "IMPLICIT":
                                warning_message = "مكون مكشوف ضمناً بسبب وجود intent-filter دون تقييد بصلاحيات حماية!"
                            else:
                                warning_message = "مكون مكشوف صراحة (exported=true) متاح لأي تطبيق دون أي صلاحيات حماية!"

                items.append({
                    "name": name,
                    "type": comp_type,
                    "is_exported": is_exported,
                    "export_type": export_type,
                    "permission": permission,
                    "read_permission": read_permission,
                    "write_permission": write_permission,
                    "grant_uri_permissions": grant_uri,
                    "intent_filters_count": len(intent_filters),
                    "is_main_launcher": is_main_launcher,
                    "risk_level": risk_level,
                    "warning_message": warning_message
                })

        return {
            "total_components": len(items),
            "exported_count": exported_count,
            "unprotected_count": unprotected_count,
            "critical_count": critical_count,
            "components": items
        }

    def check_janus_vulnerability(self) -> Dict[str, Any]:
        """كشف القابلية للإصابة بثغرة Janus (CVE-2017-13156)."""
        is_v1 = bool(self.apk.is_signed_v1())
        is_v2 = bool(self.apk.is_signed_v2())
        is_v3 = bool(self.apk.is_signed_v3())

        is_vulnerable = is_v1 and not is_v2 and not is_v3
        return {
            "is_vulnerable": is_vulnerable,
            "is_signed_v1": is_v1,
            "is_signed_v2": is_v2,
            "is_signed_v3": is_v3,
            "severity": "HIGH" if is_vulnerable else "NONE",
            "title": "ثغرة Janus (CVE-2017-13156)",
            "description": (
                "التطبيق موقّع فقط بحزمة توقيع v1 القديمة (JAR Signature) دون حزم v2 أو v3. "
                "هذا يجعله عرضة لثغرة Janus (CVE-2017-13156) على هواتف أندرويد (5.0 إلى 8.0)، "
                "حيث يمكن للمهاجم دمج ملف DEX خبيث في رأس الـ APK دون كسر التوقيع الرقمي!"
                if is_vulnerable else
                "التطبيق محمي بحزم التوقيع الحديثة (v2/v3) ومحصن ضد ثغرة Janus."
            )
        }

    def check_debug_certificate(self) -> Dict[str, Any]:
        """كشف التوقيع بشهادة التصحيح الافتراضية (Android Debug Certificate)."""
        is_debug = False
        debug_details = []
        for cert in self.apk.get_certificates() or []:
            try:
                issuer = str(getattr(cert.issuer, 'human_friendly', cert.issuer)).lower()
                subject = str(getattr(cert.subject, 'human_friendly', cert.subject)).lower()
                if "android debug" in issuer or "android debug" in subject or "androiddebugkey" in issuer or "androiddebugkey" in subject:
                    is_debug = True
                    debug_details.append({"issuer": issuer, "subject": subject})
            except Exception:
                pass

        return {
            "is_debug_signed": is_debug,
            "severity": "CRITICAL" if is_debug else "NONE",
            "title": "شهادة تصحيح الأخطاء (Android Debug Key)",
            "message": (
                "تحذير أمني حرج: تم توقيع التطبيق بمفتاح التصحيح الافتراضي (CN=Android Debug). "
                "هذا يشير إلى أن النسخة مسربة من بيئة التطوير التجريبية وليست إصداراً إنتاجياً آمناً، "
                "حيث يمتلك مفتاح التصحيح كلمة مرور معروفة عالمياً مما يسمح باستبدال التطبيق بحزم معدلة."
                if is_debug else
                "التطبيق موقّع بمفتاح إصدار خاص (غير موقع بشهادة التصحيح الافتراضية)."
            ),
            "details": debug_details
        }

    def scan_leaked_keystores(self) -> Dict[str, Any]:
        """فحص ملفات المفاتيح والشهادات المنسية داخل حزمة الـ APK."""
        SENSITIVE_EXTENSIONS = (
            ".jks", ".keystore", ".bks", ".p12", ".pfx",
            ".pem", ".key", ".pk8", ".der", ".crt", ".cer"
        )
        leaked_files = []
        for f in self.apk.get_files() or []:
            f_lower = f.lower()
            # تجاهل ملفات توقيع الحزمة المعيارية داخل META-INF
            if f_lower.startswith("meta-inf/") and any(f_lower.endswith(ext) for ext in (".rsa", ".dsa", ".ec", ".sf", ".mf")):
                continue
            if any(f_lower.endswith(ext) for ext in SENSITIVE_EXTENSIONS):
                try:
                    f_bytes = self.apk.get_file(f)
                    f_size = len(f_bytes) if f_bytes else 0
                except Exception:
                    f_size = 0
                
                is_private_key = any(f_lower.endswith(k) for k in (".jks", ".keystore", ".p12", ".pfx", ".key", ".pk8"))
                leaked_files.append({
                    "path": f,
                    "size_bytes": f_size,
                    "extension": os.path.splitext(f_lower)[1],
                    "risk": "CRITICAL" if is_private_key else "HIGH",
                    "description": "ملف مفتاح خاص أو مخزن شهادات سري (Keystore)" if is_private_key else "ملف شهادة رقمية مضمن"
                })

        return {
            "has_leaked_keystores": len(leaked_files) > 0,
            "total_leaked": len(leaked_files),
            "files": leaked_files
        }

    def calculate_risk_assessment(
        self,
        permissions: Dict,
        sensitive_methods: List,
        is_blacklisted: bool,
        janus_info: Dict = None,
        debug_cert_info: Dict = None,
        leaked_keystores: Dict = None,
        manifest_audit: Dict = None,
        manifest_security: Dict = None,
        playstore_info: Dict = None,
        firebase_audit: Dict = None,
        crypto_audit: Dict = None,
        webview_audit: Dict = None,
        cloud_bucket_audit: Dict = None,
        ipc_audit: Dict = None
    ) -> Dict[str, Any]:
        """حساب درجة المخاطر ومستوى الأمان الإجمالي للتطبيق بناءً على التدقيق العميق."""
        if is_blacklisted:
            return {
                "risk_level": "CRITICAL",
                "risk_score": 100,
                "summary": "الحزمة مدرجة في القائمة السوداء للتطبيقات المحظورة أو الضارة."
            }

        score = 0
        reasons = []

        # 1. تقييم الصلاحيات الخطرة
        dangerous_count = len(permissions.get("dangerous_permissions", []))
        if dangerous_count > 0:
            score += min(dangerous_count * 8, 30)
            reasons.append(f"يطلب التطبيق {dangerous_count} من الصلاحيات الخطرة.")

        # 2. تقييم الطرق الحساسة
        sensitive_count = len(sensitive_methods)
        if sensitive_count > 0:
            score += min(sensitive_count * 2, 20)
            reasons.append(f"تم رصد {sensitive_count} استدعاء لطرق برمجية حساسة.")

        # 3. تقييم التوقيع وحالة التوقيع
        sig_info = self.get_signature_info()
        if not sig_info.get("is_signed", False):
            score += 35
            reasons.append("ملف الـ APK غير موقع برمجياً.")

        # 4. ثغرة Janus
        if janus_info and janus_info.get("is_vulnerable", False):
            score += 20
            reasons.append("التطبيق عرضة لثغرة Janus (CVE-2017-13156) لعدم توقيعه بـ v2/v3.")

        # 5. شهادة التصحيح الافتراضية
        if debug_cert_info and debug_cert_info.get("is_debug_signed", False):
            score += 25
            reasons.append("التطبيق موقّع بمفتاح التصحيح الافتراضي (Debug Certificate).")

        # 6. ملفات المفاتيح والشهادات المنسية
        if leaked_keystores and leaked_keystores.get("has_leaked_keystores", False):
            count = leaked_keystores.get("total_leaked", 0)
            score += min(count * 15, 30)
            reasons.append(f"تم العثور على {count} من ملفات المفاتيح أو الشهادات المنسية داخل الحزمة.")

        # 7. المكونات المكشوفة غير المحمية
        if manifest_audit:
            unprotected = manifest_audit.get("unprotected_count", 0)
            if unprotected > 0:
                score += min(unprotected * 5, 25)
                reasons.append(f"يحتوي التطبيق على {unprotected} مكون مكشوف للعلن دون أي صلاحيات حماية.")

        # 8. سمات المانيفست الأمنية (Debuggable, AllowBackup, Cleartext)
        if manifest_security:
            flags = manifest_security.get("flags", {})
            if flags.get("debuggable"):
                score += 30
                reasons.append("🚨 التطبيق مفعل لوضع التصحيح (Debuggable=true) مما يتيح التلاعب بالذاكرة وتنفيذ أوامر غير مصرح بها.")
            if flags.get("allow_backup"):
                score += 8
                reasons.append("⚠️ النسخ الاحتياطي عبر ADB مفعل (allowBackup=true)؛ يمكن استخراج بيانات وقواعد بيانات التطبيق دون روت.")
            if flags.get("uses_cleartext_traffic"):
                score += 15
                reasons.append("⚠️ السماح بحركة مرور HTTP غير مشفرة (Cleartext Traffic) صراحة في المانيفست.")

        # 9. تدقيق قوة التشفير والمفاتيح الرقمية للشهادات (Cryptographic Key Strength)
        certs = sig_info.get("certificates", [])
        if any(c.get("is_weak_key", False) for c in certs):
            score += 20
            reasons.append("⚠️ طول مفتاح التوقيع الرقمي ضعيف (أقل من 2048-bit) مما يجعله عرضة للكسر الحسابي.")
        if any(c.get("is_weak_hash", False) for c in certs):
            score += 20
            reasons.append("⚠️ خوارزمية تجزئة الشهادة (MD5 / SHA-1) مكسورة أمنياً ومعرضة لهجمات التصادم.")
        if any(c.get("is_expired", False) for c in certs):
            score += 15
            reasons.append("⚠️ الشهادة الرقمية المستخدمة في توقيع التطبيق منتهية الصلاحية.")

        # 10. كشف التطبيقات المستنسخة والملغمة (Play Store Clone & Repackage Detector)
        if playstore_info and playstore_info.get("is_likely_repackaged", False):
            score += 40
            reasons.append(playstore_info.get("warning_message") or "🚨 تطبيق مشبوه: توقيع الحزمة لا يتطابق مع النسخة الرسمية على متجر Google Play (محتمل أن يكون Trojanized/Cloned).")

        # 11. كشف قواعد بيانات Firebase المفتوحة (Open Firebase Database Auditor)
        if firebase_audit and firebase_audit.get("open_databases_count", 0) > 0:
            count = firebase_audit.get("open_databases_count", 0)
            score += 35
            reasons.append(f"🚨 تسريب بيانات حرج: تم اكتشاف {count} قاعدة بيانات Firebase مفتوحة للعلن بدون مصادقة!")

        # 12. أخطاء تكوين التشفير البرمجي (Cryptographic Misconfigurations)
        if crypto_audit and crypto_audit.get("has_crypto_issues", False):
            issues = crypto_audit.get("findings", [])
            crit_crypto = sum(1 for i in issues if i.get("severity") == "CRITICAL")
            high_crypto = sum(1 for i in issues if i.get("severity") == "HIGH")
            if crit_crypto > 0:
                score += min(crit_crypto * 25, 35)
                reasons.append(f"🚨 تم رصد {crit_crypto} خوارزمية تشفير مكسورة أمنياً (مثل DES/RC4).")
            elif high_crypto > 0:
                score += min(high_crypto * 15, 25)
                reasons.append("⚠️ استخدام أوضاع تشفير غير آمنة (مثل ECB Mode أو Static IV).")

        # 13. ثغرات WebView وتجاوز SSL
        if webview_audit and webview_audit.get("total_issues", 0) > 0:
            issues = webview_audit.get("findings", [])
            if any(i.get("type") == "WEBVIEW_SSL_PROCEED_BYPASS" for i in issues):
                score += 35
                reasons.append("🚨 ثغرة خطيرة في WebView: يتم تجاوز أخطاء شهادات SSL/TLS عبر handler.proceed()!")
            if any(i.get("type") == "WEBVIEW_FILE_ACCESS_ENABLED" for i in issues):
                score += 20
                reasons.append("⚠️ السماح بالوصول لملفات النظام وعناوين file:// عبر WebView.")

        # 14. المستودعات السحابية المفتوحة (Cloud Storage Buckets)
        if cloud_bucket_audit and cloud_bucket_audit.get("open_buckets_count", 0) > 0:
            count = cloud_bucket_audit.get("open_buckets_count", 0)
            score += 35
            reasons.append(f"🚨 تسريب سحابي: تم العثور على {count} مستودع سحابي (S3/GCS/Azure) مفتوح للعلن!")

        # 15. ثغرات مسارات FileProvider و IPC
        if ipc_audit and ipc_audit.get("total_issues", 0) > 0:
            if any(f.get("type") == "FILE_PROVIDER_PATH_TRAVERSAL" for f in ipc_audit.get("findings", [])):
                score += 35
                reasons.append("🚨 ثغرة FileProvider Path Traversal: تصدير مسار جذر النظام <root-path> للعلن!")

        final_score = min(score, 100)
        if final_score >= 60:
            level = "HIGH"
        elif final_score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "risk_level": level,
            "risk_score": final_score,
            "reasons": reasons
        }

    def audit_manifest_security_flags(self) -> Dict[str, Any]:
        """فحص سمات الأمان الحرجة في المانيفست (Debuggable, AllowBackup, Cleartext, Tapjacking)."""
        def _get_attr(elem, attr: str):
            val = elem.get(f"{{http://schemas.android.com/apk/res/android}}{attr}")
            if val is None:
                val = elem.get(f"android:{attr}")
            if val is None:
                val = elem.get(attr)
            return str(val).strip() if val is not None else None

        app_elems = self.apk.find_tags("application") or []
        app_elem = app_elems[0] if app_elems else None

        findings = []
        flags = {
            "debuggable": False,
            "allow_backup": True,
            "test_only": False,
            "uses_cleartext_traffic": False,
            "has_network_security_config": False,
            "tapjacking_protected_activities": 0,
            "total_activities": 0
        }

        if app_elem is not None:
            # 1. debuggable
            dbg_val = _get_attr(app_elem, "debuggable")
            if dbg_val and dbg_val.lower() in ("true", "1"):
                flags["debuggable"] = True
                findings.append({
                    "severity": "CRITICAL",
                    "flag": "android:debuggable=true",
                    "message": "التطبيق مفعل لوضع التصحيح (Debuggable)، مما يسمح بربط jdb والتحكم في الذاكرة وتنفيذ شفرات غير مصرح بها!"
                })
            else:
                findings.append({
                    "severity": "SAFE",
                    "flag": "android:debuggable=false",
                    "message": "وضع التصحيح معطل (حزمة إنتاج آمنة من التنقيح الخارجي المباشر)."
                })

            # 2. allowBackup
            backup_val = _get_attr(app_elem, "allowBackup")
            if backup_val is not None and backup_val.lower() in ("false", "0"):
                flags["allow_backup"] = False
                findings.append({
                    "severity": "SAFE",
                    "flag": "android:allowBackup=false",
                    "message": "النسخ الاحتياطي عبر ADB معطل، مما يحمي قواعد البيانات والملفات الحساسة من الاستخراج عبر USB."
                })
            else:
                flags["allow_backup"] = True
                findings.append({
                    "severity": "WARNING",
                    "flag": "android:allowBackup=true",
                    "message": "النسخ الاحتياطي مفعل (allowBackup=true)؛ يمكن استخراج بيانات وقواعد بيانات التطبيق عبر adb backup بدون روت."
                })

            # 3. testOnly
            test_val = _get_attr(app_elem, "testOnly")
            if test_val and test_val.lower() in ("true", "1"):
                flags["test_only"] = True
                findings.append({
                    "severity": "WARNING",
                    "flag": "android:testOnly=true",
                    "message": "الحزمة موسومة كنسخة اختبارية فقط (testOnly=true)."
                })

            # 4. usesCleartextTraffic
            cleartext_val = _get_attr(app_elem, "usesCleartextTraffic")
            if cleartext_val and cleartext_val.lower() in ("true", "1"):
                flags["uses_cleartext_traffic"] = True
                findings.append({
                    "severity": "HIGH",
                    "flag": "android:usesCleartextTraffic=true",
                    "message": "التطبيق يسمح بحركة مرور HTTP غير مشفرة (Cleartext Traffic) صراحة في المانيفست."
                })

            # 5. networkSecurityConfig
            nsc_val = _get_attr(app_elem, "networkSecurityConfig")
            if nsc_val:
                flags["has_network_security_config"] = True

        # 6. فحص حماية النوافذ من هجمات التراكب (Tapjacking)
        activities = (self.apk.find_tags("activity") or [])
        flags["total_activities"] = len(activities)
        tapjack_count = 0
        for act in activities:
            ft = _get_attr(act, "filterTouchesWhenObscured")
            if ft and ft.lower() in ("true", "1"):
                tapjack_count += 1
        flags["tapjacking_protected_activities"] = tapjack_count

        return {
            "flags": flags,
            "findings": findings
        }

    def detect_app_defenses(self) -> Dict[str, Any]:
        """كشف آليات الدفاع الذاتي والحماية من التلاعب (Root Detection, Emulator, Anti-Debug, Screen Security)."""
        defenses = {
            "root_detection": {"enabled": False, "confidence": "NONE", "indicators": []},
            "emulator_detection": {"enabled": False, "confidence": "NONE", "indicators": []},
            "anti_debugging": {"enabled": False, "confidence": "NONE", "indicators": []},
            "screen_security": {"enabled": False, "confidence": "NONE", "indicators": []}
        }

        root_keywords = ["rootbeer", "/system/bin/su", "/system/xbin/su", "/system/app/superuser", "daemonsu", "magisk", "supersu", "test-keys", "busybox"]
        emu_keywords = ["ro.hardware.goldfish", "ro.kernel.qemu", "ro.product.model.sdk", "generic_x86", "nox", "bluestacks", "genymotion"]

        if self.anydx:
            try:
                # 1. كلاسات الـ DEX
                for c in self.anydx.get_classes():
                    c_name_lower = c.name.lower()
                    if "rootbeer" in c_name_lower:
                        defenses["root_detection"]["enabled"] = True
                        if "مكتبة RootBeer لكشف الروت" not in defenses["root_detection"]["indicators"]:
                            defenses["root_detection"]["indicators"].append("مكتبة RootBeer لكشف الروت")

                # 2. استدعاءات الدوال الحساسة
                for m in self.anydx.get_methods():
                    m_lower = m.name.lower()
                    c_lower = m.get_class_name().lower()

                    if "isdebuggerconnected" in m_lower or "isdebuggerconnected" in c_lower:
                        if "isDebuggerConnected" not in defenses["anti_debugging"]["indicators"]:
                            defenses["anti_debugging"]["enabled"] = True
                            defenses["anti_debugging"]["indicators"].append("isDebuggerConnected")

                    if "setflags" in m_lower and ("window" in c_lower or "view" in c_lower):
                        if "FLAG_SECURE Window Protection" not in defenses["screen_security"]["indicators"]:
                            defenses["screen_security"]["enabled"] = True
                            defenses["screen_security"]["indicators"].append("FLAG_SECURE Window Protection")

                # 3. جدول النصوص
                for s in self.anydx.get_strings():
                    val = s.get_value()
                    if not val:
                        continue
                    val_lower = val.lower()

                    for rk in root_keywords:
                        if rk in val_lower:
                            if rk not in defenses["root_detection"]["indicators"]:
                                defenses["root_detection"]["indicators"].append(rk)
                                defenses["root_detection"]["enabled"] = True

                    for ek in emu_keywords:
                        if ek in val_lower:
                            if ek not in defenses["emulator_detection"]["indicators"]:
                                defenses["emulator_detection"]["indicators"].append(ek)
                                defenses["emulator_detection"]["enabled"] = True

                    if "flag_secure" in val_lower:
                        if "FLAG_SECURE" not in defenses["screen_security"]["indicators"]:
                            defenses["screen_security"]["indicators"].append("FLAG_SECURE")
                            defenses["screen_security"]["enabled"] = True

            except Exception:
                pass

        for k in defenses:
            cnt = len(defenses[k]["indicators"])
            if cnt >= 2:
                defenses[k]["confidence"] = "HIGH"
            elif cnt == 1:
                defenses[k]["confidence"] = "MEDIUM"

        return defenses

    def audit_deep_links(self) -> Dict[str, Any]:
        """استخراج وتدقيق الروابط العميقة (Deep Links / App Links) والمخططات المخصصة."""
        def _get_attr(elem, attr: str):
            val = elem.get(f"{{http://schemas.android.com/apk/res/android}}{attr}")
            if val is None:
                val = elem.get(f"android:{attr}")
            if val is None:
                val = elem.get(attr)
            return str(val).strip() if val is not None else None

        deep_links = []
        schemes = set()
        hosts = set()

        activities = (self.apk.find_tags("activity") or []) + (self.apk.find_tags("activity-alias") or [])

        for act in activities:
            act_name = _get_attr(act, "name") or "unknown"
            is_exported_attr = _get_attr(act, "exported")

            for flt in list(act):
                if "intent-filter" not in str(flt.tag).lower():
                    continue

                auto_verify = _get_attr(flt, "autoVerify")
                is_auto_verify = auto_verify and auto_verify.lower() in ("true", "1")

                actions = [_get_attr(c, "name") for c in list(flt) if "action" in str(c.tag).lower()]
                categories = [_get_attr(c, "name") for c in list(flt) if "category" in str(c.tag).lower()]

                for data_elem in list(flt):
                    if "data" not in str(data_elem.tag).lower():
                        continue

                    scheme = _get_attr(data_elem, "scheme")
                    host = _get_attr(data_elem, "host")
                    path = _get_attr(data_elem, "path") or _get_attr(data_elem, "pathPrefix") or _get_attr(data_elem, "pathPattern") or ""

                    if scheme:
                        schemes.add(scheme)
                        if host:
                            hosts.add(host)
                            full_uri = f"{scheme}://{host}{path}"
                        else:
                            full_uri = f"{scheme}://{path}"

                        deep_links.append({
                            "activity": act_name,
                            "scheme": scheme,
                            "host": host or "*",
                            "path": path,
                            "full_uri": full_uri,
                            "auto_verify": is_auto_verify,
                            "is_browsable": "android.intent.category.BROWSABLE" in categories,
                            "is_exported": is_exported_attr
                        })

        return {
            "total_deep_links": len(deep_links),
            "unique_schemes": sorted(list(schemes)),
            "unique_hosts": sorted(list(hosts)),
            "links": deep_links[:30]
        }

    def analyze_native_libraries(self) -> Dict[str, Any]:
        """فحص وتحليل المكتبات البرمجية الأصلية C/C++ (.so) واستخراج المعماريات والنصوص الحساسة وفحص تصليب الذاكرة Checksec."""
        so_files = []
        abis = set()
        extracted_strings = []
        checksec_binaries = []

        SO_PATTERNS = [
            re.compile(b"https?://[^\\s\"'<>]{8,100}"),
            re.compile(b"AIza[0-9A-Za-z\\-_]{35}"),
            re.compile(b"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,99}")
        ]

        try:
            for f_path in self.apk.get_files() or []:
                if f_path.startswith("lib/") and f_path.endswith(".so"):
                    parts = f_path.split("/")
                    if len(parts) >= 3:
                        abi = parts[1]
                        lib_name = parts[-1]
                        abis.add(abi)

                        data = self.apk.get_file(f_path)
                        size_bytes = len(data) if data else 0

                        so_entry = {
                            "path": f_path,
                            "abi": abi,
                            "name": lib_name,
                            "size_kb": round(size_bytes / 1024, 1)
                        }
                        so_files.append(so_entry)

                        # إجراء فحص تصليب الذاكرة ELF Checksec
                        if data and analyze_elf_bytes is not None:
                            try:
                                chk_res = analyze_elf_bytes(data, file_name=lib_name, arch=abi)
                                if chk_res:
                                    checksec_binaries.append(chk_res)
                            except Exception:
                                pass

                        # استخراج النصوص الحساسة من ملفات .so ذات الحجم المناسب (< 5MB)
                        if data and size_bytes < 5 * 1024 * 1024:
                            try:
                                for pat in SO_PATTERNS:
                                    for match in pat.finditer(data):
                                        val = match.group(0).decode("utf-8", errors="ignore")
                                        if val not in extracted_strings:
                                            extracted_strings.append(val)
                                            if len(extracted_strings) >= 20:
                                                break
                            except Exception:
                                pass
        except Exception:
            pass

        checksec_summary = {
            "total_nx": sum(1 for b in checksec_binaries if b.get("is_nx")),
            "total_pie": sum(1 for b in checksec_binaries if b.get("is_pie")),
            "total_canary": sum(1 for b in checksec_binaries if b.get("has_stack_canary")),
            "total_full_relro": sum(1 for b in checksec_binaries if b.get("relro") == "FULL"),
            "total_stripped": sum(1 for b in checksec_binaries if b.get("is_stripped")),
            "banned_functions_count": sum(len(b.get("banned_functions", [])) for b in checksec_binaries)
        }

        return {
            "has_native_libraries": len(so_files) > 0,
            "architectures": sorted(list(abis)),
            "total_libraries": len(so_files),
            "libraries_sample": so_files[:25],
            "binaries": checksec_binaries[:50],
            "checksec_summary": checksec_summary,
            "extracted_sensitive_strings": extracted_strings[:15]
        }

