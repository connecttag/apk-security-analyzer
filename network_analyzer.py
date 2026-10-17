# network_analyzer.py
import re
from typing import Dict, List, Any, Optional
from androguard.core.analysis.analysis import Analysis
from androguard.core.dex import DEX
from androguard.core.apk import APK
from domains import ANDROID_DOMAINS, GOOGLE_DOMAINS, SOCIAL_DOMAINS, PROTECTION_DOMAINS, CLOUD_API_DOMAINS
from keywords import NETWORK_CALL_KEYWORDS, INTERESTING_STRING_KEYWORDS

class NetworkAnalyzer:
    def __init__(self, anydx: Analysis, apk: Optional[APK] = None):
        self.anydx = anydx
        self.apk = apk
        self.android_domains = ANDROID_DOMAINS
        self.google_domains = GOOGLE_DOMAINS
        self.social_domains = SOCIAL_DOMAINS
        self.protection_domains = PROTECTION_DOMAINS
        self.cloud_domains = CLOUD_API_DOMAINS

    def extract_ip_addresses(self) -> List[str]:
        """يستخرج عناوين IP من السلاسل النصية."""
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ip_addresses = set()
        try:
            for string_analysis in self.anydx.find_strings(".*"):
                val = string_analysis.get_value() if hasattr(string_analysis, 'get_value') else str(string_analysis)
                if isinstance(val, str):
                    for match in re.findall(ip_pattern, val):
                        if not match.startswith("0.") and not match.startswith("127.") and not match == "255.255.255.255":
                            ip_addresses.add(match)
        except Exception:
            pass
        return sorted(list(ip_addresses))[:50]

    def extract_urls(self) -> List[str]:
        """يستخرج عناوين URL المضمنة داخل الكود."""
        urls = set()
        try:
            for string_analysis in self.anydx.find_strings(r"(http|https)://.*"):
                val = string_analysis.get_value() if hasattr(string_analysis, 'get_value') else str(string_analysis)
                if isinstance(val, str) and len(val) >= 10:
                    urls.add(val.strip())
        except Exception:
            pass
        return sorted(list(urls))

    def analyze_urls(self) -> Dict[str, List[str]]:
        """تحليل وتصنيف عناوين URL المستخرجة."""
        all_urls = self.extract_urls()
        results = {
            "google_urls": [],
            "social_urls": [],
            "protection_urls": [],
            "cloud_urls": [],
            "other_urls": []
        }
        for url in all_urls:
            if any(domain in url for domain in self.android_domains):
                continue
            if any(domain in url for domain in self.protection_domains):
                results["protection_urls"].append(url)
            elif any(domain in url for domain in self.social_domains):
                results["social_urls"].append(url)
            elif any(domain in url for domain in self.cloud_domains):
                results["cloud_urls"].append(url)
            elif any(domain in url for domain in self.google_domains):
                results["google_urls"].append(url)
            else:
                results["other_urls"].append(url)

        # قصر القوائم لعدم تضخيم التقرير
        for k in results:
            results[k] = results[k][:50]

        return results

    def get_interesting_strings(self) -> List[str]:
        """استخراج السلاسل النصية المهمة مثل مفاتيح API وعناوين الخوادم."""
        found = set()
        try:
            for string_analysis in self.anydx.get_strings():
                s = string_analysis.get_orig_value() if hasattr(string_analysis, 'get_orig_value') else str(string_analysis)
                if any(keyword in s.lower() for keyword in INTERESTING_STRING_KEYWORDS):
                    if len(s) < 120:
                        found.add(s)
        except Exception:
            pass
        return list(found)[:40]

    def analyze_network_calls(self) -> Dict[str, Any]:
        """رصد استدعاءات الشبكة البرمجية."""
        network_calls = []
        try:
            for method in self.anydx.get_methods():
                for keyword in NETWORK_CALL_KEYWORDS:
                    if keyword in method.name.lower():
                        network_calls.append({
                            'class_name': method.get_class_name(),
                            'method': method.name,
                        })
                        break
        except Exception:
            pass
        return {
            "total_calls": len(network_calls),
            "calls": network_calls[:25]
        }

    def audit_network_security_config(self) -> Dict[str, Any]:
        """فحص تكوين أمان الشبكة (Network Security Config) وسياسات الاتصال."""
        if not self.apk:
            return {
                "has_config": False,
                "config_path": None,
                "cleartext_traffic_permitted": False,
                "user_certificates_trusted": False,
                "has_debug_overrides": False,
                "has_pin_set": False,
                "pinned_domains": [],
                "domain_configs": [],
                "findings": ["لم يتم تزويد كائن الـ APK لفحص تكوين الشبكة."]
            }

        # 1. فحص سمات المانيفست في <application>
        manifest_uses_cleartext = False
        nsc_ref = None
        target_sdk = 0
        try:
            target_sdk = int(self.apk.get_target_sdk_version() or 0)
        except Exception:
            pass

        for app_elem in self.apk.find_tags('application') or []:
            val_cleartext = (
                app_elem.get("{http://schemas.android.com/apk/res/android}usesCleartextTraffic")
                or app_elem.get("android:usesCleartextTraffic")
                or app_elem.get("usesCleartextTraffic")
            )
            if val_cleartext and str(val_cleartext).lower() in ("true", "1"):
                manifest_uses_cleartext = True

            val_nsc = (
                app_elem.get("{http://schemas.android.com/apk/res/android}networkSecurityConfig")
                or app_elem.get("android:networkSecurityConfig")
                or app_elem.get("networkSecurityConfig")
            )
            if val_nsc:
                nsc_ref = str(val_nsc)

        # 2. البحث عن ملف الـ XML المشار إليه في ملفات الحزمة
        all_files = self.apk.get_files() or []
        config_file_path = None

        if nsc_ref:
            # مثال: @xml/network_security_config -> network_security_config
            clean_name = nsc_ref.split("/")[-1].replace("@", "")
            for f in all_files:
                if f.startswith("res/xml/") and clean_name in f:
                    config_file_path = f
                    break

        if not config_file_path:
            # بحث احتياطي عن أي ملف network_security_config.xml
            for f in all_files:
                f_l = f.lower()
                if f_l.startswith("res/xml/") and ("network" in f_l or "security_config" in f_l):
                    config_file_path = f
                    break

        # إذا لم يكن هناك ملف تكوين مخصص
        if not config_file_path:
            cleartext_default = manifest_uses_cleartext or (target_sdk > 0 and target_sdk < 28)
            findings = []
            if cleartext_default:
                findings.append(
                    "⚠️ حركة المرور غير المشفرة (Cleartext HTTP) مسموحة افتراضياً "
                    f"({'usesCleartextTraffic=true' if manifest_uses_cleartext else f'targetSdkVersion={target_sdk} < 28'}). "
                    "مما يعرض بيانات المستخدم الحساسة للتنصت وسرقة الجلسات عبر شبكات Wi-Fi المفتوحة."
                )
            else:
                findings.append(
                    "✅ حركة المرور غير المشفرة محظورة افتراضياً (Android 9+ / API 28+)، مع عدم وجود ملف تكوين شبكة مخصص."
                )

            return {
                "has_config": False,
                "config_path": None,
                "cleartext_traffic_permitted": cleartext_default,
                "user_certificates_trusted": False,
                "has_debug_overrides": False,
                "has_pin_set": False,
                "pinned_domains": [],
                "domain_configs": [],
                "findings": findings
            }

        # 3. فك تشفير وقراءة ملف الـ XML
        root = None
        try:
            file_bytes = self.apk.get_file(config_file_path)
            if file_bytes:
                from androguard.core.axml import AXMLPrinter
                import xml.etree.ElementTree as ET
                try:
                    axml = AXMLPrinter(file_bytes)
                    xml_str = axml.get_xml()
                    if isinstance(xml_str, bytes):
                        xml_str = xml_str.decode("utf-8", errors="ignore")
                    root = ET.fromstring(xml_str)
                except Exception:
                    # قد يكون ملف XML نصي عادي
                    root = ET.fromstring(file_bytes.decode("utf-8", errors="ignore"))
        except Exception:
            root = None

        if root is None:
            return {
                "has_config": True,
                "config_path": config_file_path,
                "cleartext_traffic_permitted": manifest_uses_cleartext,
                "user_certificates_trusted": False,
                "has_debug_overrides": False,
                "has_pin_set": False,
                "pinned_domains": [],
                "domain_configs": [],
                "findings": ["ملف تكوين أمان الشبكة موجود ولكن تعذر تحليله برمجياً."]
            }

        # 4. تحليل عناصر الـ XML
        cleartext_base = False
        user_certs_trusted = False
        has_debug_overrides = False
        pinned_domains = []
        domain_configs = []
        findings = []

        # فحص <base-config>
        for base in root.findall(".//base-config"):
            ct = base.get("cleartextTrafficPermitted")
            if ct and ct.lower() in ("true", "1"):
                cleartext_base = True

            for cert in base.findall(".//certificates"):
                src = cert.get("src", "").lower()
                if "user" in src:
                    user_certs_trusted = True

        # فحص <domain-config>
        for dom_cfg in root.findall(".//domain-config"):
            domains = [d.text.strip() for d in dom_cfg.findall(".//domain") if d.text]
            ct_dom = dom_cfg.get("cleartextTrafficPermitted")
            dom_cleartext = ct_dom.lower() in ("true", "1") if ct_dom else cleartext_base

            # فحص شهادات المستخدم في النطاقات
            dom_user_trusted = False
            for cert in dom_cfg.findall(".//certificates"):
                src = cert.get("src", "").lower()
                if "user" in src:
                    user_certs_trusted = True
                    dom_user_trusted = True

            # فحص تثبيت الشهادات <pin-set>
            pin_set = dom_cfg.find(".//pin-set")
            dom_pins = []
            exp_date = None
            is_expired = False
            if pin_set is not None:
                exp_date = pin_set.get("expiration")
                if exp_date:
                    try:
                        from datetime import datetime
                        exp_dt = datetime.strptime(exp_date, "%Y-%m-%d")
                        if exp_dt < datetime.now():
                            is_expired = True
                    except Exception:
                        pass

                for p in pin_set.findall(".//pin"):
                    dom_pins.append({
                        "digest": p.get("digest", "SHA-256"),
                        "pin": p.text.strip() if p.text else ""
                    })

                for d in domains:
                    pinned_domains.append({
                        "domain": d,
                        "expiration": exp_date,
                        "is_expired": is_expired,
                        "pins_count": len(dom_pins)
                    })

            for d in domains:
                domain_configs.append({
                    "domain": d,
                    "cleartext_permitted": dom_cleartext,
                    "user_certs_trusted": dom_user_trusted,
                    "has_pinning": pin_set is not None,
                    "pin_expiration": exp_date,
                    "is_pin_expired": is_expired
                })

        # فحص <debug-overrides>
        debug_node = root.find(".//debug-overrides")
        if debug_node is not None:
            has_debug_overrides = True

        # تحديد النتيجة العامة لحركة المرور غير المشفرة
        is_cleartext_permitted = cleartext_base or (manifest_uses_cleartext and not root.findall(".//base-config"))

        # صياغة الملاحظات والتحذيرات
        if is_cleartext_permitted:
            findings.append("⚠️ السماح بحركة مرور HTTP غير مشفرة (Cleartext Traffic) في التكوين العام للتطبيق.")
        else:
            findings.append("🛡️ حركة مرور HTTP غير المشفرة محظورة في التكوين العام (HTTPS إلزامي).")

        if user_certs_trusted:
            findings.append("🚨 ثغرة أمنية حرجة: التطبيق يثق بشهادات المستخدم (User CA) في النسخة الإنتاجية! هذا يتيح اعتراض حركة HTTPS عبر هجمات MITM بمجرد تثبيت شهادة في إعدادات الهاتف.")
        else:
            findings.append("✅ يثق التطبيق فقط بشهادات النظام المعتمدة (System CAs) في الإنتاج.")

        if has_debug_overrides:
            findings.append("ℹ️ يحتوي ملف التكوين على تجاوزات وضع التصحيح (debug-overrides)، وهي تُفعّل فقط عند تشغيل التطبيق في وضع الـ Debug.")

        if pinned_domains:
            expired_count = sum(1 for p in pinned_domains if p.get("is_expired", False))
            if expired_count > 0:
                findings.append(f"⚠️ تحذير: انتهت صلاحية تثبيت الشهادات (Certificate Pinning) لـ {expired_count} نطاق! يقوم نظام أندرويد بتعطيل التثبيت بعد تاريخ الانتهاء.")
            else:
                findings.append(f"🔒 تم تفعيل تثبيت الشهادات (Certificate Pinning) بنجاح لـ {len(pinned_domains)} نطاق.")

        return {
            "has_config": True,
            "config_path": config_file_path,
            "cleartext_traffic_permitted": is_cleartext_permitted,
            "user_certificates_trusted": user_certs_trusted,
            "has_debug_overrides": has_debug_overrides,
            "has_pin_set": len(pinned_domains) > 0,
            "pinned_domains": pinned_domains,
            "domain_configs": domain_configs,
            "findings": findings
        }
