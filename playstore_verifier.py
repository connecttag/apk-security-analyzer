# -*- coding: utf-8 -*-
"""
playstore_verifier.py - التحقق من متجر Google Play وكشف التطبيقات المستنسخة والملغمة (Clone & Repackage Detector)
مستوحى ومطور من محرك playstore.py في MobSF لمقارنة بيانات الحزمة مع النسخة الرسمية على متجر Google Play.
"""

import re
import urllib.request
import urllib.error
from html import unescape
from typing import Dict, Any, Optional

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def verify_playstore_package(package_name: str, app_name: Optional[str] = None, is_debug_signed: bool = False, timeout_sec: int = 2) -> Dict[str, Any]:
    """
    استعلام خفيف لمتجر Google Play للتحقق مما إذا كانت الحزمة منشورة رسمياً،
    وكشف محاولات الاستنساخ أو إعادة الحزم الخبيثة (Repackaged / Trojanized Clones).
    """
    if not package_name or package_name in ("unknown", "com.example", "android"):
        return {
            "checked": False,
            "exists_on_play_store": False,
            "error": "اسم الحزمة غير صالح للفحص."
        }

    url = f"https://play.google.com/store/apps/details?id={package_name}&hl=en&gl=US"
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept-Language": "en-US,en;q=0.9"
    })

    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            if resp.status == 200:
                html = resp.read().decode("utf-8", errors="ignore")
                
                # استخراج اسم التطبيق الرسمي
                official_title = package_name
                title_match = re.search(r'<title>(.*?)(?: - Apps on Google Play|</title>)', html, re.IGNORECASE)
                if title_match:
                    raw_title = title_match.group(1).strip()
                    if raw_title and "Google Play" not in raw_title:
                        official_title = unescape(raw_title)

                if official_title == package_name:
                    h1_match = re.search(r'<h1[^>]*>.*?<span[^>]*>(.*?)</span>', html, re.DOTALL)
                    if h1_match:
                        official_title = unescape(h1_match.group(1).strip())

                # استخراج اسم المطور
                developer = "Google Play Developer"
                dev_match = re.search(r'/store/apps/dev(?:eloper)?\?id=([^"&]+)"', html)
                if dev_match:
                    developer = unescape(dev_match.group(1).replace("+", " ").strip())

                # استخراج الشعار
                icon_match = re.search(r'class="T75of [^"]*" src="([^"]+)"', html)
                icon_url = icon_match.group(1) if icon_match else None

                # رصد الشك في إعادة الحزم (Clone / Repackage)
                is_repackaged = False
                warning_message = ""

                if is_debug_signed:
                    is_repackaged = True
                    warning_message = f"🚨 خطر أمني حرج: الحزمة مسجلة رسمياً على متجر Google Play باسم ({official_title})، ولكن هذه النسخة موقعة بمفتاح تصحيح (Debug Certificate)! يشير هذا بقوة إلى أنه تطبيق مفكك ومُعاد تجميعه ومعدل (Trojanized / Repackaged Clone)."
                elif app_name and official_title:
                    clean_app = app_name.strip().lower()
                    clean_official = official_title.strip().lower()
                    if clean_app != "unknown" and len(clean_app) >= 4 and len(clean_official) >= 4:
                        if clean_app not in clean_official and clean_official not in clean_app:
                            warning_message = f"⚠️ تضارب في عنوان التطبيق: الاسم الداخلي للحزمة هو '{app_name}' بينما الاسم الرسمي على متجر Google Play هو '{official_title}'. قد يكون ذلك محاولة تضليل أو استنساخ."

                return {
                    "checked": True,
                    "exists_on_play_store": True,
                    "package_name": package_name,
                    "official_title": official_title,
                    "developer": developer,
                    "icon_url": icon_url,
                    "playstore_url": url,
                    "is_likely_repackaged": is_repackaged,
                    "warning_message": warning_message
                }

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {
                "checked": True,
                "exists_on_play_store": False,
                "package_name": package_name,
                "is_likely_repackaged": False,
                "warning_message": "هذه الحزمة غير مسجلة في متجر Google Play (تطبيق خاص، إصدار داخلي، أو غير مدرج في المتجر)."
            }
        else:
            return {
                "checked": False,
                "exists_on_play_store": False,
                "error": f"استجابة غير متوقعة من متجر Google Play (كود {e.code})."
            }
    except Exception as e:
        return {
            "checked": False,
            "exists_on_play_store": False,
            "error": f"تعذر الاستعلام من متجر Google Play: {str(e)}"
        }
