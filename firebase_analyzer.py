# -*- coding: utf-8 -*-
"""
firebase_analyzer.py - فاحص وتدقيق أمان قواعد بيانات Google Firebase المفتوحة
مستوحى من محرك فحص Firebase في MobSF (firebase.py).
يفحص روابط Firebase المستخرجة من الحزمة، ويتحقق مما إذا كانت قواعد البيانات مفتوحة للعلن بدون مصادقة.
"""

import re
import urllib.request
import json
from urllib.parse import urlparse
from typing import List, Dict, Any

FIREBASE_REGEX = re.compile(r'https?://[a-zA-Z0-9_\-]+\.(?:firebaseio\.com|firebasedatabase\.app)', re.IGNORECASE)

def audit_firebase_databases(urls: List[str], timeout_sec: int = 2) -> Dict[str, Any]:
    """
    استخراج وتدقيق أمان روابط وقواعد بيانات Firebase في الحزمة.
    """
    found_urls = set()
    for u in urls:
        if not u or not isinstance(u, str):
            continue
        matches = FIREBASE_REGEX.findall(u)
        for m in matches:
            # توحيد صيغة الرابط وإزالة المسارات الزائدة
            try:
                parsed = urlparse(m)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                found_urls.add(base_url)
            except Exception:
                found_urls.add(m)

    open_dbs = []
    secure_dbs = []

    for base_url in list(found_urls)[:3]:
        parsed = urlparse(base_url)
        db_name = parsed.netloc.split(".")[0]
        test_url = f"{base_url}/.json?shallow=true"

        is_open = False
        desc = ""
        try:
            req = urllib.request.Request(
                test_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SabrSecurityStudio/1.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                status_code = resp.status
                body = resp.read().decode("utf-8", errors="ignore").strip()

                # إذا كانت الاستجابة 200 ولا تحتوي على Permission denied فالقاعدة مفتوحة
                if status_code == 200 and "Permission denied" not in body and body != "null":
                    is_open = True
                    desc = f"🚨 قاعدة بيانات Firebase ({db_name}) مفتوحة للعلن بدون مصادقة! يمكن لأي طرف قراءة البيانات الحساسة."
                else:
                    desc = f"قاعدة البيانات ({db_name}) محمية بقواعد أمان تمنع القراءة العامة."
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                desc = f"قاعدة البيانات ({db_name}) محمية بقواعد مصادقة (HTTP {e.code})."
            else:
                desc = f"فشل الاستعلام عن قاعدة البيانات ({db_name}) - كود {e.code}."
        except Exception as e:
            desc = f"تعذر الاتصال بقاعدة البيانات ({db_name}) للتحقق: {str(e)}"

        entry = {
            "url": base_url,
            "db_name": db_name,
            "description": desc
        }

        if is_open:
            entry["severity"] = "CRITICAL"
            entry["status"] = "OPEN"
            open_dbs.append(entry)
        else:
            entry["severity"] = "SAFE"
            entry["status"] = "SECURE"
            secure_dbs.append(entry)

    return {
        "has_firebase_db": len(found_urls) > 0,
        "total_databases": len(found_urls),
        "open_databases_count": len(open_dbs),
        "open_databases": open_dbs,
        "secure_databases": secure_dbs
    }
