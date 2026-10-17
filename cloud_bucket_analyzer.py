# -*- coding: utf-8 -*-
"""
cloud_bucket_analyzer.py - فاحص وتدقيق أمان المستودعات السحابية المفتوحة
Cloud Storage Buckets Auditor (AWS S3, Google Cloud Storage, Azure Blob, DigitalOcean Spaces)
يستخرج روابط المستودعات السحابية من الحزمة ويتحقق مما إذا كانت مفتوحة للعلن بدون مصادقة.
"""

import re
import urllib.request
import urllib.error
from urllib.parse import urlparse
from typing import List, Dict, Any

S3_REGEX = re.compile(r'https?://([a-zA-Z0-9_\-\.]+)\.s3(?:[\.\-][a-zA-Z0-9_\-]+)?\.amazonaws\.com', re.IGNORECASE)
S3_PATH_REGEX = re.compile(r'https?://s3(?:[\.\-][a-zA-Z0-9_\-]+)?\.amazonaws\.com/([a-zA-Z0-9_\-\.]+)', re.IGNORECASE)
GCS_REGEX = re.compile(r'https?://storage\.googleapis\.com/([a-zA-Z0-9_\-\.]+)', re.IGNORECASE)
AZURE_REGEX = re.compile(r'https?://([a-zA-Z0-9_\-]+)\.blob\.core\.windows\.net(?:/([a-zA-Z0-9_\-]+))?', re.IGNORECASE)
DO_SPACES_REGEX = re.compile(r'https?://([a-zA-Z0-9_\-\.]+)\.([a-z0-9]+)\.digitaloceanspaces\.com', re.IGNORECASE)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SabrSecurityStudio/1.0"

def audit_cloud_buckets(urls: List[str], timeout_sec: int = 2) -> Dict[str, Any]:
    """استخراج وتدقيق أمان المستودعات السحابية العامة من قائمة الروابط."""
    buckets_to_test = {}

    for u in urls:
        if not u or not isinstance(u, str):
            continue

        # 1. AWS S3
        for m in S3_REGEX.finditer(u):
            b_name = m.group(1)
            if b_name and b_name not in ("s3", "www", "assets"):
                buckets_to_test[b_name] = {
                    "provider": "AWS S3",
                    "bucket_name": b_name,
                    "url": f"https://{b_name}.s3.amazonaws.com",
                    "test_url": f"https://{b_name}.s3.amazonaws.com/?max-keys=1"
                }

        for m in S3_PATH_REGEX.finditer(u):
            b_name = m.group(1)
            if b_name and b_name not in ("s3", "www"):
                buckets_to_test[b_name] = {
                    "provider": "AWS S3",
                    "bucket_name": b_name,
                    "url": f"https://s3.amazonaws.com/{b_name}",
                    "test_url": f"https://s3.amazonaws.com/{b_name}/?max-keys=1"
                }

        # 2. Google Cloud Storage
        for m in GCS_REGEX.finditer(u):
            b_name = m.group(1)
            if b_name:
                buckets_to_test[b_name] = {
                    "provider": "Google Cloud Storage",
                    "bucket_name": b_name,
                    "url": f"https://storage.googleapis.com/{b_name}",
                    "test_url": f"https://storage.googleapis.com/{b_name}/?max-keys=1"
                }

        # 3. Azure Blob
        for m in AZURE_REGEX.finditer(u):
            acc_name = m.group(1)
            container = m.group(2) or ""
            key = f"azure_{acc_name}_{container}"
            buckets_to_test[key] = {
                "provider": "Azure Blob Storage",
                "bucket_name": f"{acc_name}/{container}" if container else acc_name,
                "url": f"https://{acc_name}.blob.core.windows.net/{container}",
                "test_url": f"https://{acc_name}.blob.core.windows.net/{container}?restype=container&comp=list&maxresults=1"
            }

        # 4. DigitalOcean Spaces
        for m in DO_SPACES_REGEX.finditer(u):
            b_name = m.group(1)
            region = m.group(2)
            key = f"do_{b_name}_{region}"
            buckets_to_test[key] = {
                "provider": "DigitalOcean Spaces",
                "bucket_name": b_name,
                "url": f"https://{b_name}.{region}.digitaloceanspaces.com",
                "test_url": f"https://{b_name}.{region}.digitaloceanspaces.com/?max-keys=1"
            }

    open_buckets = []
    secure_buckets = []

    for b_id, info in list(buckets_to_test.items())[:3]:
        is_open = False
        desc = ""
        try:
            req = urllib.request.Request(info["test_url"], headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                # إذا كانت الاستجابة تحتوي على قائمة الملفات فهو مفتوح
                if resp.status == 200 and any(tag in body for tag in ("<ListBucketResult", "<ListAllMyBucketsResult", "<EnumerationResults")):
                    is_open = True
                    desc = f"🚨 مستودع سحابي ({info['bucket_name']}) مفتوح للعلن! يمكن لأي شخص تصفح وتحميل ملفات التطبيق."
                else:
                    desc = f"المستودع السحابي ({info['bucket_name']}) محمي أو يتطلب مصادقة."
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                desc = f"المستودع السحابي ({info['bucket_name']}) محمي بقواعد IAM ومصادقة سحابية (HTTP {e.code})."
            elif e.code == 404:
                desc = f"المستودع السحابي ({info['bucket_name']}) غير متاح للعامة أو خاص (HTTP 404)."
            else:
                desc = f"استجابة غير متوقعة من المستودع السحابي (كود {e.code})."
        except Exception as e:
            desc = f"تعذر التحقق من المستودع السحابي: {str(e)}"

        item = {
            "provider": info["provider"],
            "bucket_name": info["bucket_name"],
            "url": info["url"],
            "description": desc,
            "status": "OPEN" if is_open else "SECURE",
            "severity": "CRITICAL" if is_open else "SAFE"
        }

        if is_open:
            open_buckets.append(item)
        else:
            secure_buckets.append(item)

    return {
        "has_cloud_buckets": len(buckets_to_test) > 0,
        "total_buckets": len(buckets_to_test),
        "open_buckets_count": len(open_buckets),
        "open_buckets": open_buckets,
        "secure_buckets": secure_buckets
    }
