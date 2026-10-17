# development_analyzer.py
import os
import json
import re
from typing import Dict, List, Any
from androguard.core.apk import APK
from androguard.core.analysis.analysis import Analysis
from keywords import ADS_LIBRARY_KEYWORDS, KNOWN_LIBRARIES

class DevelopmentAnalyzer:
    def __init__(self, apk: APK, anydx: Analysis):
        self.apk = apk
        self.anydx = anydx

    def detect_languages_and_frameworks(self) -> Dict[str, Any]:
        """الكشف عن لغات البرمجة وأطر العمل المستخدمة."""
        kotlin_detected = False
        java_detected = False
        flutter_detected = False
        react_native_detected = False
        unity_detected = False
        compose_detected = False

        # فحص ملفات الحزمة
        files = self.apk.get_files() or []
        for file in files:
            if "libflutter.so" in file:
                flutter_detected = True
            if "libreactnativejni.so" in file or "assets/index.android.bundle" in file:
                react_native_detected = True
            if "libunity.so" in file:
                unity_detected = True

        # فحص الكلاسات والطرق
        xml_found = any(f.endswith(".xml") for f in files)

        try:
            for class_analysis in self.anydx.get_classes():
                class_name = class_analysis.name
                if "kotlin/" in class_name or "kotlinx/" in class_name:
                    kotlin_detected = True
                if "java/" in class_name:
                    java_detected = True
                if not compose_detected and any("Composable" in m.name for m in class_analysis.get_methods() or []):
                    compose_detected = True
        except Exception:
            pass

        return {
            "is_kotlin": kotlin_detected,
            "is_java": java_detected,
            "is_flutter": flutter_detected,
            "is_react_native": react_native_detected,
            "is_unity": unity_detected,
            "has_compose": compose_detected,
            "has_xml_layouts": xml_found
        }

    def check_ads_libraries(self) -> Dict[str, Any]:
        """الكشف عن مكتبات الإعلانات وشبكات التتبع."""
        ads_found = []
        try:
            for method in self.anydx.get_methods():
                m_name = method.name.lower()
                for keyword in ADS_LIBRARY_KEYWORDS:
                    if keyword in m_name:
                        ads_found.append({
                            'keyword': keyword,
                            'class_name': method.get_class_name(),
                            'method': method.name
                        })
                        break
        except Exception:
            pass

        # تصنيف المكتبات المكتشفة بدون تكرار
        detected_networks = set()
        for item in ads_found:
            detected_networks.add(item['keyword'])

        return {
            "has_ads": len(ads_found) > 0,
            "detected_networks": sorted(list(detected_networks)),
            "details_sample": ads_found[:15]
        }

    def detect_known_libraries(self) -> List[str]:
        """كشف المكتبات الشائعة المضمنة داخل التطبيق (مثل OkHttp, Retrofit, Room, Firebase)."""
        detected = []
        try:
            classes_names = [c.name for c in self.anydx.get_classes()]
            for lib_name, prefixes in KNOWN_LIBRARIES.items():
                if any(any(c.startswith(p) for p in prefixes) for c in classes_names):
                    detected.append(lib_name)
        except Exception:
            pass
        return detected

    def detect_exodus_trackers(self, urls: List[str] = None) -> Dict[str, Any]:
        """الكشف عن متتبعات وشبكات الخصوصية بالاعتماد على قاعدة بيانات Exodus Privacy."""
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exodus_trackers.json")
        trackers_db = []
        if os.path.exists(db_path):
            try:
                with open(db_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    trackers_db = data.get("trackers", [])
            except Exception:
                pass

        if not trackers_db:
            return {
                "total_detected": 0,
                "categories_summary": {},
                "trackers": []
            }

        # جمع أسماء الكلاسات بصيغة جافا
        java_classes = set()
        try:
            for c in self.anydx.get_classes():
                name = c.name
                if name.startswith("L") and name.endswith(";"):
                    name = name[1:-1]
                java_classes.add(name.replace("/", "."))
        except Exception:
            pass

        url_list = urls or []
        detected_trackers = []
        categories_count = {}

        for tracker in trackers_db:
            code_sig = tracker.get("code_signature", "").strip()
            net_sig = tracker.get("network_signature", "").strip()
            matched = False
            matched_by = None
            matched_samples = []

            # 1. مطابقة توقيع الكود
            if code_sig:
                patterns = [p.strip() for p in code_sig.split("|") if p.strip()]
                for pat in patterns:
                    for cls in java_classes:
                        if cls.startswith(pat) or pat in cls:
                            matched = True
                            matched_by = "CODE"
                            if len(matched_samples) < 3:
                                matched_samples.append(cls)
                    if matched:
                        break

            # 2. مطابقة توقيع الشبكة (في حال عدم المطابقة بالكود)
            if not matched and net_sig and url_list:
                for u in url_list:
                    try:
                        if re.search(net_sig, u, re.IGNORECASE):
                            matched = True
                            matched_by = "NETWORK"
                            matched_samples.append(u[:80])
                            break
                    except Exception:
                        pass

            if matched:
                t_cats = tracker.get("categories", ["Unknown"])
                for cat in t_cats:
                    categories_count[cat] = categories_count.get(cat, 0) + 1

                detected_trackers.append({
                    "id": tracker.get("id"),
                    "name": tracker.get("name"),
                    "categories": t_cats,
                    "website": tracker.get("website", ""),
                    "code_signature": code_sig,
                    "network_signature": net_sig,
                    "matched_by": matched_by,
                    "matched_samples": matched_samples
                })

        return {
            "total_detected": len(detected_trackers),
            "categories_summary": categories_count,
            "trackers": detected_trackers
        }

    def detect_architecture_profile(self) -> Dict[str, List[str]]:
        """
        الكشف المعماري الشامل عن طبقات التخزين وإدارة الحالة وحقن التبعيات والمهام الخلفية.
        """
        storage = []
        state = []
        di = []
        bg = []
        net = []
        crypto = []

        try:
            class_names = [c.name for c in self.anydx.get_classes()]

            def match(prefixes):
                return any(any(c.startswith(p) or p in c for p in prefixes) for c in class_names)

            # 1. التخزين وقواعد البيانات
            if match(["Landroidx/room/"]): storage.append("Room")
            if match(["Landroid/database/sqlite/", "Landroidx/sqlite/"]): storage.append("SQLite")
            if match(["Landroidx/datastore/"]): storage.append("DataStore")
            if match(["Landroid/content/SharedPreferences;", "Landroidx/preference/"]): storage.append("SharedPreferences")
            if match(["Lcom/tencent/mmkv/"]): storage.append("MMKV")
            if match(["Lio/realm/"]): storage.append("Realm")
            if match(["Lio/objectbox/"]): storage.append("ObjectBox")
            if match(["Lnet/sqlcipher/"]): storage.append("SQLCipher")

            # 2. إدارة الحالة (State Management)
            if match(["Landroidx/lifecycle/ViewModel"]): state.append("ViewModel")
            if match(["Landroidx/lifecycle/LiveData"]): state.append("LiveData")
            if match(["Lkotlinx/coroutines/flow/StateFlow", "Lkotlinx/coroutines/flow/SharedFlow"]): state.append("StateFlow")
            elif match(["Lkotlinx/coroutines/flow/"]): state.append("Coroutines Flow")
            if match(["Lio/reactivex/"]): state.append("RxJava")

            # 3. حقن التبعيات (Dependency Injection)
            if match(["Lcom/google/dagger/hilt/", "Ldagger/hilt/"]): di.append("Hilt")
            elif match(["Ldagger/"]): di.append("Dagger")
            if match(["Lorg/koin/"]): di.append("Koin")

            # 4. معالجة وجدولة المهام بالخلفية (Background Workers)
            if match(["Landroidx/work/"]): bg.append("WorkManager")
            if match(["Landroid/app/job/JobScheduler;"]): bg.append("JobScheduler")
            if match(["Landroid/app/AlarmManager;"]): bg.append("AlarmManager")
            if match(["Lcom/firebase/jobdispatcher/"]): bg.append("Firebase JobDispatcher")

            # 5. مكتبات الاتصال والشبكات (Networking Stack)
            if match(["Lretrofit2/"]): net.append("Retrofit")
            if match(["Lokhttp3/"]): net.append("OkHttp")
            if match(["Lio/ktor/"]): net.append("Ktor")
            if match(["Lcom/android/volley/"]): net.append("Volley")
            if match(["Lcom/apollographql/apollo"]): net.append("Apollo GraphQL")

            # 6. أطر التشفير والحماية (Cryptographic Frameworks)
            if match(["Ljava/security/KeyStore;", "Landroid/security/keystore/"]): crypto.append("Android KeyStore")
            if match(["Lorg/bouncycastle/"]): crypto.append("BouncyCastle")
            if match(["Lorg/conscrypt/"]): crypto.append("Conscrypt")
            if match(["Lcom/google/crypto/tink/"]): crypto.append("Google Tink")
            if match(["Ljavax/crypto/"]): crypto.append("Javax Crypto")

        except Exception:
            pass

        return {
            "local_storage": sorted(list(set(storage))),
            "state_management": sorted(list(set(state))),
            "dependency_injection": sorted(list(set(di))),
            "background_tasks": sorted(list(set(bg))),
            "networking_stack": sorted(list(set(net))),
            "cryptography": sorted(list(set(crypto)))
        }

    def infer_app_category(self, permissions: List[str] = None, activities: List[str] = None) -> Dict[str, Any]:
        """
        استنتاج تصنيف وفئة التطبيق بناءً على الصلاحيات والأنشطة والمكتبات المكتشفة.
        """
        perms = permissions or []
        acts = [a.lower() for a in (activities or [])]

        class_names = []
        try:
            class_names = [c.name for c in self.anydx.get_classes()]
        except Exception:
            pass

        scores = {
            "Game": 0,
            "Social Media": 0,
            "Shopping": 0,
            "Finance": 0,
            "Travel & Local": 0,
            "Media & Video": 0,
            "Productivity": 0,
            "Tools": 0,
            "Health & Fitness": 0,
            "Education": 0,
            "Communication": 0,
            "News & Magazines": 0
        }

        # 1. تقييم الصلاحيات
        if any(p in perms for p in ["android.permission.CAMERA", "android.permission.RECORD_AUDIO"]):
            scores["Social Media"] += 2
            scores["Media & Video"] += 2
            scores["Communication"] += 2

        if any(p in perms for p in ["android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"]):
            scores["Travel & Local"] += 3
            scores["Shopping"] += 1

        if any(p in perms for p in ["android.permission.SEND_SMS", "android.permission.RECEIVE_SMS", "android.permission.READ_SMS"]):
            scores["Communication"] += 3
            scores["Social Media"] += 1

        if "android.permission.READ_CONTACTS" in perms:
            scores["Communication"] += 2
            scores["Social Media"] += 2

        if "android.permission.BODY_SENSORS" in perms or "android.permission.ACTIVITY_RECOGNITION" in perms:
            scores["Health & Fitness"] += 4

        # 2. تقييم كلاسات الكود والـ SDKs
        def has_pkg(pkg_sig):
            return any(pkg_sig in c for c in class_names)

        if has_pkg("com/google/android/gms/maps") or has_pkg("com/mapbox/"):
            scores["Travel & Local"] += 3

        if has_pkg("com/stripe/") or has_pkg("com/paypal/") or has_pkg("com/braintreepayments/") or has_pkg("com/squareup/"):
            scores["Finance"] += 4
            scores["Shopping"] += 3

        if has_pkg("com/google/android/exoplayer2/") or has_pkg("androidx/media3/") or has_pkg("tv/danmaku/ijk/"):
            scores["Media & Video"] += 4

        if has_pkg("com/unity3d/") or has_pkg("org/cocos2dx/") or has_pkg("com/epicgames/ue4/"):
            scores["Game"] += 6

        if has_pkg("com/facebook/") or has_pkg("com/twitter/") or has_pkg("com/instagram/"):
            scores["Social Media"] += 2

        # 3. تقييم أسماء الـ Activities
        for a in acts:
            if any(k in a for k in ["game", "level", "player", "unity", "cocos", "play", "stage", "arcade"]):
                scores["Game"] += 2
            if any(k in a for k in ["cart", "checkout", "order", "product", "shop", "catalog"]):
                scores["Shopping"] += 3
            if any(k in a for k in ["wallet", "transfer", "bank", "payment", "crypto", "card", "loan"]):
                scores["Finance"] += 3
            if any(k in a for k in ["chat", "message", "conversation", "call", "inbox"]):
                scores["Communication"] += 3
            if any(k in a for k in ["feed", "profile", "timeline", "follower", "friend", "story", "post"]):
                scores["Social Media"] += 2
            if any(k in a for k in ["editor", "document", "sheet", "note", "task", "calendar", "todo"]):
                scores["Productivity"] += 2
            if any(k in a for k in ["reader", "article", "news", "feed", "blog", "rss"]):
                scores["News & Magazines"] += 2
            if any(k in a for k in ["workout", "fitness", "diet", "calorie", "step", "heart", "gym"]):
                scores["Health & Fitness"] += 3
            if any(k in a for k in ["lesson", "quiz", "course", "exam", "learn", "study"]):
                scores["Education"] += 3

        best_category = max(scores, key=scores.get)
        max_score = scores[best_category]

        if max_score < 2:
            best_category = "Tools"  # الفئة الافتراضية للتطبيقات الخدمية

        return {
            "inferred_category": best_category,
            "confidence_score": max_score,
            "category_scores": {k: v for k, v in scores.items() if v > 0}
        }

    def generate_natural_summary(self, app_name: str, permissions: List[str], features: List[str],
                                 has_ads: bool, min_sdk_name: str, inferred_category: str) -> Dict[str, Any]:
        """
        إنشاء ملخص تنفيذي مقروء باللغتين العربية والإنجليزية يصف قدرات التطبيق ومتطلباته.
        """
        perms = permissions or []
        feats = features or []

        has_internet = any(p in perms for p in ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"])
        has_camera = any(p in perms for p in ["android.permission.CAMERA"]) or any("camera" in f.lower() for f in feats)
        has_location = any("location" in p.lower() for p in perms) or any("location" in f.lower() for f in feats)
        has_microphone = "android.permission.RECORD_AUDIO" in perms or any("microphone" in f.lower() for f in feats)
        has_bluetooth = any("bluetooth" in p.lower() for p in perms) or any("bluetooth" in f.lower() for f in feats)
        has_storage_access = any("storage" in p.lower() or "media" in p.lower() for p in perms)

        # الملخص العربي
        parts_ar = [f"تطبيق {app_name} (فئة: {inferred_category}):"]
        highlights_ar = []

        if has_internet:
            parts_ar.append("يتطلب اتصالاً بالإنترنت للعمل.")
            highlights_ar.append("متصل بالإنترنت")
        else:
            parts_ar.append("يعمل دون الحاجة إلى اتصال بالإنترنت (Offline).")
            highlights_ar.append("يعمل دون اتصال")

        if has_ads:
            parts_ar.append("يحتوي على شبكات إعلانية مدعومة.")
            highlights_ar.append("يحتوي على إعلانات")
        else:
            parts_ar.append("خالٍ من شبكات الإعلانات الظاهرة.")
            highlights_ar.append("خالٍ من الإعلانات")

        hardware_ar = []
        if has_camera: hardware_ar.append("الكاميرا")
        if has_location: hardware_ar.append("تحديد الموقع الجغرافي")
        if has_microphone: hardware_ar.append("الميكروفون")
        if has_bluetooth: hardware_ar.append("البلوتوث")
        if has_storage_access: hardware_ar.append("الوصول للملفات")

        if hardware_ar:
            parts_ar.append(f"يصل إلى عتاد الجهاز: {', '.join(hardware_ar)}.")
            highlights_ar.extend(hardware_ar)

        parts_ar.append(f"الحد الأدنى للنظام المطلوب: {min_sdk_name} أو أحدث.")

        # الملخص الإنجليزي
        parts_en = [f"App '{app_name}' (Category: {inferred_category}):"]
        highlights_en = []

        if has_internet:
            parts_en.append("Requires an active internet connection.")
            highlights_en.append("Online Service")
        else:
            parts_en.append("Fully functional offline.")
            highlights_en.append("Offline Capable")

        if has_ads:
            parts_en.append("Integrated with monetization advertising networks.")
            highlights_en.append("Contains Ads")
        else:
            parts_en.append("Ad-free experience.")
            highlights_en.append("Ad-Free")

        hardware_en = []
        if has_camera: hardware_en.append("Camera")
        if has_location: hardware_en.append("Location Tracking")
        if has_microphone: hardware_en.append("Microphone")
        if has_bluetooth: hardware_en.append("Bluetooth")
        if has_storage_access: hardware_en.append("Storage Access")

        if hardware_en:
            parts_en.append(f"Accesses device hardware: {', '.join(hardware_en)}.")
            highlights_en.extend(hardware_en)

        parts_en.append(f"System Requirement: {min_sdk_name} or later.")

        return {
            "summary_ar": " ".join(parts_ar),
            "summary_en": " ".join(parts_en),
            "highlights_ar": highlights_ar,
            "highlights_en": highlights_en
        }

