# keywords.py - قوائم الكلمات المفتاحية لرصد الطرق الحساسة والمكتبات

SENSITIVE_METHOD_KEYWORDS = [
    "camera", "location", "gps", "sms", "call", "contacts",
    "getDeviceId", "getSubscriberId", "getSimSerialNumber", "getImei",
    "sendTextMessage", "dial", "getPackageInfo", "exec", "loadLibrary"
]

ADS_LIBRARY_KEYWORDS = [
    "admob", "facebook", "advertising", "google_play_services",
    "applovin", "ironsource", "unityads", "mopub",
    "inappbilling", "billing", "payment"
]

NETWORK_CALL_KEYWORDS = [
    "http", "https", "socket", "url", "client", "connection",
    "ssl", "tls", "trustmanager", "certificate"
]

INTERESTING_STRING_KEYWORDS = [
    "http", "url", "api", "secret", "key", "password", "token",
    "database", "server", "endpoint", "debug", "test", "release"
]

VULNERABILITY_KEYWORDS = {
    "sql_injection": ["rawQuery", "execSQL", "query"],
    "insecure_storage": ["sharedpreferences", "getSharedPreferences"],
    "hardcoded_credentials": ["password", "api_key", "secret_key"],
    "weak_cryptography": ["MD5", "SHA1"]
}

KNOWN_LIBRARIES = {
    "okhttp": ["Lokhttp3/", "Lcom/squareup/okhttp/"],
    "retrofit": ["Lretrofit2/"],
    "gson": ["Lcom/google/gson/"],
    "firebase": ["Lcom/google/firebase/"],
    "glide": ["Lcom/bumptech/glide/"],
    "picasso": ["Lcom/squareup/picasso/"],
    "exoplayer": ["Lcom/google/android/exoplayer2/"],
    "dagger": ["Ldagger/"],
    "hilt": ["Lcom/google/dagger/hilt/"],
    "koin": ["Lorg/koin/"],
    "room": ["Landroidx/room/"],
    "rxjava": ["Lio/reactivex/"],
    "coroutines": ["Lkotlinx/coroutines/"],
    "sqlite": ["Landroid/database/sqlite/", "Landroidx/sqlite/"],
    "datastore": ["Landroidx/datastore/"],
    "workmanager": ["Landroidx/work/"],
    "mapbox": ["Lcom/mapbox/mapboxsdk/"]
}

KOTLIN_KEYWORDS = ["kotlin/", "kotlinx/"]
JAVA_KEYWORDS = ["java/", "javax/"]
