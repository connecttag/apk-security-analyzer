# 🛡️ Android APK Security & Vulnerability Analyzer

An advanced, comprehensive **Static Application Security Testing (SAST)** and forensic analysis suite for Android applications (APKs). Automatically assesses mobile applications against the **OWASP Mobile Application Security Verification Standard (MASVS)**, detects hardcoded secrets, audits cryptographic usage, analyzes native libraries, and generates detailed compliance reports.

---

## 🚀 Key Features

- **📊 OWASP Mobile / MASVS Compliance Matrix:** Automatically scores APKs across MASVS categories (Storage, Cryptography, Authentication, Network, Platform Interaction, Code Quality).
- **🔑 Leaked Secrets & API Keys Detection:** Scans DEX bytecodes and strings for exposed AWS credentials, Stripe keys, GitHub tokens, Google Cloud API keys, private certificates, and staging server endpoints.
- **🔐 Cryptographic Security Audit:** Detects insecure algorithms (MD5, SHA-1, DES, RC4), hardcoded symmetric keys, static IVs, and predictable seeds.
- **🌐 Network & Cloud Asset Analysis:** Identifies cleartext HTTP traffic, insecure SSL/TLS configurations, and exposed Firebase Realtime Databases or AWS S3 / Google Cloud Storage buckets.
- **📱 Component & IPC Vulnerability Scanning:** Inspects AndroidManifest.xml for exported activities, services, receivers, and content providers lacking proper permissions or prone to intent redirection.
- **🌐 WebView Security Audit:** Detects dangerous settings (`setJavaScriptEnabled`, `allowFileAccess`, `setAllowUniversalAccessFromFileURLs`) and SSL certificate bypasses (`handler.proceed()`).
- **🛡️ Native Binary Security (.so Checksec):** Analyzes ELF native shared objects for security hardening flags (NX Bit, PIE, Full/Partial RELRO, Stack Canaries).
- **📦 SBOM & Tracker Detection:** Extracts Software Bill of Materials (SBOM) and detects third-party advertising, analytics, and telemetry trackers (integrated with Exodus Privacy).
- **🔄 Version Diffing Engine:** Compares two versions of the same APK to highlight newly introduced permissions, components, trackers, or security regressions.
- **🛠️ Smart Security Patcher:** Automatically decompile, patch (`FLAG_SECURE` removal, SSL Pinning bypass, force debuggable, root detection neutralization), re-align, and re-sign APKs.
- **📑 Multi-Format Reporting:** Exports findings into structured JSON, interactive HTML dashboards, Markdown summaries, or SQL catalogs.

---

## 📁 Project Structure

```text
apk-security-analyzer/
├── data/
│   └── blacklist.json           # Suspicious domains and tracker patterns
├── temp_icons/                  # Temporary extraction directory for APK icons
├── apk_inspector.py             # Main inspection & analysis orchestration engine
├── apk_patcher.py               # Smart binary patcher and rebuilder
├── security_analyzer.py         # Core security and vulnerability checks
├── crypto_audit.py              # Cryptographic implementation auditor
├── secrets_analyzer.py          # Hardcoded secrets and token detector
├── network_analyzer.py          # URL, domain, and transport security analyzer
├── owasp_matrix.py              # OWASP MASVS compliance matrix mapper
├── webview_analyzer.py          # WebView security auditor
├── ipc_analyzer.py              # IPC and Intent redirection analyzer
├── cloud_bucket_analyzer.py     # Public S3/GCS bucket auditor
├── firebase_analyzer.py         # Open Firebase database scanner
├── entropy_analyzer.py          # High-entropy secret and packing detector
├── elf_checksec.py              # Native ELF binary hardening analyzer
├── sbom_analyzer.py             # Software Bill of Materials extractor
├── report_generator.py          # HTML and Markdown report generator
├── resource_editor.py           # Resource and asset extractor
├── toolchain_detector.py        # Framework detection (Flutter, React Native, Unity, Xamarin)
├── info_extractor.py            # Manifest metadata and package information
├── playstore_verifier.py        # Google Play Store package verification
├── constants.py                 # Core constants and configurations
├── domains.py                   # Domain extraction regex and utilities
├── keywords.py                  # Vulnerability signatures and keyword lists
├── exodus_trackers.json         # Exodus privacy tracker signatures
├── main.py                      # CLI entry point
├── requirements.txt             # Python dependencies
├── LICENSE                      # MIT License
└── README.md                    # Documentation
```

---

## 🛠️ Installation

### Prerequisites
- **Python 3.9+**
- (Optional for patching) `apktool`, `zipalign`, `apksigner`

### Setup
```bash
git clone https://github.com/connecttag/apk-security-analyzer.git
cd apk-security-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 CLI Usage

### 1. Full Security Audit & JSON Report
```bash
python main.py path/to/app.apk --output report.json
```

### 2. Export Interactive HTML Report
```bash
python main.py path/to/app.apk --export-html report.html
```

### 3. Export Markdown Report
```bash
python main.py path/to/app.apk --export-md report.md
```

### 4. Compare Two APK Versions (Security Diff)
```bash
python main.py --diff v1.0.apk v2.0.apk --output diff_report.json
```

### 5. Inspect Manifest Only
```bash
python main.py path/to/app.apk --manifest
```

### 6. Extract All Icons & Visual Assets
```bash
python main.py path/to/app.apk --export-all-icons ./icons_output
```

---

## 🔧 Smart Patcher Usage (`apk_patcher.py`)

Apply automated security testing patches (e.g. For penetration testing or dynamic analysis):

```bash
# Bypass SSL Pinning and allow user certificates
python apk_patcher.py path/to/app.apk --patch-ssl --rebuild --sign --output patched.apk

# Disable FLAG_SECURE (allow screenshots in protected apps)
python apk_patcher.py path/to/app.apk --patch-screen --rebuild --sign

# Enable debugging (android:debuggable="true")
python apk_patcher.py path/to/app.apk --patch-debug --rebuild --sign

# Full bypass suite + auto-install to connected device
python apk_patcher.py path/to/app.apk --patch-all --rebuild --sign --install
```

---

## 📄 License

This project is licensed under the **[MIT License](LICENSE)**.
