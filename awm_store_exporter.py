# awm_store_exporter.py
# -*- coding: utf-8 -*-
"""
awm_store_exporter.py - مولد استعلامات وحزم متجر AwmStore
(AwmStore Schema & Packaging Exporter)
متوافق بنسبة 100% مع منطق F:\\my-software-projects\\Python\\androgeard\\store
يقوم بتوليد:
1. استعلامات SQL لجداول applications_tbl, applications_versions_tbl, applications_permissions_tbl,
   scans_tbl, scan_versions, scan_permissions, scan_components, scan_app_libraries, scan_app_urls, إلخ.
2. بنية مجلدات النشر الخاصة بمتجر AwmStore (images, release, database, scan) أو أرشيف ZIP مضغوط.
"""

import os
import io
import json
import shutil
import zipfile
import tempfile
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

ANDROID_SDK_VERSIONS = {
    14: "Android 4.0",
    15: "Android 4.0.3",
    16: "Android 4.1",
    17: "Android 4.2",
    18: "Android 4.3",
    19: "Android 4.4",
    21: "Android 5.0",
    22: "Android 5.1",
    23: "Android 6.0",
    24: "Android 7.0",
    25: "Android 7.1",
    26: "Android 8.0",
    27: "Android 8.1",
    28: "Android 9.0",
    29: "Android 10.0",
    30: "Android 11.0",
    31: "Android 12.0",
    32: "Android 12L",
    33: "Android 13.0",
    34: "Android 14.0",
    35: "Android 15.0",
    36: "Android 16.0",
}

FEATURE_TRANSLATIONS = {
    'android.hardware.camera': 'كاميرا',
    'android.hardware.camera.autofocus': 'كاميرا مع تركيز تلقائي',
    'android.hardware.camera.flash': 'كاميرا مع فلاش',
    'android.hardware.bluetooth': 'بلوتوث',
    'android.hardware.location': 'تحديد الموقع',
    'android.hardware.location.gps': 'GPS',
    'android.hardware.location.network': 'تحديد الموقع عبر الشبكة',
    'android.hardware.microphone': 'ميكروفون',
    'android.hardware.sensor.accelerometer': 'مستشعر الحركة',
    'android.hardware.touchscreen': 'شاشة لمس',
    'android.hardware.wifi': 'واي فاي',
    'android.software.live_wallpaper': 'خلفيات متحركة',
    'android.hardware.screen.portrait': 'وضع عمودي',
    'android.hardware.screen.landscape': 'وضع أفقي',
    'android.hardware.fingerprint': 'بصمة الإصبع',
    'android.hardware.biometrics': 'القياسات الحيوية',
    'android.hardware.nfc': 'الاتصال قريب المدى (NFC)',
}


class AwmStoreExporter:
    def __init__(self, db_name: str = "awm_store_db"):
        self.db_name = db_name

    def normalize_analysis_data(self, inspection: Dict[str, Any], apk_path: str = "") -> Dict[str, Any]:
        """
        توحيد وتجهيز البيانات المستخرجة من سَبْر لتطابق بنية قاموس analysis_data في androgeard/store.
        """
        basic = inspection.get("basic_info", {})
        hashes = inspection.get("hashes", {})
        security = inspection.get("security", {})
        dev = inspection.get("development", {})
        perms_info = inspection.get("permissions", {})
        comps = inspection.get("components", {})
        resources = inspection.get("resources_summary", {})
        localization = resources.get("localization", {})
        network = inspection.get("network", {})

        pkg_name = basic.get("package_name") or inspection.get("package_name", "unknown")
        app_name = basic.get("app_name") or inspection.get("app_name", pkg_name)
        ver_info = basic.get("version", {})
        ver_code = ver_info.get("code") if isinstance(ver_info, dict) else inspection.get("version_code", 0)
        ver_name = ver_info.get("name") if isinstance(ver_info, dict) else inspection.get("version_name", "1.0")

        sdk_info = basic.get("sdk_versions", {})
        min_sdk = sdk_info.get("min") if isinstance(sdk_info, dict) else inspection.get("min_sdk", 21)
        target_sdk = sdk_info.get("target") if isinstance(sdk_info, dict) else inspection.get("target_sdk", 33)
        min_sdk_name = ANDROID_SDK_VERSIONS.get(int(min_sdk or 0), f"Android {min_sdk}")

        size_mb = basic.get("size_mb", 0.0)
        if size_mb == 0.0 and apk_path and os.path.exists(apk_path):
            size_mb = round(os.path.getsize(apk_path) / (1024 * 1024), 2)

        # استخراج الصلاحيات
        all_perms = perms_info.get("all_permissions") or inspection.get("permissions", [])
        if isinstance(all_perms, dict):
            all_perms = list(all_perms.keys())

        # استخراج الشهادات
        sig_info = security.get("signatures", {})
        certs = sig_info.get("certs", [])
        if not certs and isinstance(security.get("certificates"), list):
            certs = security.get("certificates")

        # ميزات العتاد
        features = []
        raw_features = comps.get("features", [])
        if raw_features:
            features = raw_features
        elif "hardware_matrix" in basic and "features" in basic["hardware_matrix"]:
            features = [f.get("name") for f in basic["hardware_matrix"]["features"] if f.get("name")]

        # معلومات الإعلانات والمكتبات
        ads_info = dev.get("ads_libraries", {})
        has_ads = ads_info.get("has_ads", False)
        ads_libraries = ads_info.get("ads_libraries", [])

        # اللغات
        supports_arabic = localization.get("supports_arabic", False)
        supports_english = localization.get("supports_english", True)
        default_lang = localization.get("default_language", "ar" if supports_arabic else "en")
        supported_locales = localization.get("supported_locales", [])

        # الحسابات البصرية والمكونات
        activities = comps.get("activities", [])
        services = comps.get("services", [])
        receivers = comps.get("receivers", [])
        providers = comps.get("providers", [])

        # الشبكات
        urls = network.get("urls", {}).get("other_urls", []) if isinstance(network.get("urls"), dict) else network.get("urls", [])
        ip_addresses = network.get("ip_addresses", [])

        # الكشف عن لغة التطوير
        lang_info = dev.get("language_info", {})
        is_kotlin = lang_info.get("is_kotlin", False)
        is_java = lang_info.get("is_java", True)

        return {
            "package_name": pkg_name,
            "app_name": app_name,
            "version_code": str(ver_code),
            "version_name": str(ver_name),
            "min_sdk": int(min_sdk or 0),
            "target_sdk": int(target_sdk or 0),
            "min_sdk_name": min_sdk_name,
            "size_mb": float(size_mb),
            "hashes": hashes,
            "features": features,
            "permissions": all_perms,
            "certificates": certs,
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "development": {
                "language_info": {"is_kotlin": is_kotlin, "is_java": is_java},
                "ads_libraries": {"has_ads": has_ads, "ads_libraries": ads_libraries},
                "dependency_injection": dev.get("dependency_injection", {}),
                "state_management": dev.get("state_management", {}),
            },
            "languages_info": {
                "default_language": default_lang,
                "supported_locales": supported_locales,
                "supports_arabic": supports_arabic,
                "supports_english": supports_english
            },
            "network": {
                "urls": {"other_urls": urls},
                "ip_addresses": ip_addresses
            },
            "sensitive_methods": security.get("sensitive_methods", []),
            "main_activity_filters": security.get("main_activity_filters", {})
        }

    def _generate_description(self, analysis_data: Dict[str, Any]) -> str:
        """
        إنشاء وصف تلقائي باللغة العربية مطابق تماماً لمنطق androgeard/store.
        """
        permissions = analysis_data.get('permissions', [])
        has_internet = any(
            perm in permissions for perm in
            ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"]
        )
        has_ads = analysis_data.get('development', {}).get('ads_libraries', {}).get('has_ads', False)

        parts = [f"تطبيق {analysis_data['app_name']}:"]

        # الميزات
        translated_features = []
        for feature in analysis_data.get('features', []):
            translated_features.append(FEATURE_TRANSLATIONS.get(feature, feature.replace('android.hardware.', '').replace('android.', '')))

        if translated_features:
            parts.append("\n\nالميزات المدعومة:")
            for feature in sorted(set(translated_features)):
                parts.append(f"\n- {feature}")

        # الصلاحيات
        if not permissions:
            parts.append("\n\nلا يطلب التطبيق أي صلاحيات إجبارية.")

        # الاتصال بالإنترنت
        parts.append("\n\nيتطلب اتصالاً بالإنترنت." if has_internet else "\n\nلا يتطلب اتصالاً بالإنترنت.")

        # الإعلانات
        parts.append("\nيحتوي على إعلانات." if has_ads else "\nخالي من الإعلانات.")

        # متطلبات النظام
        parts.append(f"\n\nمتطلبات النظام: أندرويد {analysis_data['min_sdk_name']} أو أحدث.")

        return ''.join(parts)

    def _generate_id(self, package_name: str) -> int:
        """توليد معرف رقمي فريد ومستقر للحزمة"""
        digest = hashlib.md5(package_name.encode('utf-8')).hexdigest()
        return abs(int(digest[:7], 16)) % 9000000 + 1000

    def _generate_scan_id(self, package_name: str, version_code: Any) -> int:
        """توليد معرف فحص فريد"""
        s = f"{package_name}_{version_code}_{int(datetime.now().timestamp())}"
        digest = hashlib.sha1(s.encode('utf-8')).hexdigest()
        return abs(int(digest[:8], 16)) % 9000000000 + 1000000000

    def generate_schema_ddl(self) -> str:
        """
        توليد تعريف جداول AwmStore لضمان إمكانية تشغيل السكربت مباشرة دون أخطاء.
        """
        return f"""-- ===========================================================================
-- AwmStore Database Schema Definitions
-- ===========================================================================
CREATE DATABASE IF NOT EXISTS `{self.db_name}`;
USE `{self.db_name}`;

CREATE TABLE IF NOT EXISTS `applications_tbl` (
    `id` BIGINT NOT NULL,
    `recordID` BIGINT NOT NULL,
    `packageName` VARCHAR(255) NOT NULL,
    `UniqueID2` VARCHAR(255) NOT NULL,
    `name` VARCHAR(255) NOT NULL,
    `nameEn` VARCHAR(255),
    `size` DECIMAL(10, 2),
    `description` TEXT,
    `finalDownloadUrl` VARCHAR(500),
    `image` VARCHAR(255),
    `imageCover` VARCHAR(255),
    `sha1` VARCHAR(40),
    `sha256` VARCHAR(64),
    `md5` VARCHAR(32),
    `signatureSha1` VARCHAR(64),
    `signatureOwner` TEXT,
    `usedFeatures` TEXT,
    `minSdk` INT,
    `targetSdk` INT,
    `isFree` TINYINT(1) DEFAULT 1,
    `hasAds` TINYINT(1) DEFAULT 0,
    `isOriginal` TINYINT(1) DEFAULT 1,
    `isSafe` TINYINT(1) DEFAULT 1,
    `isVerified` TINYINT(1) DEFAULT 0,
    `checked` TINYINT(1) DEFAULT 1,
    `isChecked` TINYINT(1) DEFAULT 1,
    `isPublic` TINYINT(1) DEFAULT 1,
    `operationRequirements` VARCHAR(255),
    `needPermissions` TINYINT(1) DEFAULT 0,
    `isNeedNetwork` TINYINT(1) DEFAULT 0,
    `needInternet` TINYINT(1) DEFAULT 0,
    `allowRemove` TINYINT(1) DEFAULT 1,
    `isAccessRestricted` TINYINT(1) DEFAULT 0,
    `isNeedLogin` TINYINT(1) DEFAULT 0,
    `isHasRegistration` TINYINT(1) DEFAULT 0,
    `isAllowShowPermissions` TINYINT(1) DEFAULT 1,
    `isAllowShowDownloadList` TINYINT(1) DEFAULT 0,
    `active` TINYINT(1) DEFAULT 1,
    `createAt` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `createBy` BIGINT DEFAULT 1,
    `updateAt` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_package` (`packageName`)
);

CREATE TABLE IF NOT EXISTS `applications_versions_tbl` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `masterApplicationID` BIGINT NOT NULL,
    `code` INT NOT NULL,
    `name` VARCHAR(100) NOT NULL,
    `size` DECIMAL(10, 2),
    `description` TEXT,
    `createAt` DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS `applications_permissions_tbl` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `masterApplicationID` BIGINT NOT NULL,
    `code` VARCHAR(255) NOT NULL,
    `createAt` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updateAt` DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS `scans_tbl` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `applicationId` BIGINT NOT NULL,
    `packageName` VARCHAR(255) NOT NULL,
    `versionCode` VARCHAR(50),
    `versionName` VARCHAR(100),
    `sizeMb` DECIMAL(10, 2),
    `minSdk` INT,
    `targetSdk` INT,
    `sha1` VARCHAR(40),
    `sha256` VARCHAR(64),
    `md5` VARCHAR(32),
    `activitiesCount` INT DEFAULT 0,
    `servicesCount` INT DEFAULT 0,
    `receiversCount` INT DEFAULT 0,
    `providersCount` INT DEFAULT 0,
    `permissionsCount` INT DEFAULT 0,
    `isKotlin` TINYINT(1) DEFAULT 0,
    `isJava` TINYINT(1) DEFAULT 1,
    `hasAds` TINYINT(1) DEFAULT 0,
    `sensitiveMethodsCount` INT DEFAULT 0,
    `hasIntentFilters` TINYINT(1) DEFAULT 0,
    `urlsCount` INT DEFAULT 0,
    `ipAddressesCount` INT DEFAULT 0,
    `defaultLanguage` VARCHAR(50),
    `supportedLocales` TEXT,
    `supportsArabic` TINYINT(1) DEFAULT 0,
    `supportsEnglish` TINYINT(1) DEFAULT 1,
    `apkPath` VARCHAR(500),
    `createdAt` DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS `scan_versions` (
    `id` BIGINT PRIMARY KEY,
    `application_id` BIGINT NOT NULL,
    `version_code` INT,
    `version_name` VARCHAR(100),
    `size_mb` DECIMAL(10, 2),
    `min_sdk` INT,
    `target_sdk` INT,
    `file_sha1` VARCHAR(40),
    `file_sha256` VARCHAR(64),
    `file_md5` VARCHAR(32),
    `apk_path` VARCHAR(500),
    `activities_count` INT DEFAULT 0,
    `services_count` INT DEFAULT 0,
    `receivers_count` INT DEFAULT 0,
    `providers_count` INT DEFAULT 0,
    `permissions_count` INT DEFAULT 0,
    `is_kotlin` TINYINT(1) DEFAULT 0,
    `is_java` TINYINT(1) DEFAULT 1,
    `has_ads_detected` TINYINT(1) DEFAULT 0,
    `sensitive_methods_count` INT DEFAULT 0,
    `has_intent_filters` TINYINT(1) DEFAULT 0,
    `urls_count` INT DEFAULT 0,
    `ip_addresses_count` INT DEFAULT 0,
    `default_language` VARCHAR(50),
    `supports_arabic` TINYINT(1) DEFAULT 0,
    `supports_english` TINYINT(1) DEFAULT 1,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS `scan_permissions` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` BIGINT NOT NULL,
    `permission_name` VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS `scan_components` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` BIGINT NOT NULL,
    `component_type` VARCHAR(50) NOT NULL,
    `component_name` VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS `scan_app_libraries` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` BIGINT NOT NULL,
    `library_name` VARCHAR(255) NOT NULL,
    `library_type` VARCHAR(50) NOT NULL
);

CREATE TABLE IF NOT EXISTS `scan_app_urls` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` BIGINT NOT NULL,
    `url` TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS `scan_app_sensitive_methods` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` BIGINT NOT NULL,
    `method_signature` VARCHAR(500) NOT NULL
);

CREATE TABLE IF NOT EXISTS `scan_app_certificates` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` BIGINT NOT NULL,
    `issuer` TEXT,
    `subject` TEXT,
    `sha1` VARCHAR(40),
    `sha256` VARCHAR(64),
    `valid_from` VARCHAR(100),
    `valid_until` VARCHAR(100)
);

"""

    def generate_all_sql(self, analysis_data: Dict[str, Any], apk_rel_path: str = "") -> str:
        """
        توليد سكربت SQL الشامل لمتجر AwmStore مع كافة الجداول والبيانات.
        """
        app_id = self._generate_id(analysis_data['package_name'])
        scan_id = self._generate_scan_id(analysis_data['package_name'], analysis_data['version_code'])

        pkg_name = analysis_data['package_name']
        app_name = analysis_data['app_name'].replace("'", "''")
        package_parts = pkg_name.split('.')
        package_last_part = package_parts[-1] if package_parts else pkg_name

        description = self._generate_description(analysis_data).replace("'", "''")

        sig_info = analysis_data['certificates'][0] if analysis_data.get('certificates') else {}
        signature_sha1 = sig_info.get('sha1', '')
        signature_owner = sig_info.get('issuer', 'Unknown').replace("'", "''")
        used_features = ", ".join(analysis_data.get('features', [])).replace("'", "''") if analysis_data.get('features') else ""

        main_icon_name = "ic_launcher.webp"
        apk_copy_name = f"{pkg_name}.apk"
        apk_final_path = apk_rel_path if apk_rel_path else f"output/applications/{pkg_name}/release/{apk_copy_name}"

        has_ads = 1 if analysis_data['development']['ads_libraries'].get('has_ads') else 0
        has_internet_permission = any(
            perm in analysis_data['permissions'] for perm in
            ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"]
        )
        is_need_network = 1 if has_internet_permission else 0
        need_permissions = 1 if analysis_data['permissions'] else 0

        operation_requirements = f"يتطلب أندرويد {analysis_data['min_sdk_name']} والأحدث .".replace("'", "''")

        sha1 = analysis_data['hashes'].get('sha1', '')
        sha256 = analysis_data['hashes'].get('sha256', '')
        md5 = analysis_data['hashes'].get('md5', '')

        version_code_int = int(analysis_data['version_code']) if analysis_data.get('version_code') and str(analysis_data['version_code']).isdigit() else 0
        version_name = analysis_data['version_name'].replace("'", "''")

        lines = [
            f"-- ===========================================================================",
            f"-- AwmStore Database Exporter (Integrated into Sabr Studio)",
            f"-- Target: {pkg_name} ({app_name}) v{version_name} ({version_code_int})",
            f"-- Generated on: {datetime.now().isoformat()}",
            f"-- ===========================================================================\n",
            self.generate_schema_ddl(),
            f"-- 1. INSERT INTO applications_tbl",
            f"INSERT INTO applications_tbl (",
            f"    id, recordID, packageName, UniqueID2, name, nameEn, size, description, finalDownloadUrl, image, imageCover,",
            f"    sha1, sha256, md5, signatureSha1, signatureOwner, usedFeatures,",
            f"    minSdk, targetSdk, isFree, hasAds, isOriginal, isSafe, isVerified, checked, isChecked, isPublic,",
            f"    operationRequirements, needPermissions, isNeedNetwork, needInternet, allowRemove, isAccessRestricted,",
            f"    isNeedLogin, isHasRegistration, isAllowShowPermissions, isAllowShowDownloadList,",
            f"    active, createAt, createBy, updateAt",
            f") VALUES (",
            f"    {app_id}, {app_id}, '{pkg_name}', '{pkg_name}', '{app_name}', '{package_last_part}',",
            f"    {analysis_data['size_mb']:.2f}, '{description}', '{apk_copy_name}', '{main_icon_name}', '',",
            f"    '{sha1}', '{sha256}', '{md5}', '{signature_sha1}', '{signature_owner}', '{used_features}',",
            f"    {analysis_data['min_sdk']}, {analysis_data['target_sdk']}, 1, {has_ads}, 1, 1, 1, 1, 1, 1,",
            f"    '{operation_requirements}', {need_permissions}, {is_need_network}, {1 if has_internet_permission else 0},",
            f"    1, 0, 0, 0, 1, 0, 1, NOW(), 1, NOW()",
            f") ON DUPLICATE KEY UPDATE",
            f"    name = VALUES(name), size = VALUES(size), description = VALUES(description),",
            f"    sha1 = VALUES(sha1), sha256 = VALUES(sha256), md5 = VALUES(md5), updateAt = NOW();\n",

            f"-- 2. INSERT INTO applications_versions_tbl",
            f"INSERT INTO applications_versions_tbl (",
            f"    masterApplicationID, code, name, size, description",
            f") VALUES (",
            f"    {app_id}, {version_code_int}, '{version_name}', {analysis_data['size_mb']:.2f}, ''",
            f");\n",

            f"-- 3. INSERT INTO applications_permissions_tbl",
            f"DELETE FROM applications_permissions_tbl WHERE masterApplicationID = {app_id};"
        ]

        for perm in analysis_data['permissions']:
            clean_perm = perm.replace("'", "''")
            lines.append(f"INSERT INTO applications_permissions_tbl (masterApplicationID, code, createAt, updateAt) VALUES ({app_id}, '{clean_perm}', NOW(), NOW());")
        lines.append("")

        # 4. Scans Table
        lines.extend([
            f"-- 4. INSERT INTO scans_tbl",
            f"INSERT INTO scans_tbl (",
            f"    applicationId, packageName, versionCode, versionName, sizeMb, minSdk, targetSdk,",
            f"    sha1, sha256, md5, activitiesCount, servicesCount, receiversCount, providersCount, permissionsCount,",
            f"    isKotlin, isJava, hasAds, sensitiveMethodsCount, hasIntentFilters, urlsCount, ipAddressesCount,",
            f"    defaultLanguage, supportedLocales, supportsArabic, supportsEnglish, apkPath, createdAt",
            f") VALUES (",
            f"    {app_id}, '{pkg_name}', '{version_code_int}', '{version_name}', {analysis_data['size_mb']:.2f},",
            f"    {analysis_data['min_sdk']}, {analysis_data['target_sdk']}, '{sha1}', '{sha256}', '{md5}',",
            f"    {len(analysis_data['activities'])}, {len(analysis_data['services'])}, {len(analysis_data['receivers'])},",
            f"    {len(analysis_data['providers'])}, {len(analysis_data['permissions'])},",
            f"    {1 if analysis_data['development']['language_info']['is_kotlin'] else 0},",
            f"    {1 if analysis_data['development']['language_info']['is_java'] else 0},",
            f"    {has_ads}, {len(analysis_data.get('sensitive_methods', []))}, 1,",
            f"    {len(analysis_data.get('network', {}).get('urls', {}).get('other_urls', []))},",
            f"    {len(analysis_data.get('network', {}).get('ip_addresses', []))},",
            f"    '{analysis_data['languages_info'].get('default_language', 'ar')}',",
            f"    '{', '.join(analysis_data['languages_info'].get('supported_locales', []))}',",
            f"    {1 if analysis_data['languages_info'].get('supports_arabic') else 0},",
            f"    {1 if analysis_data['languages_info'].get('supports_english') else 0},",
            f"    '{apk_final_path}', NOW()",
            f");\n",

            f"-- 5. INSERT INTO scan_versions",
            f"INSERT INTO scan_versions (",
            f"    id, application_id, version_code, version_name, size_mb, min_sdk, target_sdk, file_sha1, file_sha256, file_md5,",
            f"    apk_path, activities_count, services_count, receivers_count, providers_count, permissions_count,",
            f"    is_kotlin, is_java, has_ads_detected, sensitive_methods_count, has_intent_filters, urls_count, ip_addresses_count,",
            f"    default_language, supports_arabic, supports_english, created_at",
            f") VALUES (",
            f"    {scan_id}, {app_id}, {version_code_int}, '{version_name}', {analysis_data['size_mb']:.2f},",
            f"    {analysis_data['min_sdk']}, {analysis_data['target_sdk']}, '{sha1}', '{sha256}', '{md5}',",
            f"    '{apk_final_path}', {len(analysis_data['activities'])}, {len(analysis_data['services'])},",
            f"    {len(analysis_data['receivers'])}, {len(analysis_data['providers'])}, {len(analysis_data['permissions'])},",
            f"    {1 if analysis_data['development']['language_info']['is_kotlin'] else 0},",
            f"    {1 if analysis_data['development']['language_info']['is_java'] else 0},",
            f"    {has_ads}, {len(analysis_data.get('sensitive_methods', []))}, 1,",
            f"    {len(analysis_data.get('network', {}).get('urls', {}).get('other_urls', []))},",
            f"    {len(analysis_data.get('network', {}).get('ip_addresses', []))},",
            f"    '{analysis_data['languages_info'].get('default_language', 'ar')}',",
            f"    {1 if analysis_data['languages_info'].get('supports_arabic') else 0},",
            f"    {1 if analysis_data['languages_info'].get('supports_english') else 0},",
            f"    NOW()",
            f");\n",

            f"-- 6. INSERT INTO scan_permissions"
        ])

        for perm in analysis_data['permissions']:
            clean_perm = perm.replace("'", "''")
            lines.append(f"INSERT INTO scan_permissions (scan_id, permission_name) VALUES ({scan_id}, '{clean_perm}');")
        lines.append("")

        # 7. Scan Components
        lines.append(f"-- 7. INSERT INTO scan_components")
        for comp_type, key in [("activity", "activities"), ("service", "services"), ("receiver", "receivers"), ("provider", "providers")]:
            for comp_name in analysis_data.get(key, []):
                clean_name = comp_name.replace("'", "''")
                lines.append(f"INSERT INTO scan_components (scan_id, component_type, component_name) VALUES ({scan_id}, '{comp_type}', '{clean_name}');")
        lines.append("")

        # 8. Libraries
        lines.append(f"-- 8. INSERT INTO scan_app_libraries")
        for lib, found in analysis_data['development']['dependency_injection'].items():
            if found:
                lines.append(f"INSERT INTO scan_app_libraries (scan_id, library_name, library_type) VALUES ({scan_id}, '{lib}', 'di');")
        for lib, found in analysis_data['development']['state_management'].items():
            if found:
                lines.append(f"INSERT INTO scan_app_libraries (scan_id, library_name, library_type) VALUES ({scan_id}, '{lib}', 'state');")
        for lib in analysis_data['development']['ads_libraries'].get('ads_libraries', []):
            lines.append(f"INSERT INTO scan_app_libraries (scan_id, library_name, library_type) VALUES ({scan_id}, '{lib}', 'ads');")
        lines.append("")

        # 9. URLs
        lines.append(f"-- 9. INSERT INTO scan_app_urls")
        for u in analysis_data['network']['urls'].get('other_urls', [])[:100]:
            clean_url = str(u).replace("'", "''")
            lines.append(f"INSERT INTO scan_app_urls (scan_id, url) VALUES ({scan_id}, '{clean_url}');")
        lines.append("")

        # 10. Certificates
        lines.append(f"-- 10. INSERT INTO scan_app_certificates")
        for cert in analysis_data['certificates']:
            c_issuer = cert.get('issuer', 'Unknown').replace("'", "''")
            c_subject = cert.get('subject', 'Unknown').replace("'", "''")
            c_sha1 = cert.get('sha1', '')
            c_sha256 = cert.get('sha256', '')
            lines.append(f"INSERT INTO scan_app_certificates (scan_id, issuer, subject, sha1, sha256, valid_from, valid_until) VALUES ({scan_id}, '{c_issuer}', '{c_subject}', '{c_sha1}', '{c_sha256}', 'NOW()', 'NOW()');")
        lines.append("")

        return "\n".join(lines)

    def export_sql(self, inspection: Dict[str, Any], apk_path: str, output_file: str) -> str:
        """تصدير ملف SQL مدمج لمتجر AwmStore"""
        data = self.normalize_analysis_data(inspection, apk_path)
        sql_content = self.generate_all_sql(data)

        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(sql_content)

        return output_file

    def export_package(self, inspection: Dict[str, Any], apk_path: str, output_target: str) -> str:
        """
        تصدير الحزمة الكاملة لمتجر AwmStore (مجلد أو أرشيف ZIP).
        الهيكل:
        - images/ (ic_launcher.webp, ic_launcher_{dpi}.webp)
        - release/ ({package_name}.apk)
        - database/ (awm_store_complete.sql, insert_applications_tbl.sql, ...)
        - scan/ (analysis_summary.json)
        """
        data = self.normalize_analysis_data(inspection, apk_path)
        pkg_name = data['package_name']
        is_zip = output_target.lower().endswith(".zip")

        # إنشاء مجلد عمل مؤقت
        temp_dir = tempfile.mkdtemp(prefix="awm_store_pkg_")
        try:
            base_dir = os.path.join(temp_dir, pkg_name)
            dirs = {
                'images': os.path.join(base_dir, "images"),
                'release': os.path.join(base_dir, "release"),
                'database': os.path.join(base_dir, "database"),
                'scan': os.path.join(base_dir, "scan")
            }
            for d in dirs.values():
                os.makedirs(d, exist_ok=True)

            # 1. استخراج الأيقونات بكافة الكثافات بصيغة WebP
            if apk_path and os.path.exists(apk_path):
                try:
                    from androguard.core.apk import APK
                    from info_extractor import InfoExtractor
                    from PIL import Image
                    ext = InfoExtractor(APK(apk_path))
                    icons_map = ext.extract_all_icons(dirs['images'])
                    # نسخ الأيقونة الرئيسية باسم ic_launcher.webp
                    main_icon = icons_map.get("main")
                    if main_icon and os.path.exists(main_icon):
                        target_main_webp = os.path.join(dirs['images'], "ic_launcher.webp")
                        if main_icon.endswith(".webp"):
                            shutil.copy2(main_icon, target_main_webp)
                        else:
                            try:
                                with Image.open(main_icon) as im:
                                    im.save(target_main_webp, format="WEBP", quality=95)
                            except Exception:
                                shutil.copy2(main_icon, target_main_webp)
                except Exception as e:
                    pass

            # 2. نسخ ملف APK الأصلي
            apk_copy_name = f"{pkg_name}.apk"
            apk_dest = os.path.join(dirs['release'], apk_copy_name)
            if apk_path and os.path.exists(apk_path):
                shutil.copy2(apk_path, apk_dest)

            # 3. توليد ملفات SQL
            all_sql = self.generate_all_sql(data, f"output/applications/{pkg_name}/release/{apk_copy_name}")
            sql_file_path = os.path.join(dirs['database'], f"insert_awm_store_{pkg_name}.sql")
            with open(sql_file_path, "w", encoding="utf-8") as f:
                f.write(all_sql)

            # 4. توليد ملف analysis_summary.json
            summary_data = {
                "package_name": pkg_name,
                "app_name": data['app_name'],
                "version": {"code": data['version_code'], "name": data['version_name']},
                "sdk_versions": {"min": data['min_sdk'], "target": data['target_sdk']},
                "hashes": data['hashes'],
                "permissions": data['permissions'],
                "components": {
                    "activities": data['activities'],
                    "services": data['services'],
                    "receivers": data['receivers'],
                    "providers": data['providers'],
                },
                "certificates": data['certificates'],
                "languages_info": data['languages_info'],
                "development": data['development'],
                "exported_by": "Sabr Android Security Studio - AwmStore Engine",
                "timestamp": datetime.now().isoformat()
            }
            summary_path = os.path.join(dirs['scan'], "analysis_summary.json")
            with open(summary_path, "w", encoding="utf-8") as f:
                json.dump(summary_data, f, indent=4, ensure_ascii=False)

            # 5. التصدير للوجهة المحددة (مجلد أو ZIP)
            if is_zip:
                os.makedirs(os.path.dirname(os.path.abspath(output_target)), exist_ok=True)
                with zipfile.ZipFile(output_target, "w", zipfile.ZIP_DEFLATED) as z:
                    for root, _, files in os.walk(base_dir):
                        for file in files:
                            full_path = os.path.join(root, file)
                            rel_path = os.path.relpath(full_path, base_dir)
                            z.write(full_path, os.path.join(pkg_name, rel_path))
                return output_target
            else:
                # إذا كانت الوجهة مجلداً
                final_dest_dir = os.path.join(output_target, pkg_name) if not output_target.endswith(pkg_name) else output_target
                os.makedirs(final_dest_dir, exist_ok=True)
                # نسخ المحتويات
                for item in os.listdir(base_dir):
                    s = os.path.join(base_dir, item)
                    d = os.path.join(final_dest_dir, item)
                    if os.path.isdir(s):
                        if os.path.exists(d):
                            shutil.rmtree(d)
                        shutil.copytree(s, d)
                    else:
                        shutil.copy2(s, d)
                return final_dest_dir

        finally:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass
