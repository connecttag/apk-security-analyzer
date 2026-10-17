# sql_generator.py
# -*- coding: utf-8 -*-
"""
sql_generator.py - مولد استعلامات SQL لمستودعات ومتاجر التطبيقات (Store & Catalog SQL Exporter)
يقوم بإنشاء سكربت SQL مهيكل يحتوي على تعريف الجداول وعمليات الإدراج لكافة بيانات التطبيق المفحوص.
"""

from datetime import datetime
from typing import Dict, Any, List

class StoreSqlGenerator:
    def __init__(self, db_name: str = "sabr_app_catalog"):
        self.db_name = db_name

    def _escape_sql(self, val: Any) -> str:
        if val is None:
            return "NULL"
        s = str(val).replace("'", "''")
        return f"'{s}'"

    def generate_catalog_sql(self, inspection: Dict[str, Any], output_path: str = None) -> str:
        """
        توليد سكربت SQL كامل لإدراج بيانات التطبيق والفحص.
        """
        basic = inspection.get("basic_info", {})
        hashes = inspection.get("hashes", {})
        security = inspection.get("security", {})
        dev = inspection.get("development", {})
        perms = inspection.get("permissions", {})
        comps = inspection.get("components", {})
        resources = inspection.get("resources_summary", {})
        localization = resources.get("localization", {})
        risk = security.get("risk_assessment", {})

        pkg_name = basic.get("package_name", "unknown")
        app_name = basic.get("app_name", pkg_name)
        ver_code = basic.get("version", {}).get("code", 0)
        ver_name = basic.get("version", {}).get("name", "unknown")
        min_sdk = basic.get("sdk_versions", {}).get("min", 0)
        target_sdk = basic.get("sdk_versions", {}).get("target", 0)
        size_mb = basic.get("size_mb", 0.0)
        category = basic.get("inferred_category", "Tools")
        natural_summary = basic.get("natural_summary", "")

        sha256 = hashes.get("sha256", "")
        sha1 = hashes.get("sha1", "")
        md5 = hashes.get("md5", "")

        risk_level = risk.get("risk_level", "LOW")
        risk_score = risk.get("risk_score", 0)

        supports_arabic = 1 if localization.get("supports_arabic", False) else 0
        supports_english = 1 if localization.get("supports_english", True) else 0
        default_lang = localization.get("default_language", "en")

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines = [
            f"-- ===========================================================================",
            f"-- سَبْر (Sabr) - Advanced Android APK Security & Inspection Studio",
            f"-- سكربت تصدير قاعدة بيانات مستودع التطبيقات (App Catalog SQL Script)",
            f"-- Generated on: {now_str}",
            f"-- Application: {pkg_name} ({app_name}) v{ver_name} ({ver_code})",
            f"-- ===========================================================================\n",
            f"CREATE TABLE IF NOT EXISTS `sabr_applications` (",
            f"    `id` INTEGER PRIMARY KEY AUTO_INCREMENT,",
            f"    `package_name` VARCHAR(255) NOT NULL UNIQUE,",
            f"    `app_name` VARCHAR(255),",
            f"    `latest_version_code` BIGINT,",
            f"    `latest_version_name` VARCHAR(100),",
            f"    `min_sdk` INT,",
            f"    `target_sdk` INT,",
            f"    `size_mb` DECIMAL(10, 2),",
            f"    `category` VARCHAR(100),",
            f"    `supports_arabic` TINYINT(1) DEFAULT 0,",
            f"    `supports_english` TINYINT(1) DEFAULT 1,",
            f"    `default_language` VARCHAR(20),",
            f"    `risk_level` VARCHAR(50),",
            f"    `risk_score` INT,",
            f"    `sha256` VARCHAR(64),",
            f"    `sha1` VARCHAR(40),",
            f"    `md5` VARCHAR(32),",
            f"    `executive_summary` TEXT,",
            f"    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,",
            f"    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP",
            f");\n",
            f"CREATE TABLE IF NOT EXISTS `sabr_permissions` (",
            f"    `id` INTEGER PRIMARY KEY AUTO_INCREMENT,",
            f"    `package_name` VARCHAR(255) NOT NULL,",
            f"    `permission` VARCHAR(255) NOT NULL,",
            f"    `is_dangerous` TINYINT(1) DEFAULT 0",
            f");\n",
            f"CREATE TABLE IF NOT EXISTS `sabr_components` (",
            f"    `id` INTEGER PRIMARY KEY AUTO_INCREMENT,",
            f"    `package_name` VARCHAR(255) NOT NULL,",
            f"    `component_type` VARCHAR(50) NOT NULL,",
            f"    `component_name` VARCHAR(255) NOT NULL,",
            f"    `is_exported` TINYINT(1) DEFAULT 0",
            f");\n",
            f"CREATE TABLE IF NOT EXISTS `sabr_trackers` (",
            f"    `id` INTEGER PRIMARY KEY AUTO_INCREMENT,",
            f"    `package_name` VARCHAR(255) NOT NULL,",
            f"    `tracker_name` VARCHAR(150) NOT NULL,",
            f"    `categories` VARCHAR(255)",
            f");\n",
            f"-- 1. إدراج أو تحديث سجل التطبيق الأساسي",
            f"INSERT INTO `sabr_applications` (",
            f"    `package_name`, `app_name`, `latest_version_code`, `latest_version_name`,",
            f"    `min_sdk`, `target_sdk`, `size_mb`, `category`, `supports_arabic`, `supports_english`,",
            f"    `default_language`, `risk_level`, `risk_score`, `sha256`, `sha1`, `md5`, `executive_summary`",
            f") VALUES (",
            f"    {self._escape_sql(pkg_name)}, {self._escape_sql(app_name)}, {ver_code}, {self._escape_sql(ver_name)},",
            f"    {min_sdk}, {target_sdk}, {size_mb}, {self._escape_sql(category)}, {supports_arabic}, {supports_english},",
            f"    {self._escape_sql(default_lang)}, {self._escape_sql(risk_level)}, {risk_score},",
            f"    {self._escape_sql(sha256)}, {self._escape_sql(sha1)}, {self._escape_sql(md5)}, {self._escape_sql(natural_summary)}",
            f") ON DUPLICATE KEY UPDATE",
            f"    `app_name` = VALUES(`app_name`), `latest_version_code` = VALUES(`latest_version_code`),",
            f"    `latest_version_name` = VALUES(`latest_version_name`), `risk_level` = VALUES(`risk_level`),",
            f"    `risk_score` = VALUES(`risk_score`), `updated_at` = NOW();\n"
        ]

        # 2. الصلاحيات
        all_perms = perms.get("all_permissions", []) or []
        dang_perms = set(perms.get("dangerous_permissions", []) or [])
        if all_perms:
            lines.append(f"-- 2. إدراج الصلاحيات المطلوبة")
            lines.append(f"DELETE FROM `sabr_permissions` WHERE `package_name` = {self._escape_sql(pkg_name)};")
            for p in all_perms:
                is_dang = 1 if p in dang_perms else 0
                lines.append(f"INSERT INTO `sabr_permissions` (`package_name`, `permission`, `is_dangerous`) VALUES ({self._escape_sql(pkg_name)}, {self._escape_sql(p)}, {is_dang});")
            lines.append("")

        # 3. المكونات المكشوفة والأساسية
        lines.append(f"-- 3. إدراج المكونات البرمجية")
        lines.append(f"DELETE FROM `sabr_components` WHERE `package_name` = {self._escape_sql(pkg_name)};")
        for act in comps.get("activities", []) or []:
            lines.append(f"INSERT INTO `sabr_components` (`package_name`, `component_type`, `component_name`) VALUES ({self._escape_sql(pkg_name)}, 'activity', {self._escape_sql(act)});")
        for srv in comps.get("services", []) or []:
            lines.append(f"INSERT INTO `sabr_components` (`package_name`, `component_type`, `component_name`) VALUES ({self._escape_sql(pkg_name)}, 'service', {self._escape_sql(srv)});")
        for rec in comps.get("receivers", []) or []:
            lines.append(f"INSERT INTO `sabr_components` (`package_name`, `component_type`, `component_name`) VALUES ({self._escape_sql(pkg_name)}, 'receiver', {self._escape_sql(rec)});")
        for prv in comps.get("providers", []) or []:
            lines.append(f"INSERT INTO `sabr_components` (`package_name`, `component_type`, `component_name`) VALUES ({self._escape_sql(pkg_name)}, 'provider', {self._escape_sql(prv)});")
        lines.append("")

        # 4. متتبعات الخصوصية
        exodus = dev.get("exodus_trackers", {})
        trackers = exodus.get("trackers", [])
        if trackers:
            lines.append(f"-- 4. إدراج شبكات التتبع والخصوصية")
            lines.append(f"DELETE FROM `sabr_trackers` WHERE `package_name` = {self._escape_sql(pkg_name)};")
            for t in trackers:
                t_name = t.get("name", "Unknown")
                t_cats = ", ".join(t.get("categories", []))
                lines.append(f"INSERT INTO `sabr_trackers` (`package_name`, `tracker_name`, `categories`) VALUES ({self._escape_sql(pkg_name)}, {self._escape_sql(t_name)}, {self._escape_sql(t_cats)});")
            lines.append("")

        sql_output = "\n".join(lines)

        if output_path:
            import os
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(sql_output)

        return sql_output
