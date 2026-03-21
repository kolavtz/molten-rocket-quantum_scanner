import os

db_path = "src/database.py"

with open(db_path, "r", encoding="utf-8") as f:
    text = f.read()

# List of exact targets and replacements to wrap in try..except
replacements = [
    # 1. Users
    ("""        cur.execute(\"\"\"
            CREATE TABLE IF NOT EXISTS users (
                id                          VARCHAR(36) PRIMARY KEY,
                employee_id                 VARCHAR(64) UNIQUE,
                username                    VARCHAR(150) UNIQUE NOT NULL,
                email                       VARCHAR(255) UNIQUE,
                password_hash               VARCHAR(255) NOT NULL,
                role                        VARCHAR(50) NOT NULL,
                created_by                  VARCHAR(36),
                is_active                   BOOLEAN DEFAULT TRUE,
                password_setup_token_hash   CHAR(64) UNIQUE,
                password_setup_token_expiry DATETIME,
                must_change_password        BOOLEAN DEFAULT TRUE,
                failed_login_attempts       INT DEFAULT 0,
                lockout_until               DATETIME,
                last_login_at               DATETIME,
                password_changed_at         DATETIME,
                created_at                  DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at                  DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id)
                    ON DELETE SET NULL
            ) ENGINE=InnoDB
        \"\"\")""",
     """        try:
            cur.execute(\"\"\"
                CREATE TABLE IF NOT EXISTS users (
                    id                          VARCHAR(36) PRIMARY KEY,
                    employee_id                 VARCHAR(64) UNIQUE,
                    username                    VARCHAR(150) UNIQUE NOT NULL,
                    email                       VARCHAR(255) UNIQUE,
                    password_hash               VARCHAR(255) NOT NULL,
                    role                        VARCHAR(50) NOT NULL,
                    created_by                  VARCHAR(36),
                    is_active                   BOOLEAN DEFAULT TRUE,
                    password_setup_token_hash   CHAR(64) UNIQUE,
                    password_setup_token_expiry DATETIME,
                    must_change_password        BOOLEAN DEFAULT TRUE,
                    failed_login_attempts       INT DEFAULT 0,
                    lockout_until               DATETIME,
                    last_login_at               DATETIME,
                    password_changed_at         DATETIME,
                    created_at                  DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at                  DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (created_by) REFERENCES users(id)
                        ON DELETE SET NULL
                ) ENGINE=InnoDB
            \"\"\")
        except Exception as e:
            logger.warning(\"Table 'users' setup warning: %s\", e)"""),

    # 2. Scans
    ("""        cur.execute(\"\"\"
            CREATE TABLE IF NOT EXISTS scans (
                scan_id          VARCHAR(36)  PRIMARY KEY,
                target           VARCHAR(512) NOT NULL,
                asset_class      VARCHAR(64),
                status           VARCHAR(32),
                compliance_score INT          DEFAULT 0,
                total_assets     INT          DEFAULT 0,
                quantum_safe     INT          DEFAULT 0,
                quantum_vuln     INT          DEFAULT 0,
                scanned_at       DATETIME,
                report_json      LONGTEXT     NOT NULL,
                is_encrypted     BOOLEAN      DEFAULT FALSE
            ) ENGINE=InnoDB
        \"\"\")""",
     """        try:
            cur.execute(\"\"\"
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id          VARCHAR(36)  PRIMARY KEY,
                    target           VARCHAR(512) NOT NULL,
                    asset_class      VARCHAR(64),
                    status           VARCHAR(32),
                    compliance_score INT          DEFAULT 0,
                    total_assets     INT          DEFAULT 0,
                    quantum_safe     INT          DEFAULT 0,
                    quantum_vuln     INT          DEFAULT 0,
                    scanned_at       DATETIME,
                    report_json      LONGTEXT     NOT NULL,
                    is_encrypted     BOOLEAN      DEFAULT FALSE
                ) ENGINE=InnoDB
            \"\"\")
        except Exception as e:
            logger.warning(\"Table 'scans' setup warning: %s\", e)"""),

    # 3. DNS
    ("""        cur.execute(\"\"\"
            CREATE TABLE IF NOT EXISTS asset_dns_records (
                id            BIGINT AUTO_INCREMENT PRIMARY KEY,
                scan_id       VARCHAR(36) NOT NULL,
                hostname      VARCHAR(255) NOT NULL,
                record_type   VARCHAR(16) NOT NULL,
                record_value  VARCHAR(1024) NOT NULL,
                ttl           INT DEFAULT 300,
                resolved_at   DATETIME,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                    ON DELETE CASCADE,
                INDEX idx_dns_scan_id (scan_id),
                INDEX idx_dns_hostname (hostname)
            ) ENGINE=InnoDB
        \"\"\")""",
     """        try:
            cur.execute(\"\"\"
                CREATE TABLE IF NOT EXISTS asset_dns_records (
                    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
                    scan_id       VARCHAR(36) NOT NULL,
                    hostname      VARCHAR(255) NOT NULL,
                    record_type   VARCHAR(16) NOT NULL,
                    record_value  VARCHAR(1024) NOT NULL,
                    ttl           INT DEFAULT 300,
                    resolved_at   DATETIME,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                        ON DELETE CASCADE,
                    INDEX idx_dns_scan_id (scan_id),
                    INDEX idx_dns_hostname (hostname)
                ) ENGINE=InnoDB
            \"\"\")
        except Exception as e:
            logger.warning(\"Table 'asset_dns_records' setup warning: %s\", e)"""),

    # 4. CBOM
    ("""        cur.execute(\"\"\"
            CREATE TABLE IF NOT EXISTS cbom_reports (
                scan_id      VARCHAR(36) PRIMARY KEY,
                cbom_json    LONGTEXT NOT NULL,
                is_encrypted BOOLEAN  DEFAULT FALSE,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                    ON DELETE CASCADE
            ) ENGINE=InnoDB
        \"\"\")""",
     """        try:
            cur.execute(\"\"\"
                CREATE TABLE IF NOT EXISTS cbom_reports (
                    scan_id      VARCHAR(36) PRIMARY KEY,
                    cbom_json    LONGTEXT NOT NULL,
                    is_encrypted BOOLEAN  DEFAULT FALSE,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                        ON DELETE CASCADE
                ) ENGINE=InnoDB
            \"\"\")
        except Exception as e:
            logger.warning(\"Table 'cbom_reports' setup warning: %s\", e)"""),

    # 5. audit_log_chain
    ("""        cur.execute(\"\"\"
            CREATE TABLE IF NOT EXISTS audit_log_chain (
                id             TINYINT PRIMARY KEY,
                last_entry_id  BIGINT,
                last_hash      CHAR(64),
                updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB
        \"\"\")""",
     """        try:
            cur.execute(\"\"\"
                CREATE TABLE IF NOT EXISTS audit_log_chain (
                    id             TINYINT PRIMARY KEY,
                    last_entry_id  BIGINT,
                    last_hash      CHAR(64),
                    updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP
                        ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB
            \"\"\")
        except Exception as e:
            logger.warning(\"Table 'audit_log_chain' setup warning: %s\", e)"""),

    # 6. audit_logs (Uses f\"\"\")
    ("""        cur.execute(f\"\"\"
            CREATE TABLE IF NOT EXISTS audit_logs (
                id               BIGINT AUTO_INCREMENT PRIMARY KEY,
                actor_user_id    {user_id_column_type},
                actor_username   VARCHAR(150),
                event_category   VARCHAR(64) NOT NULL,
                event_type       VARCHAR(128) NOT NULL,
                target_user_id   {user_id_column_type},
                target_scan_id   VARCHAR(36),
                ip_address       VARCHAR(64),
                user_agent       VARCHAR(512),
                request_method   VARCHAR(16),
                request_path     VARCHAR(255),
                status           VARCHAR(32) NOT NULL,
                details_json     LONGTEXT,
                previous_hash    CHAR(64) NOT NULL,
                entry_hash       CHAR(64) NOT NULL UNIQUE,
                created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (actor_user_id) REFERENCES users(id)
                    ON DELETE SET NULL,
                FOREIGN KEY (target_user_id) REFERENCES users(id)
                    ON DELETE SET NULL,
                FOREIGN KEY (target_scan_id) REFERENCES scans(scan_id)
                    ON DELETE SET NULL,
                INDEX idx_audit_created_at (created_at),
                INDEX idx_audit_category (event_category),
                INDEX idx_audit_actor (actor_user_id),
                INDEX idx_audit_target_user (target_user_id),
                INDEX idx_audit_target_scan (target_scan_id)
            ) ENGINE=InnoDB
        \"\"\")""",
     """        try:
            cur.execute(f\"\"\"
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
                    actor_user_id    {user_id_column_type},
                    actor_username   VARCHAR(150),
                    event_category   VARCHAR(64) NOT NULL,
                    event_type       VARCHAR(128) NOT NULL,
                    target_user_id   {user_id_column_type},
                    target_scan_id   VARCHAR(36),
                    ip_address       VARCHAR(64),
                    user_agent       VARCHAR(512),
                    request_method   VARCHAR(16),
                    request_path     VARCHAR(255),
                    status           VARCHAR(32) NOT NULL,
                    details_json     LONGTEXT,
                    previous_hash    CHAR(64) NOT NULL,
                    entry_hash       CHAR(64) NOT NULL UNIQUE,
                    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (actor_user_id) REFERENCES users(id)
                        ON DELETE SET NULL,
                    FOREIGN KEY (target_user_id) REFERENCES users(id)
                        ON DELETE SET NULL,
                    FOREIGN KEY (target_scan_id) REFERENCES scans(scan_id)
                        ON DELETE SET NULL,
                    INDEX idx_audit_created_at (created_at),
                    INDEX idx_audit_category (event_category),
                    INDEX idx_audit_actor (actor_user_id),
                    INDEX idx_audit_target_user (target_user_id),
                    INDEX idx_audit_target_scan (target_scan_id)
                ) ENGINE=InnoDB
            \"\"\")
        except Exception as e:
            logger.warning(\"Table 'audit_logs' setup warning: %s\", e)"""),

    # 7. schedules
    ("""        cur.execute(\"\"\"
            CREATE TABLE IF NOT EXISTS report_schedules (
                schedule_id     VARCHAR(36) PRIMARY KEY,
                created_by_id   VARCHAR(36),
                created_by_name VARCHAR(150),
                created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                enabled         BOOLEAN DEFAULT TRUE,
                report_type     VARCHAR(120) NOT NULL,
                frequency       VARCHAR(32) NOT NULL,
                assets          VARCHAR(256),
                sections_json   LONGTEXT,
                schedule_date   VARCHAR(20),
                schedule_time   VARCHAR(10),
                timezone_name   VARCHAR(64),
                email_list      VARCHAR(512),
                save_path       VARCHAR(512),
                download_link   BOOLEAN DEFAULT FALSE,
                status          VARCHAR(32) DEFAULT 'scheduled',
                FOREIGN KEY (created_by_id) REFERENCES users(id)
                    ON DELETE SET NULL,
                INDEX idx_report_schedules_created_at (created_at),
                INDEX idx_report_schedules_status (status)
            ) ENGINE=InnoDB
        \"\"\")""",
     """        try:
            cur.execute(\"\"\"
                CREATE TABLE IF NOT EXISTS report_schedules (
                    schedule_id     VARCHAR(36) PRIMARY KEY,
                    created_by_id   VARCHAR(36),
                    created_by_name VARCHAR(150),
                    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    enabled         BOOLEAN DEFAULT TRUE,
                    report_type     VARCHAR(120) NOT NULL,
                    frequency       VARCHAR(32) NOT NULL,
                    assets          VARCHAR(256),
                    sections_json   LONGTEXT,
                    schedule_date   VARCHAR(20),
                    schedule_time   VARCHAR(10),
                    timezone_name   VARCHAR(64),
                    email_list      VARCHAR(512),
                    save_path       VARCHAR(512),
                    download_link   BOOLEAN DEFAULT FALSE,
                    status          VARCHAR(32) DEFAULT 'scheduled',
                    FOREIGN KEY (created_by_id) REFERENCES users(id)
                        ON DELETE SET NULL,
                    INDEX idx_report_schedules_created_at (created_at),
                    INDEX idx_report_schedules_status (status)
                ) ENGINE=InnoDB
            \"\"\")
        except Exception as e:
            logger.warning(\"Table 'report_schedules' setup warning: %s\", e)"""),

    # 8. Assets
    ("""        cur.execute(\"\"\"
            CREATE TABLE IF NOT EXISTS assets (
                id          BIGINT AUTO_INCREMENT PRIMARY KEY,
                target      VARCHAR(512) UNIQUE NOT NULL,
                type        VARCHAR(64),
                owner       VARCHAR(150),
                risk_level  VARCHAR(32),
                notes       TEXT,
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB
        \"\"\")""",
     """        try:
            cur.execute(\"\"\"
                CREATE TABLE IF NOT EXISTS assets (
                    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
                    target      VARCHAR(512) UNIQUE NOT NULL,
                    type        VARCHAR(64),
                    owner       VARCHAR(150),
                    risk_level  VARCHAR(32),
                    notes       TEXT,
                    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB
            \"\"\")
        except Exception as e:
            logger.warning(\"Table 'assets' setup warning: %s\", e)""")
]

count = 0
for target, repl in replacements:
    if target in text:
        text = text.replace(target, repl)
        count += 1
    else:
        print(f"FAILED TO FIND TARGET: {target[:100]}...")

if count > 0:
    with open(db_path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"Applied {count} replacements.")
else:
    print("No replacements applied.")
