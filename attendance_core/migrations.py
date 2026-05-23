from datetime import datetime


SCHEMA_MIGRATIONS = (
    (
        "20260523_001_break_type",
        "Add breaks.break_type so paid breaks and unpaid POWER NAP BREAK records are tracked separately.",
    ),
)


def default_now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def cursor_column_exists(cursor, table_name, column_name, postgres=False):
    if postgres:
        cursor.execute("""
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = %s
                  AND column_name = %s
            )
        """, (table_name, column_name))
        row = cursor.fetchone()
        return bool(row[0]) if row else False

    cursor.execute(f"PRAGMA table_info({table_name})")
    return any(row[1] == column_name for row in cursor.fetchall())


def ensure_schema_migrations_table(cursor, postgres=False):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            migration_id TEXT PRIMARY KEY,
            description TEXT,
            applied_at TEXT NOT NULL
        )
    """)


def get_applied_schema_migration_ids(cursor):
    cursor.execute("SELECT migration_id FROM schema_migrations")
    return {row[0] for row in cursor.fetchall()}


def record_schema_migration(cursor, migration_id, description, postgres=False, now_func=None):
    applied_at = (now_func or default_now_str)()
    if postgres:
        cursor.execute("""
            INSERT INTO schema_migrations (migration_id, description, applied_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (migration_id) DO NOTHING
        """, (migration_id, description, applied_at))
        return

    cursor.execute("""
        INSERT OR IGNORE INTO schema_migrations (migration_id, description, applied_at)
        VALUES (?, ?, ?)
    """, (migration_id, description, applied_at))


def migrate_break_type(cursor, postgres=False):
    if postgres:
        cursor.execute("ALTER TABLE breaks ADD COLUMN IF NOT EXISTS break_type TEXT NOT NULL DEFAULT 'regular'")
        return

    if not cursor_column_exists(cursor, "breaks", "break_type"):
        cursor.execute("ALTER TABLE breaks ADD COLUMN break_type TEXT NOT NULL DEFAULT 'regular'")


SCHEMA_MIGRATION_HANDLERS = {
    "20260523_001_break_type": migrate_break_type,
}


def apply_schema_migrations(cursor, postgres=False, now_func=None):
    ensure_schema_migrations_table(cursor, postgres=postgres)
    applied_ids = get_applied_schema_migration_ids(cursor)
    for migration_id, description in SCHEMA_MIGRATIONS:
        if migration_id in applied_ids:
            continue
        SCHEMA_MIGRATION_HANDLERS[migration_id](cursor, postgres=postgres)
        record_schema_migration(cursor, migration_id, description, postgres=postgres, now_func=now_func)