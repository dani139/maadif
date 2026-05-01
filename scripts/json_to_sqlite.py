#!/usr/bin/env python3
"""
Convert Ghidra JSON export to SQLite database.

Usage:
    python3 json_to_sqlite.py <input.json> <output.db>     # Single file
    python3 json_to_sqlite.py <json_dir> [output.db]       # Directory mode
"""

import json
import sqlite3
import sys
from pathlib import Path
from datetime import datetime


def create_tables(conn):
    """Create database schema matching ExportToJson.java output"""
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS library_info (
            id INTEGER PRIMARY KEY,
            name TEXT,
            file_size INTEGER,
            architecture TEXT,
            compiler TEXT,
            image_base TEXT,
            language TEXT,
            min_address TEXT,
            max_address TEXT,
            analysis_date TEXT,
            function_count INTEGER,
            string_count INTEGER,
            import_count INTEGER,
            export_count INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS functions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            address TEXT UNIQUE,
            signature TEXT,
            calling_convention TEXT,
            parameter_count INTEGER,
            body_size INTEGER,
            is_thunk INTEGER,
            is_external INTEGER,
            is_export INTEGER,
            instruction_count INTEGER,
            basic_block_count INTEGER,
            edge_count INTEGER,
            code_hash TEXT,
            decompiled TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS strings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT,
            value TEXT,
            length INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS imports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            address TEXT,
            library TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS exports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            address TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS memory_sections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            start_addr TEXT,
            end_addr TEXT,
            size INTEGER,
            is_read INTEGER,
            is_write INTEGER,
            is_execute INTEGER,
            is_initialized INTEGER
        )
    """)

    # Create indexes for faster queries
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_functions_address ON functions(address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_functions_code_hash ON functions(code_hash)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_strings_value ON strings(value)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_imports_name ON imports(name)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_imports_library ON imports(library)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_exports_name ON exports(name)")

    conn.commit()


def import_library_info(conn, data, counts):
    """Import library metadata"""
    if "library" not in data:
        return

    lib = data["library"]
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO library_info (
            name, architecture, compiler, image_base, language,
            min_address, max_address, analysis_date,
            function_count, string_count, import_count, export_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        lib.get("name"),
        lib.get("architecture"),
        lib.get("compiler"),
        lib.get("image_base"),
        lib.get("language"),
        lib.get("min_address"),
        lib.get("max_address"),
        datetime.now().isoformat(),
        counts.get("functions", 0),
        counts.get("strings", 0),
        counts.get("imports", 0),
        counts.get("exports", 0)
    ))

    conn.commit()


def import_functions(conn, data):
    """Import functions with decompiled code"""
    if "functions" not in data:
        return 0

    cursor = conn.cursor()
    count = 0
    decompiled_count = 0

    for func in data["functions"]:
        try:
            decompiled = func.get("decompiled")
            cursor.execute("""
                INSERT OR REPLACE INTO functions (
                    name, address, signature, calling_convention, parameter_count,
                    body_size, is_thunk, is_external, is_export,
                    instruction_count, basic_block_count, edge_count,
                    code_hash, decompiled
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                func.get("name"),
                func.get("address"),
                func.get("signature"),
                func.get("calling_convention"),
                func.get("parameter_count", 0),
                func.get("body_size", 0),
                1 if func.get("is_thunk") else 0,
                1 if func.get("is_external") else 0,
                1 if func.get("is_export") else 0,
                func.get("instruction_count", 0),
                func.get("basic_block_count", 0),
                func.get("edge_count", 0),
                func.get("code_hash"),
                decompiled
            ))
            count += 1
            if decompiled:
                decompiled_count += 1
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    return count, decompiled_count


def import_strings(conn, data):
    """Import strings"""
    if "strings" not in data:
        return 0

    cursor = conn.cursor()
    count = 0

    for s in data["strings"]:
        cursor.execute("""
            INSERT INTO strings (address, value, length)
            VALUES (?, ?, ?)
        """, (
            s.get("address"),
            s.get("value"),
            s.get("length", 0)
        ))
        count += 1

    conn.commit()
    return count


def import_imports(conn, data):
    """Import imported symbols"""
    if "imports" not in data:
        return 0

    cursor = conn.cursor()
    count = 0

    for imp in data["imports"]:
        cursor.execute("""
            INSERT INTO imports (name, address, library)
            VALUES (?, ?, ?)
        """, (
            imp.get("name"),
            imp.get("address"),
            imp.get("library")
        ))
        count += 1

    conn.commit()
    return count


def import_exports(conn, data):
    """Import exported symbols"""
    if "exports" not in data:
        return 0

    cursor = conn.cursor()
    count = 0

    for exp in data["exports"]:
        cursor.execute("""
            INSERT INTO exports (name, address)
            VALUES (?, ?)
        """, (
            exp.get("name"),
            exp.get("address")
        ))
        count += 1

    conn.commit()
    return count


def import_memory_sections(conn, data):
    """Import memory sections"""
    if "memory_sections" not in data:
        return

    cursor = conn.cursor()

    for sec in data["memory_sections"]:
        cursor.execute("""
            INSERT INTO memory_sections (
                name, start_addr, end_addr, size,
                is_read, is_write, is_execute, is_initialized
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            sec.get("name"),
            sec.get("start"),
            sec.get("end"),
            sec.get("size", 0),
            1 if sec.get("is_read") else 0,
            1 if sec.get("is_write") else 0,
            1 if sec.get("is_execute") else 0,
            1 if sec.get("is_initialized") else 0
        ))

    conn.commit()


def convert_single(json_path, db_path):
    """Convert single JSON file to SQLite"""
    print(f"[Convert] Reading {json_path}")

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Remove existing db
    db_file = Path(db_path)
    if db_file.exists():
        db_file.unlink()

    print(f"[Convert] Creating {db_path}")

    conn = sqlite3.connect(db_path)

    try:
        create_tables(conn)

        func_count, decompiled_count = import_functions(conn, data)
        print(f"[Convert] Imported {func_count} functions ({decompiled_count} decompiled)")

        string_count = import_strings(conn, data)
        print(f"[Convert] Imported {string_count} strings")

        import_count = import_imports(conn, data)
        print(f"[Convert] Imported {import_count} imports")

        export_count = import_exports(conn, data)
        print(f"[Convert] Imported {export_count} exports")

        import_memory_sections(conn, data)

        counts = {
            "functions": func_count,
            "strings": string_count,
            "imports": import_count,
            "exports": export_count
        }
        import_library_info(conn, data, counts)

        print(f"[Convert] Complete: {db_path} ({db_file.stat().st_size} bytes)")

    finally:
        conn.close()


def convert_directory(json_dir, db_path):
    """Convert all JSON files in directory to single SQLite db (legacy mode)"""
    json_files = list(Path(json_dir).glob("*.json"))
    print(f"Found {len(json_files)} JSON files")

    if not json_files:
        print("No JSON files found")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create simple schema for multi-library mode
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS libraries (
            id INTEGER PRIMARY KEY,
            name TEXT,
            language TEXT,
            compiler TEXT,
            image_base TEXT
        );

        CREATE TABLE IF NOT EXISTS functions (
            id INTEGER PRIMARY KEY,
            lib_id INTEGER,
            name TEXT,
            address TEXT,
            signature TEXT,
            is_thunk INTEGER,
            is_external INTEGER,
            is_export INTEGER,
            body_size INTEGER,
            code_hash TEXT,
            decompiled TEXT,
            FOREIGN KEY (lib_id) REFERENCES libraries(id)
        );

        CREATE TABLE IF NOT EXISTS strings (
            id INTEGER PRIMARY KEY,
            lib_id INTEGER,
            value TEXT,
            address TEXT,
            FOREIGN KEY (lib_id) REFERENCES libraries(id)
        );

        CREATE TABLE IF NOT EXISTS imports (
            id INTEGER PRIMARY KEY,
            lib_id INTEGER,
            name TEXT,
            library TEXT,
            FOREIGN KEY (lib_id) REFERENCES libraries(id)
        );

        CREATE TABLE IF NOT EXISTS exports (
            id INTEGER PRIMARY KEY,
            lib_id INTEGER,
            name TEXT,
            address TEXT,
            FOREIGN KEY (lib_id) REFERENCES libraries(id)
        );

        CREATE INDEX IF NOT EXISTS idx_func_name ON functions(name);
        CREATE INDEX IF NOT EXISTS idx_func_lib ON functions(lib_id);
        CREATE INDEX IF NOT EXISTS idx_strings_lib ON strings(lib_id);
    ''')

    for json_file in json_files:
        print(f"  Importing {json_file.name}...")
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        lib = data.get('library', {})
        cursor.execute('''
            INSERT INTO libraries (name, language, compiler, image_base)
            VALUES (?, ?, ?, ?)
        ''', (lib.get('name'), lib.get('language'), lib.get('compiler'), lib.get('image_base')))
        lib_id = cursor.lastrowid

        for func in data.get('functions', []):
            cursor.execute('''
                INSERT INTO functions (lib_id, name, address, signature, is_thunk,
                    is_external, is_export, body_size, code_hash, decompiled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (lib_id, func.get('name'), func.get('address'), func.get('signature'),
                  1 if func.get('is_thunk') else 0,
                  1 if func.get('is_external') else 0,
                  1 if func.get('is_export') else 0,
                  func.get('body_size', 0), func.get('code_hash'), func.get('decompiled')))

        for s in data.get('strings', []):
            cursor.execute('INSERT INTO strings (lib_id, value, address) VALUES (?, ?, ?)',
                          (lib_id, s.get('value'), s.get('address')))

        for imp in data.get('imports', []):
            if isinstance(imp, dict):
                cursor.execute('INSERT INTO imports (lib_id, name, library) VALUES (?, ?, ?)',
                              (lib_id, imp.get('name'), imp.get('library')))
            else:
                cursor.execute('INSERT INTO imports (lib_id, name) VALUES (?, ?)', (lib_id, imp))

        for exp in data.get('exports', []):
            cursor.execute('INSERT INTO exports (lib_id, name, address) VALUES (?, ?, ?)',
                          (lib_id, exp.get('name'), exp.get('address')))

    conn.commit()
    conn.close()
    print(f"Database: {db_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 json_to_sqlite.py <input.json> <output.db>  # Single file")
        print("  python3 json_to_sqlite.py <json_dir> [output.db]    # Directory")
        sys.exit(1)

    input_path = Path(sys.argv[1])

    if input_path.is_file() and input_path.suffix == '.json':
        # Single file mode (used by ApiServer)
        if len(sys.argv) < 3:
            print("Error: output.db required for single file mode")
            sys.exit(1)
        db_path = sys.argv[2]
        convert_single(str(input_path), db_path)
    elif input_path.is_dir():
        # Directory mode (legacy)
        db_path = sys.argv[2] if len(sys.argv) > 2 else str(input_path / "natives.db")
        convert_directory(str(input_path), db_path)
    else:
        print(f"Error: {input_path} not found or not a valid JSON file/directory")
        sys.exit(1)


if __name__ == "__main__":
    main()
