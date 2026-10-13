import sqlite3


def get_conn(path: str = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
    return conn


def find_products(conn: sqlite3.Connection, name: str) -> list[tuple]:
    # BUG (CWE-89): user input concatenated into SQL
    query = f"SELECT id, name, price FROM products WHERE name LIKE '%{name}%'"
    return conn.execute(query).fetchall()
