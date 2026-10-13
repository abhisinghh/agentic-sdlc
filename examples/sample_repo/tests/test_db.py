from app.db import find_products, get_conn


def test_find_products_by_exact_name():
    conn = get_conn()
    conn.execute("INSERT INTO products (name, price) VALUES ('apple', 1.0)")
    assert find_products(conn, "apple") == [(1, "apple", 1.0)]
