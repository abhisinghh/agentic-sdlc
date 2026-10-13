### Add a maximum-price filter to product search

`find_products(conn, name)` should accept an optional `max_price: float | None = None` and only
return products at or below that price when it is given. Keep the query parameterised and add tests.
