import sqlite3

# Connect to the SQLite database (or create it if it doesn't exist)
connection = sqlite3.connect('detishop.db')
cursor = connection.cursor()

# Create User Management table
cursor.execute("DROP TABLE IF EXISTS users")
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        login_attempts INTEGER NOT NULL DEFAULT 0,
        role TEXT NOT NULL CHECK(Role IN ('admin', 'customer')) DEFAULT 'customer'
        
    )
''')

# Create Product Catalog table
cursor.execute("DROP TABLE IF EXISTS products")
cursor.execute('''
CREATE TABLE IF NOT EXISTS products (
    product_id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    ImageURL TEXT NOT NULL,
    category TEXT NOT NULL,
    stock_qnt INTEGER NOT NULL
)
''')

# Create Shopping Cart table
cursor.execute("DROP TABLE IF EXISTS shopping_cart")
cursor.execute('''
CREATE TABLE IF NOT EXISTS shopping_cart (
    card_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    product_id INTEGER,
    quantity INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(user_id),
    FOREIGN KEY(product_id) REFERENCES products(product_id)
)
''')

# Create Order History table
#cursor.execute('''
#CREATE TABLE IF NOT EXISTS orders (
#    order_id INTEGER PRIMARY KEY AUTOINCREMENT,
#    user_id INTEGER,
#    product_id INTEGER,
#    total_price REAL,
#    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
#    FOREIGN KEY(user_id) REFERENCES users(user_id),
#    FOREIGN KEY(product_id) REFERENCES products(product_id)
#)
#''')

# Create Reviews and Ratings table
cursor.execute("DROP TABLE IF EXISTS reviews")
cursor.execute('''
CREATE TABLE IF NOT EXISTS reviews (           
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_name TEXT NOT NULL,
    product_name TEXT NOT NULL,
    review TEXT,
    user_id INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

connection.commit()