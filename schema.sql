-- Drop tables in reverse order of dependencies
DROP TABLE IF EXISTS order_items;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,  /* Will store encrypted username */
    password TEXT NOT NULL,         /* Will store hashed password */
    email TEXT NOT NULL,            /* Will store encrypted email */
    mobile TEXT NOT NULL,           /* Will store encrypted mobile */
    address TEXT NOT NULL,          /* Will store encrypted address */
    profile_image TEXT,             /* Column to store image path */
    security_answer_1 TEXT NOT NULL,   /* Answer to first security question */
    security_answer_2 TEXT NOT NULL,   /* Answer to second security question */
    is_being_edited INTEGER DEFAULT 0, /* Indicates if the record is being edited */
    edited_by TEXT DEFAULT NULL        /* Stores the username of the editor */
);

CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    price REAL NOT NULL,
    stock INTEGER NOT NULL,
    image TEXT,
    additional_images TEXT
);

CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    total DECIMAL(10,2) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);