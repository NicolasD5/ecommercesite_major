# Import Flask and its core components for web application functionality
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
# Import Bcrypt for secure password hashing
from flask_bcrypt import Bcrypt
# Import SQLite3 for database operations
import sqlite3
# Import logging for application event tracking
import logging
# Import custom encryption functions for data security
from encryption import encrypt_data, decrypt_data
# Import timedelta for session duration management
from datetime import timedelta
# Import random and string for verification code generation
import random
import string
# Import OS for file path operations
import os
# Import secure_filename for safe file uploads
from werkzeug.utils import secure_filename
# Import custom password validation class
from password_validation import PasswordValidator
# Import rate limiting functionality
#from flask_limiter import Limiter
#from flask_limiter.util import get_remote_address

import base64
from datetime import datetime
import uuid

# Create Flask application instance
app = Flask(__name__)


# Initialise rate limiter with IP-based tracking and stricter limits
'''
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],  # Set default rate limits
    storage_uri="memory://",  # Store rate limit data in memory
)
'''
app.secret_key = 'jRFfOua3p9yNAVv6d8ygf-d3g1OTcCnQw4_GZ0kwBag='  #Hardcoded secret key for encryption
bcrypt = Bcrypt(app)  # Initialise Bcrypt for password hashing
logger = logging.getLogger(__name__)
logging.basicConfig(filename='security_log.log', encoding='utf-8', level=logging.DEBUG, format='%(asctime)s %(message)s')

# Configure session settings
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.permanent_session_lifetime = timedelta(minutes=15)

# Hardcoded admin credentials would be changed in production environment but for simplicity and demonstrating the roles it is hardcoded
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# Store the generated admin verification code
admin_verification_code = None

# Configure file upload settings and only allow image file extensions and set the images to upload in the static folder
UPLOAD_FOLDER = 'static/profile_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True) #Ensure the upload folder exists as it makes a directory of it doesn't exist in the directory set in UPLOAD_FOLDER

PRODUCT_IMAGES_FOLDER = 'static/product_images'
app.config['PRODUCT_IMAGES_FOLDER'] = PRODUCT_IMAGES_FOLDER
os.makedirs(app.config['PRODUCT_IMAGES_FOLDER'], exist_ok=True)

@app.before_request
def before_request():
    #Generate a new nonce for each request which is part of the content security policy
    if 'nonce' not in g:
        g.nonce = base64.b64encode(os.urandom(16)).decode('utf-8')

@app.context_processor
def inject_nonce():
    #Make nonce available to all templates
    return dict(nonce=g.nonce)

@app.after_request
def add_security_headers(response):
    #Content Security Policy
    nonce = g.get('nonce', '')
    response.headers['Content-Security-Policy'] = (
        "style-src 'self' 'unsafe-inline'; "      #Styles from same origin and inline (for Flask-WTF)
        "img-src 'self' data: blob:; "            #Images from same origin, data URIs, and blob
        "font-src 'self'; "                       #Fonts only from same origin
        "connect-src 'self'; "                    #AJAX/WebSocket only from same origin
        "media-src 'self'; "                      #Media only from same origin
        "frame-src 'none'; "                      #Deny iframe usage
        "frame-ancestors 'none'; "                #Prevent site from being embedded
        "object-src 'none'; "                     #Prevent object/embed/applet
        "base-uri 'self'; "                       #Restrict base tag
        "form-action 'self'; "                    #Forms can only submit to same origin
        "manifest-src 'self'; "                   #Web app manifest from same origin
        "worker-src 'self' blob:; "               #Workers only from same origin and blob
        "upgrade-insecure-requests; "             #Upgrade HTTP to HTTPS
    )
    
    #Additional Security Headers
    response.headers['X-Frame-Options'] = 'DENY'  #Prevent clickjacking
    response.headers['X-Content-Type-Options'] = 'nosniff'  #Prevent MIME type sniffing
    response.headers['X-XSS-Protection'] = '1; mode=block'  #Enable XSS filter
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'  #Force HTTPS
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'  #Control referrer information
    response.headers['Permissions-Policy'] = (
        "accelerometer=(), "
        "camera=(), "
        "geolocation=(), "
        "gyroscope=(), "
        "magnetometer=(), "
        "microphone=(), "
        "payment=(), "
        "usb=()"
    )
    
    return response

def allowed_file(filename): #Check if the uploaded file has an allowed extension only allowing jpg and png as seen in the ALLOWED EXTENSIONS variable
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db(): #Create a database connection
    db = sqlite3.connect('database.db')
    db.row_factory = sqlite3.Row  # Allows accessing columns by name
    return db

def close_db(db): #Close the database connection 
    if db is not None:
        db.close()

def generate_verification_code(length=6): # Generate a random verification code for the admin login, "string.ascii_uppercase" ensures that the code is only uppercase letters and digits
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def username_exists(username): #Check if a username already exists in the database
    try:
        connection = get_db()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users")  # Get all users
        users = cursor.fetchall()
        
        for user in users:
            if decrypt_data(user['username']) == username:  #Compare decrypted usernames
                return True
        return False
    finally:
        close_db(connection)

def sanitise_input(value): #Escapes the html characters and stops XSS attacks
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
        .replace("/", "&#x2F;")
    )

def execute_safe_query(query, params=(), fetch_one=False): #Execute a parameterised SQL query safely
    try:
        connection = get_db()
        cursor = connection.cursor()
        cursor.execute(query, params)
        
        if fetch_one:
            result = cursor.fetchone()
        else:
            result = cursor.fetchall()
            
        connection.commit()
        return result
    except Exception as e:
        logger.error(f"Database error in execute_safe_query function (main.py): {e}")
        raise
    finally:
        close_db(connection)

def validate_user_id(user_id): #Validate that user_id is a positive integer ensuring there are no invaild user ids
    try:
        user_id = int(user_id)
        if user_id <= 0:
            raise ValueError("Invalid user ID")
        return user_id
    except (ValueError, TypeError):
        raise ValueError("Invalid user ID")

def get_cart_items():
    """Helper function to get all items in the cart with their details"""
    cart_items = []
    if session.get('cart'):
        connection = get_db()
        cursor = connection.cursor()
        try:
            for product_id, quantity in session['cart'].items():
                cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
                product = cursor.fetchone()
                if product:
                    item = dict(product)
                    item['quantity'] = quantity
                    cart_items.append(item)
        finally:
            connection.close()
    return cart_items

def calculate_cart_total():
    """Helper function to calculate the total price of all items in the cart"""
    total = 0
    if session.get('cart'):
        connection = get_db()
        cursor = connection.cursor()
        try:
            for product_id, quantity in session['cart'].items():
                cursor.execute("SELECT price FROM products WHERE id = ?", (product_id,))
                result = cursor.fetchone()
                if result:
                    total += result['price'] * quantity
        finally:
            connection.close()
    return total

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            # Log input username for debugging
            logger.info(f"Input username: {username}")
            
            # Get all users to compare decrypted usernames
            cursor.execute('SELECT * FROM users')
            users = cursor.fetchall()
            
            user = None
            for u in users:
                decrypted_username = decrypt_data(u['username'])
                if decrypted_username == username:
                    user = u
                    break

            if user and bcrypt.check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = username
                session['mobile'] = decrypt_data(user['mobile']) if user['mobile'] else 'Not provided'
                session['address'] = decrypt_data(user['address']) if user['address'] else 'Not provided'
                session.permanent = True
                
                flash('Login successful!', 'success')
                return redirect(url_for('customer_dashboard'))
                
            flash('Invalid username or password')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login')
            return redirect(url_for('login'))
        finally:
            close_db(conn)
    
    return render_template('login.html')

@app.route("/customer_dashboard")
def customer_dashboard():
    user_id = session.get("user_id")
    if not user_id:
        logger.debug("No user_id in session. Redirecting to login.")
        flash("Please log in to access this page.", "warning")
        return redirect(url_for("login"))

    try:
        connection = get_db()
        cursor = connection.cursor()

        # First get user profile data
        cursor.execute("SELECT profile_image FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        
        user_data = {
            "id": user_id,
            "username": session.get("username"),
            "mobile": session.get("mobile"),
            "address": session.get("address"),
            "profile_image": result[0] if result and result[0] else "default.png"
        }

        # Get orders first
        cursor.execute("""
            SELECT id, created_at, total 
            FROM orders 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        """, (user_id,))
        
        orders_data = cursor.fetchall()
        orders = []
        
        # Process each order
        for order in orders_data:
            # Get items for this order
            cursor.execute("""
                SELECT p.name, oi.quantity, oi.price
                FROM order_items oi
                JOIN products p ON p.id = oi.product_id
                WHERE oi.order_id = ?
            """, (order['id'],))
            
            items = cursor.fetchall()
            
            orders.append({
                'id': order['id'],
                'created_at': order['created_at'],
                'total': order['total'],
                'items': [{
                    'name': item['name'],
                    'quantity': item['quantity'],
                    'price': item['price']
                } for item in items]
            })

        connection.close()
        print(user_data)
        print(orders)
        return render_template("customer_dashboard.html", 
                            user_data=user_data,
                            orders=orders)

    except Exception as e:
        logger.error(f"Error in customer_dashboard: {str(e)}", exc_info=True) #exc_info=True shows where errors are occuring in the log
        if 'connection' in locals():
            connection.close()
        flash("An error occurred while fetching user data.", "danger")
        return redirect(url_for("products"))  # Changed to redirect to products instead of login

@app.route("/logout")
def logout():
    if session.get('is_admin'):
        try:
            connection = get_db()
            cursor = connection.cursor()
            cursor.execute("""
                UPDATE users 
                SET is_being_edited = 0, edited_by = NULL 
                WHERE edited_by = ?
            """, (ADMIN_USERNAME,))
            connection.commit()
        except Exception as e:
            logger.error(f"Error stopping SQL injection {e}")
    
    session.clear() #Ensures the session is removed when the user logs out
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/create_account", methods=["GET", "POST"])
def create_account():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        mobile = request.form.get('mobile', '')
        address = request.form.get('address', '')
        
        try:
            # Encrypt the username and user data
            encrypted_username = encrypt_data(username)
            encrypted_mobile = encrypt_data(mobile) if mobile else ''
            encrypted_address = encrypt_data(address) if address else ''
            
            # Hash the password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            # Insert the new user
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (username, password, mobile, address) VALUES (?, ?, ?, ?)',
                (encrypted_username, hashed_password, encrypted_mobile, encrypted_address)
            )
            conn.commit()
            
            flash('Account created successfully! Please login.')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Error creating account: {str(e)}")
            flash('An error occurred while creating your account')
            return redirect(url_for('create_account'))
        finally:
            close_db(conn)
    
    return render_template('create_account.html')

@app.route("/forgot_login", methods=["GET", "POST"])
#@limiter.limit("10 per minute")  # Limit password reset attempts
def forgot_login(): #Forgot login functionality allows users to change their password through verifying their identity through security questions
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        security_answer_1 = request.form.get("security_answer_1", "").strip()
        security_answer_2 = request.form.get("security_answer_2", "").strip()
        new_password = request.form.get("new_password", "").strip()

        if not username or not security_answer_1 or not security_answer_2 or not new_password: #Ensures all fields are filled in
            flash("All fields are required.", "danger")
            return redirect(url_for("forgot_login"))

        validation_result = PasswordValidator.validate_password(new_password) #Validates the new password
        if not validation_result["valid"]:
            for error in validation_result["errors"]:
                flash(error, "danger")
            return redirect(url_for("forgot_login"))

        try:
            user = execute_safe_query( #Fetches the user data from the database safely
                "SELECT * FROM users WHERE username = ?",
                (encrypt_data(username),),
                fetch_one=True
            )

            if not user:
                flash("Invalid username.", "danger")
                return redirect(url_for("forgot_login"))

            #Checks security answers to match the ones in the database
            if user['security_answer_1'] != security_answer_1 or user['security_answer_2'] != security_answer_2:
                flash("Security answers do not match.", "danger")
                return redirect(url_for("forgot_login"))

            #Update password using parameterised query
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            execute_safe_query(
                "UPDATE users SET password = ? WHERE username = ?",
                (hashed_password, user['username'])
            )

            flash("Password reset successfully! Please log in.", "success")
            return redirect(url_for("login"))

        except Exception as e:
            logger.error(f"Error during password reset: {e}")
            flash("An error occurred while resetting your password.", "danger")
            return redirect(url_for("forgot_login"))

    return render_template("forgot_login.html")

@app.route("/admin_dashboard", methods=["GET", "POST"])
def admin_dashboard(): #Handle the admin login and verification
    if request.method == "POST":
        entered_code = request.form.get("verification_code")
        if entered_code == admin_verification_code:
            session['is_admin'] = True  #Establish admin session
            session['username'] = ADMIN_USERNAME
            flash("Admin verified successfully!", "success")
            return redirect(url_for("view_users"))
        else:
            flash("Invalid verification code. Please try again.", "danger")
    return render_template("admin_dashboard.html")

@app.route("/view_users")
def view_users(): #Display list of all users for the admin
    if not session.get('is_admin'):
        flash("Admin access required", "danger")
        return redirect(url_for("login"))

    try:
        #Ensure that it is executing a safe query and also ensures two cannot edit it at the same time
        execute_safe_query("""
            UPDATE users 
            SET is_being_edited = 0, edited_by = NULL 
            WHERE is_being_edited = 1
        """)
        
        # Fetch users with parameterised query
        users = execute_safe_query("""
            SELECT id, username, mobile, address, is_being_edited, edited_by 
            FROM users
        """)

        decrypted_users = []
        for user in users:
            decrypted_users.append({
                'id': user['id'],
                'username': decrypt_data(user['username']),
                'mobile': decrypt_data(user['mobile']),
                'address': decrypt_data(user['address']),
                'is_being_edited': bool(user['is_being_edited']),
                'edited_by': user['edited_by']
            })

        return render_template("view_users.html", users=decrypted_users)
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        flash("An error occurred while fetching user data.", "danger")
        return redirect(url_for("admin_dashboard"))

@app.route("/edit_user/<int:user_id>") 
def edit_user(user_id): #Allows admin to edit user data, taking the user id that was selected and giving the details and the ability to change them
    if not session.get('is_admin'):
        flash("Admin access required", "danger")
        return redirect(url_for("login"))

    try:
        #Validates user_id
        user_id = validate_user_id(user_id)
        
        execute_safe_query(""" 
            UPDATE users 
            SET is_being_edited = 0, edited_by = NULL 
            WHERE edited_by = ?
        """, (ADMIN_USERNAME,))
        
        # Get user data
        user = execute_safe_query(
            "SELECT * FROM users WHERE id = ?", 
            (user_id,), 
            fetch_one=True
        )

        if not user:
            flash("User not found", "danger")
            return redirect(url_for("view_users"))
        
        execute_safe_query("""
            UPDATE users 
            SET is_being_edited = 1, edited_by = ? 
            WHERE id = ?
        """, (ADMIN_USERNAME, user_id))

        user_data = {
            'id': user['id'],
            'username': decrypt_data(user['username']),
            'mobile': decrypt_data(user['mobile']),
            'address': decrypt_data(user['address'])
        }
        
        return render_template("edit_user.html", user=user_data)
    except ValueError as ve:
        flash(str(ve), "danger") #Handles error if user id is invalid
        return redirect(url_for("view_users"))
    except Exception as e:
        logger.error(f"Error accessing user data: {e}")
        flash("An error occurred", "danger")
        return redirect(url_for("view_users"))

@app.route("/update_user/<int:user_id>", methods=["POST"])
#@limiter.limit("10 per minute")  #Limit update attempts
def update_user(user_id):
    if not session.get('is_admin'):
        flash("Admin access required", "danger")
        return redirect(url_for("login"))

    try:
        user_id = validate_user_id(user_id)
        
        #Validates input data
        new_mobile = sanitise_input(request.form.get("new_mobile", "").strip())
        new_address = sanitise_input(request.form.get("new_address", "").strip())
        
        if not new_mobile or not new_address:
            flash("Mobile and address cannot be empty", "danger")
            return redirect(url_for("edit_user", user_id=user_id))

        #Update user data with parameterised queries
        execute_safe_query(
            "UPDATE users SET mobile = ? WHERE id = ?", 
            (encrypt_data(new_mobile), user_id)
        )
        execute_safe_query(
            "UPDATE users SET address = ? WHERE id = ?", 
            (encrypt_data(new_address), user_id)
        )
        
        execute_safe_query("""
            UPDATE users 
            SET is_being_edited = 0, edited_by = NULL 
            WHERE id = ?
        """, (user_id,))
        
        flash("User data updated successfully!", "success")
        
    except ValueError as ve:
        flash(str(ve), "danger")
    except Exception as e:
        logger.error(f"Error updating user data: {e}")
        flash("An error occurred while updating user data.", "danger")
    
    return redirect(url_for("view_users"))

@app.route("/manage_users")
def manage_users(): #Displays the list of users
    if 'username' not in session or session['username'] != ADMIN_USERNAME:
        flash("Admin access required", "danger")
        return redirect(url_for("login"))

    try:
        connection = get_db()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT id, username, mobile, address, is_being_edited, edited_by 
            FROM users
        """)
        users = cursor.fetchall()

        decrypted_users = []
        for user in users:
            decrypted_users.append({
                'id': user['id'],
                'username': decrypt_data(user['username']),
                'mobile': decrypt_data(user['mobile']),
                'address': decrypt_data(user['address']),
                'is_being_edited': user['is_being_edited'],
                'edited_by': user['edited_by']
            })

        return render_template("manage_users.html", users=decrypted_users)
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        flash("An error occurred while fetching user data.", "danger")
        return redirect(url_for("admin_dashboard"))

@app.route("/products")
def products():
    try:
        connection = get_db()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM products")
        products = cursor.fetchall()
        return render_template('products.html', products=products)
    except Exception as e:
        logger.error(f"Error loading products: {e}")
        flash("Error loading products", "danger")
        return render_template('products.html', products=[])
    finally:
        if 'connection' in locals():
            connection.close()

@app.route("/product/<int:product_id>")
def product_detail(product_id):
    try:
        # Get product details
        connection = get_db()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        
        if product is None:
            flash("Product not found", "danger")
            return redirect(url_for('products'))
            
        # Convert to dictionary for template
        product_dict = dict(product)
        
        return render_template('product_detail.html', product=product_dict)
        
    except Exception as e:
        logger.error(f"Error loading product details: {e}")
        flash("Error loading product details", "danger")
        return redirect(url_for('products'))
    finally:
        if 'connection' in locals():
            connection.close()

@app.route("/")
def home():
    return redirect(url_for('products'))

@app.route("/cart")
def cart():
    if not session.get('user_id'):
        flash("Please log in to view your cart", "warning")
        return redirect(url_for("login"))
        
    cart_items = []
    total = 0
    
    if session.get('cart'):
        connection = get_db()
        cursor = connection.cursor()
        
        for product_id, quantity in session['cart'].items():
            cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
            product = cursor.fetchone()
            if product:
                item = dict(product)
                item['quantity'] = quantity
                cart_items.append(item)
                total += item['price'] * quantity
                
        connection.close()
        
    return render_template("cart.html", cart_items=cart_items, total=total)

@app.route("/add_to_cart/<int:product_id>", methods=["POST"])
def add_to_cart(product_id):
    if not session.get('user_id'):
        flash("Please log in to add items to cart", "warning")
        return redirect(url_for("login"))
    
    try:
        quantity = int(request.form.get("quantity", 1))
        if quantity < 1:
            flash("Invalid quantity", "danger")
            return redirect(url_for("product_detail", product_id=product_id))
        
        # Initialise cart in session if it doesn't exist
        if 'cart' not in session:
            session['cart'] = {}
            
        # Add or update item in cart
        if str(product_id) in session['cart']:
            session['cart'][str(product_id)] += quantity
        else:
            session['cart'][str(product_id)] = quantity
            
        session.modified = True
        flash("Added to cart successfully!", "success")
        return redirect(url_for("cart"))
        
    except Exception as e:
        flash("Error adding to cart", "danger")
        return redirect(url_for("product_detail", product_id=product_id))

@app.route("/remove_from_cart/<int:product_id>", methods=["POST"])
def remove_from_cart(product_id):
    try:
        quantity = int(request.form.get('remove_quantity', 1))
        if str(product_id) in session.get('cart', {}):
            current_quantity = session['cart'][str(product_id)]
            if quantity >= current_quantity:
                del session['cart'][str(product_id)]
            else:
                session['cart'][str(product_id)] -= quantity
            session.modified = True
            flash(f"Removed {quantity} item(s) from cart", "success")
    except ValueError:
        flash("Invalid quantity", "danger")
    return redirect(url_for("cart"))

def get_product_by_id(product_id):
    """Helper function to fetch a product by its ID from the database."""
    connection = get_db()
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        return dict(product) if product else None
    except Exception as e:
        logger.error(f"Error fetching product with ID {product_id}: {e}")
        return None
    finally:
        cursor.close()

# Update the checkout function to use the helper function
@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    # Check if user is logged in
    if not session.get('user_id'):
        flash("Please log in to checkout", "warning")
        session['next'] = url_for('checkout')
        return redirect(url_for('login'))
    
    # Get cart items
    cart_items = get_cart_items()
    if not cart_items:
        flash("Your cart is empty", "warning")
        return redirect(url_for('cart'))
    
    total = calculate_cart_total()
    
    # Handle order submission
    if request.method == 'POST':
        try:
            connection = get_db()
            cursor = connection.cursor()
            
            # Create the order
            cursor.execute(
                "INSERT INTO orders (user_id, total) VALUES (?, ?)",
                (session['user_id'], total)
            )
            order_id = cursor.lastrowid
            
            # Create the order items
            for item in cart_items:
                cursor.execute(
                    """INSERT INTO order_items 
                       (order_id, product_id, quantity, price) 
                       VALUES (?, ?, ?, ?)""",
                    (order_id, item['id'], item['quantity'], item['price'])
                )
            
            # Update product stock
            for item in cart_items:
                cursor.execute(
                    "UPDATE products SET stock = stock - ? WHERE id = ?",
                    (item['quantity'], item['id'])
                )
            
            connection.commit()
            session.pop('cart', None)  # Clear the cart
            flash("Order placed successfully!", "success")
            return redirect(url_for('products'))
            
        except Exception as e:
            if 'connection' in locals():
                connection.rollback()
            logger.error(f"Checkout error: {e}")
            flash("Error processing your order", "danger")
            return redirect(url_for('cart'))
        finally:
            if 'connection' in locals():
                connection.close()
    
    # Show checkout page
    print(cart_items)
    return render_template('checkout.html', 
                         cart_items=cart_items,
                         total=total)

@app.errorhandler(Exception)
def unhandled_exception(e):
    logger.error(f"Unhandled exception: {e}", exc_info=True)  # Log the exception with traceback
    return render_template("404.html"), 500

@app.errorhandler(429)  #Handles the exception when the rate limit is exceeded
def ratelimit_handler(e):
    logger.warning(f"Rate limit exceeded: {e.description}")
    flash("Too many requests. Please try again later.", "danger")
    return redirect(url_for('login')), 429

if __name__ == "__main__":
    app.run(debug=True)
