import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask_sqlalchemy import SQLAlchemy
from main import app
import unittest

# Create test database
db = SQLAlchemy(app)

from encryption import encrypt_data
from flask_bcrypt import Bcrypt

class EcommerceTestCase(unittest.TestCase):
    def setUp(self):
        """Set up test client and test database"""
        app.config['TESTING'] = True
        # Use separate test database to avoid affecting production data
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
        self.client = app.test_client()
        
        with app.app_context():
            db.create_all()  # Creates fresh tables for each test
            self.create_test_data()
    
    def tearDown(self):
        """Clean up after tests"""
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def create_test_data(self):
        """Create test products and users"""
        bcrypt = Bcrypt(app)
        # Create test user
        test_user = {
            'username': encrypt_data('testuser'),
            'password': bcrypt.generate_password_hash('testpass').decode('utf-8'),
            'mobile': encrypt_data('1234567890'),
            'address': encrypt_data('Test Address'),
            'email': encrypt_data('test@test.com'),
            'security_answer_1': 'test1',
            'security_answer_2': 'test2'
        }
        
        # Create test product
        test_product = {
            'name': 'Test Guitar',
            'description': 'Test Description',
            'price': 999.99,
            'stock': 10,
            'image': 'test.jpg'
        }
        
        with app.app_context():
            cursor = db.session.execute(
                """INSERT INTO users (username, password, mobile, address, email, 
                   security_answer_1, security_answer_2) 
                   VALUES (:username, :password, :mobile, :address, :email, 
                   :security_answer_1, :security_answer_2)""",
                test_user
            )
            db.session.execute(
                """INSERT INTO products (name, description, price, stock, image)
                   VALUES (:name, :description, :price, :stock, :image)""",
                test_product
            )
            db.session.commit()

    def test_login(self):
        """Test login functionality"""
        response = self.client.post('/login', data={
            'username': 'testuser',
            'password': 'testpass'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login successful', response.data)

    def test_add_to_cart(self):
        """Test adding items to cart"""
        # First login
        self.client.post('/login', data={
            'username': 'testuser',
            'password': 'testpass'
        })
        
        # Then add to cart
        response = self.client.post('/add_to_cart/1', data={
            'quantity': 1
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Added to cart successfully', response.data)

    def test_checkout(self):
        """Test checkout process"""
        # Login and add item to cart first
        self.client.post('/login', data={
            'username': 'testuser',
            'password': 'testpass'
        })
        self.client.post('/add_to_cart/1', data={'quantity': 1})
        
        # Test checkout
        response = self.client.post('/checkout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Thank You for Your Order', response.data)

    def test_product_stock(self):
        """Test product stock updates after purchase"""
        # Login and purchase
        self.client.post('/login', data={
            'username': 'testuser',
            'password': 'testpass'
        })
        self.client.post('/add_to_cart/1', data={'quantity': 1})
        self.client.post('/checkout')
        
        # Check stock updated
        with app.app_context():
            result = db.session.execute("SELECT stock FROM products WHERE id = 1")
            new_stock = result.fetchone()[0]
            self.assertEqual(new_stock, 9)

    def test_invalid_login(self):
        """Test invalid login credentials"""
        response = self.client.post('/login', data={
            'username': 'testuser',
            'password': 'wrongpass'
        }, follow_redirects=True)
        self.assertIn(b'Invalid username or password', response.data)

    def test_cart_total(self):
        """Test cart total calculation"""
        # Login and add items
        self.client.post('/login', data={
            'username': 'testuser',
            'password': 'testpass'
        })
        self.client.post('/add_to_cart/1', data={'quantity': 2})
        
        with self.client.session_transaction() as session:
            from main import calculate_cart_total
            total = calculate_cart_total()
            self.assertEqual(total, 1999.98)

if __name__ == '__main__':
    unittest.main()
