import os
import sys

# Add parent directory to Python path so we can import main.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app
from unittest.mock import patch, MagicMock
import unittest

class EcommerceTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        
        # Mock data for testing
        self.mock_products = {
            1: {'id': 1, 'name': 'Test Guitar', 'price': 999.99, 'stock': 10, 'image': 'test.jpg'},
            2: {'id': 2, 'name': 'Test Guitar 2', 'price': 1499.99, 'stock': 5, 'image': 'test2.jpg'}
        }
        
        # Mock user data
        self.mock_user = {'id': 1, 'username': 'testuser'}

    def mock_db_cursor(self):
        """Create a mock cursor with test data"""
        cursor = MagicMock()
        cursor.fetchone = lambda: self.mock_products[1]
        cursor.fetchall = lambda: list(self.mock_products.values())
        return cursor

    @patch('main.get_db')
    def test_get_cart_items(self, mock_get_db):
        """Test get_cart_items function"""
        mock_get_db.return_value.cursor.return_value = self.mock_db_cursor()
        
        with self.client.session_transaction() as session:
            session['cart'] = {'1': 2}
        
        from main import get_cart_items
        cart_items = get_cart_items()
        
        self.assertEqual(len(cart_items), 1)
        self.assertEqual(cart_items[0]['quantity'], 2)
        self.assertEqual(cart_items[0]['price'], 999.99)

    @patch('main.get_db')
    def test_calculate_cart_total(self, mock_get_db):
        """Test calculate_cart_total function"""
        mock_get_db.return_value.cursor.return_value = self.mock_db_cursor()
        
        with self.client.session_transaction() as session:
            session['cart'] = {'1': 2, '2': 1}
        
        from main import calculate_cart_total
        total = calculate_cart_total()
        
        expected_total = (999.99 * 2) + (1499.99 * 1)
        self.assertAlmostEqual(total, expected_total, places=2)

    def test_add_to_cart(self):
        """Test add_to_cart function"""
        response = self.client.post('/add_to_cart/1', data={'quantity': 2})
        
        with self.client.session_transaction() as session:
            self.assertIn('1', session['cart'])
            self.assertEqual(session['cart']['1'], 2)

    def test_remove_from_cart(self):
        """Test remove_from_cart function"""
        with self.client.session_transaction() as session:
            session['cart'] = {'1': 3}
            
        response = self.client.post('/remove_from_cart/1', data={'remove_quantity': 2})
        
        with self.client.session_transaction() as session:
            self.assertEqual(session['cart']['1'], 1)

    def test_remove_all_from_cart(self):
        """Test removing all items from cart"""
        with self.client.session_transaction() as session:
            session['cart'] = {'1': 2}
            
        response = self.client.post('/remove_from_cart/1', data={'remove_quantity': 2})
        
        with self.client.session_transaction() as session:
            self.assertNotIn('1', session.get('cart', {}))

    def test_empty_cart(self):
        """Test empty cart calculations"""
        from main import calculate_cart_total, get_cart_items
        
        total = calculate_cart_total()
        items = get_cart_items()
        
        self.assertEqual(total, 0)
        self.assertEqual(len(items), 0)

    @patch('main.get_db')
    def test_checkout_process(self, mock_get_db):
        """Test complete checkout process"""
        # Setup mock cursor
        mock_cursor = self.mock_db_cursor()
        mock_get_db.return_value.cursor.return_value = mock_cursor
        
        # Setup session with user and cart
        with self.client.session_transaction() as session:
            session['user_id'] = 1
            session['cart'] = {'1': 2, '2': 1}
        
        # Test checkout
        response = self.client.post('/checkout')
        self.assertEqual(response.status_code, 302)  # Should redirect to receipt
        
        # Verify cart is cleared
        with self.client.session_transaction() as session:
            self.assertNotIn('cart', session)

    @patch('main.get_db')
    def test_checkout_requires_login(self, mock_get_db):
        """Test checkout requires user login"""
        response = self.client.get('/checkout')
        self.assertEqual(response.status_code, 302)  # Should redirect to login
        
        with self.client.session_transaction() as session:
            self.assertTrue(session.get('checkout_pending'))

    @patch('main.get_db')
    def test_product_stock_update(self, mock_get_db):
        """Test product stock updates after purchase"""
        mock_cursor = self.mock_db_cursor()
        mock_get_db.return_value.cursor.return_value = mock_cursor
        
        with self.client.session_transaction() as session:
            session['user_id'] = 1
            session['cart'] = {'1': 2}
        
        response = self.client.post('/checkout')
        
        # Verify stock was updated
        calls = mock_cursor.execute.call_args_list
        self.assertTrue(any('UPDATE products SET stock' in str(call) for call in calls))

    def test_cart_quantity_validation(self):
        """Test cart quantity validation"""
        # Test invalid quantity
        response = self.client.post('/add_to_cart/1', data={'quantity': -1})
        self.assertIn('Invalid quantity', response.get_data(as_text=True))
        
        # Test zero quantity
        response = self.client.post('/add_to_cart/1', data={'quantity': 0})
        self.assertIn('Invalid quantity', response.get_data(as_text=True))

    def test_cart_session_persistence(self):
        """Test cart data persists in session"""
        # Add item to cart
        self.client.post('/add_to_cart/1', data={'quantity': 2})
        
        # Verify cart data persists
        with self.client.session_transaction() as session:
            self.assertIn('1', session['cart'])
            self.assertEqual(session['cart']['1'], 2)
        
        # Add more of same item
        self.client.post('/add_to_cart/1', data={'quantity': 3})
        
        # Verify quantity was updated
        with self.client.session_transaction() as session:
            self.assertEqual(session['cart']['1'], 5)

if __name__ == '__main__':
    unittest.main()
