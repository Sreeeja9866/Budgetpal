import pytest
from main import app
from src.database import get_db
from src.authentication import generate_password_hash
from datetime import datetime, timedelta
import json

def test_():
    assert 1 == 1

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

# Helper function to create a test user
def create_test_user(client):
    with app.app_context():
        db = get_db(app)
        db.execute('INSERT INTO users (fullname, username, email, password) VALUES (?, ?, ?, ?)',
                    ('Test User', 'testuser', 'test@example.com', generate_password_hash('StrongPassword123!')))
        db.commit()

        # Get the user ID of the newly created user
        user = db.execute('SELECT id FROM users WHERE username = ?', ('testuser',)).fetchone()
        user_id = user['id']
        
        # Now set up security questions
        db.execute('''
            UPDATE users 
            SET security_question_1 = ?, 
                security_answer_1 = ?,
                security_question_2 = ?,
                security_answer_2 = ?
            WHERE id = ?
        ''', (
            'What was your first pet\'s name?',
            generate_password_hash('a'),
            'In what city were you born?',
            generate_password_hash('b'),
            user_id
        ))
        db.commit()

# Helper function to delete the test user
def delete_test_user():
    with app.app_context():
        db = get_db(app)
        db.execute('DELETE FROM users WHERE username = ?', ('testuser',))
        db.commit()

# Helper function to get a client with logged in user
@pytest.fixture
def logged_in_client(client):
    create_test_user(client)
    client.post('/login', data={'username': 'testuser', 'password': 'StrongPassword123!'}, follow_redirects=True)
    yield client
    delete_test_user()

# Helper function to add a test savings goal
def add_test_savings_goal(logged_in_client):
    return logged_in_client.post('/add_savings_goal', data={
        'goal_name': 'Test Goal',
        'target_amount': 1000,
        'target_date': (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d'),
        'priority': 3
    }, follow_redirects=True)

def remove_all_savings_goals(logged_in_client):
    """Remove all savings goals for the current user"""
    with app.app_context():
        db = get_db(app)
        db.execute('DELETE FROM savings_goals WHERE user_id = ?', (1,))  # Assuming user_id is 1 for test user
        db.commit()
# ============================================================================
# Home page test
# ============================================================================
def test_home_page(client):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/' page is requested (GET)
    THEN check that the response is valid
    """
    response = client.get('/')
    assert response.status_code == 200
    assert b"Expense Manager" in response.data
    assert b"Track Your Expenses" in response.data
    assert b"Budget Management" in response.data
    assert b"Expense Insights" in response.data

# ============================================================================
# authentication tests
# ============================================================================

# signup tests
def test_sigup(client):
    """Test registration form validation"""
    # Test signup page fetch
    response = client.get('/signup')
    assert response.status_code == 200

def test_sigup_password_len(client):
    # Test password security criteria - is 8 char long
    response = client.post('/signup', data={
        'fullname': 'Test User',
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'weak',
        'confirm_password': 'weak'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Password must be at least 8 characters long" in response.data

def test_sigup_password_has_uppercase(client):
    # Test password security criteria - has upper case
    response = client.post('/signup', data={
        'fullname': 'Test User',
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'nouppercase@1234',
        'confirm_password': 'nouppercase@1234'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Password must contain at least one uppercase letter" in response.data

def test_sigup_password_has_lowercase(client):
    # Test password security criteria - has lower case
    response = client.post('/signup', data={
        'fullname': 'Test User',
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'NOLOWERCASE@1234',
        'confirm_password': 'NOLOWERCASE@1234'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Password must contain at least one lowercase letter" in response.data

def test_sigup_password_has_digit(client):
    # Test password security criteria - has digit
    response = client.post('/signup', data={
        'fullname': 'Test User',
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'Nodigits',
        'confirm_password': 'Nodigits'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Password must contain at least one digit" in response.data

def test_sigup_successful(client):
    # Test successful registration
    response = client.post('/signup', data={
        'fullname': 'Test User',
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'StrongPassword123!',
        'confirm_password': 'StrongPassword123!'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Already have an account" in response.data or b"Security Questions" in response.data

    delete_test_user()

def test_sigup_duplicate(client):
    # Test existing user or email
    create_test_user(client)
    response = client.post('/signup', data={
        'fullname': 'Test User',
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'weak',
        'confirm_password': 'weak'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Already have an account" in response.data and b"Login" in response.data
    delete_test_user()

# login tests
def test_login(client):
    """Test login functionality"""
    
    # Test login page fetch
    response = client.get('/login')
    assert response.status_code == 200
    assert b"Login" in response.data

def test_login_invalid_user(client):
    # Test login with non-existent user
    response = client.post('/login', data={
        'username': 'nonexistentuser',
        'password': 'SomePassword123!'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Invalid User" in response.data

def test_login_valid_user(client):
    # Create a test user for the following tests
    create_test_user(client)

    # Test login with correct credentials
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'StrongPassword123!'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Expense Manager - Home" in response.data

    delete_test_user()

def test_login_invalid_password(client):
    create_test_user(client)
    # Test login with incorrect password
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'WrongPassword123!'
    }, follow_redirects=True)
   
    assert response.status_code == 200
    assert b"Invalid password" in response.data
    delete_test_user()

def test_login_5_incorrect_attempts(client):
    create_test_user(client)
    # Test account lockout after 5 incorrect attempts
    for _ in range(5):
        response = client.post('/login', data={
            'username': 'testuser',
            'password': 'WrongPassword123!'
        }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Account locked due to too many incorrect attempts. Try again after 30 minutes." in response.data
    delete_test_user()

def test_login_after_locked(client):
    create_test_user(client)
    # Test account lockout after 5 incorrect attempts
    for _ in range(5):
        client.post('/login', data={
            'username': 'testuser',
            'password': 'WrongPassword123!'
        }, follow_redirects=True)

    response = client.post('/login', data={
            'username': 'testuser',
            'password': 'StrongPassword123!'
        }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Login" in response.data

    delete_test_user()

# Test reset password page access
def test_reset_password_page(client):
    response = client.get('/reset_password')
    assert response.status_code == 302  # Should redirect to login page if not logged in

# Test security answers page access
def test_security_answers_page(client):
    response = client.get('/security_answers')
    assert response.status_code == 302  # Should redirect to login page if not logged in

# Test submitting correct security answers
def test_correct_security_answers(client):
    create_test_user(client)
    
    # Log in the user
    client.post('/login', data={'username': 'testuser', 'password': 'StrongPassword123!'})
    
    response = client.post('/security_answers', data={
        'security_answer_1': 'a',
        'security_answer_2': 'b'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Reset Password" in response.data
    
    delete_test_user()

# Test submitting incorrect security answers
def test_incorrect_security_answers(client):
    create_test_user(client)
    
    # Log in the user
    client.post('/login', data={'username': 'testuser', 'password': 'StrongPassword123!'})
    
    response = client.post('/security_answers', data={
        'security_answer_1': 'WrongAnswer',
        'security_answer_2': 'WrongCity'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Incorrect security answers" in response.data
    
    delete_test_user()

# Test password reset with valid new password
def test_valid_password_reset(client):
    create_test_user(client)
    
    # Log in the user and pass security answers
    client.post('/login', data={'username': 'testuser', 'password': 'StrongPassword123!'})
    client.post('/security_answers', data={
        'security_answer_1': 'a',
        'security_answer_2': 'b'
    })
    
    response = client.post('/reset_password', data={
        'new_password': 'NewStrongPassword456!',
        'confirm_password': 'NewStrongPassword456!'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Expense Manager - Home" in response.data
    delete_test_user()

# ============================================================================
# Income and Expense tests
# ============================================================================
    
def test_add_expense(logged_in_client):
    """Test adding an expense"""
    response = logged_in_client.post('/add_expense', data={
        'date': '2024-07-27',
        'category': 'Food',
        'amount': '50.00',
        'description': 'Groceries'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Expense added successfully' in response.data

def test_add_income(logged_in_client):
    """Test adding an income"""
    response = logged_in_client.post('/add_income', data={
        'date': '2024-07-27',
        'category': 'Salary',
        'amount': '2000.00',
        'description': 'Monthly salary',
        'frequency': 'monthly'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Income added successfully' in response.data

def test_view_expenses(logged_in_client):
    """Test viewing expenses"""
    # First, add a test expense
    logged_in_client.post('/add_expense', data={
        'date': '2024-07-27',
        'category': 'Food',
        'amount': '50.00',
        'description': 'Groceries'
    }, follow_redirects=True)

    # Now, view expenses
    response = logged_in_client.get('/expenses')

    assert response.status_code == 200
    assert b'Expenses' in response.data
    assert b'Food' in response.data
    assert b'50' in response.data
    assert b'Groceries' in response.data

def test_view_income(logged_in_client):
    """Test viewing income"""
    # First, add a test income
    logged_in_client.post('/add_income', data={
        'date': '2024-07-27',
        'category': 'Salary',
        'amount': '2000.00',
        'description': 'Monthly salary',
        'frequency': 'monthly'
    }, follow_redirects=True)

    # Now, view income
    response = logged_in_client.get('/income')
    assert response.status_code == 200
    assert b'Income' in response.data
    assert b'Salary' in response.data
    assert b'2000' in response.data
    assert b'Monthly salary' in response.data
    assert b'monthly' in response.data

def test_add_expense_unauthenticated(client):
    """Test adding an expense without authentication"""
    response = client.post('/add_expense', data={
        'date': '2024-07-27',
        'category': 'Food',
        'amount': '50.00',
        'description': 'Groceries'
    }, follow_redirects=True)
    assert response.status_code == 200
    # checks if redirected to login page
    assert b'Login' in response.data  

def test_add_income_unauthenticated(client):
    """Test adding an income without authentication"""
    response = client.post('/add_income', data={
        'date': '2024-07-27',
        'category': 'Salary',
        'amount': '2000.00',
        'description': 'Monthly salary',
        'frequency': 'monthly'
    }, follow_redirects=True)
    assert response.status_code == 200
    # checks if redirected to login page
    assert b'Login' in response.data  

def test_view_expenses_unauthenticated(client):
    """Test viewing expenses without authentication"""
    response = client.get('/expenses', follow_redirects=True)
    assert response.status_code == 200
    # checks if redirected to login page
    assert b'Login' in response.data  

def test_view_income_unauthenticated(client):
    """Test viewing income without authentication"""
    response = client.get('/income', follow_redirects=True)
    assert response.status_code == 200
    # checks if redirected to login page
    assert b'Login' in response.data