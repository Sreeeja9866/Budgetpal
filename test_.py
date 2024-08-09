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
# ============================================================================
# Savings Goals tests
# ============================================================================

def test_view_savings_goals(logged_in_client):
    """Test viewing savings goals"""
    add_test_savings_goal(logged_in_client)

    response = logged_in_client.get('/savings_goals')
    assert response.status_code == 200
    assert b'Savings Goals' in response.data
    assert b'Test Goal' in response.data
    assert b'$1000.00' in response.data
    assert b'Priority: 3' in response.data

    remove_all_savings_goals(logged_in_client)

def test_add_savings_goal(logged_in_client):
    """Test adding a savings goal"""
    response = add_test_savings_goal(logged_in_client)
    assert response.status_code == 200
    assert b'Test Goal' in response.data
    assert b'$1000.00' in response.data
    assert b'Priority: 3' in response.data

    # Verify that the goal is in the database
    with app.app_context():
        db = get_db(app)
        goal = db.execute('SELECT * FROM savings_goals WHERE name = ?', ('Test Goal',)).fetchone()
        assert goal is not None
        assert goal['target_amount'] == 1000
        assert goal['priority'] == 3

    remove_all_savings_goals(logged_in_client)


def test_savings_goals_unauthenticated(client):
    """Test accessing savings goals routes without authentication"""
    routes = [
        '/savings_goals',
    ]
    for route in routes:
        response = client.get(route, follow_redirects=True)
        print("", response.data)
        assert response.status_code == 200
        assert b'Login' in response.data  # Should be redirected to login page

# ============================================================================
# Budget Forecast and Management tests
# ============================================================================
        
def add_test_financial_data(logged_in_client):
    """Add test financial data for the current user"""
    with app.app_context():
        db = get_db(app)
        # Add income
        db.execute('INSERT INTO incomes (user_id, date, category, amount, description, frequency) VALUES (?, ?, ?, ?, ?, ?)',
                   (1, '2024-07-01', 'Salary', 5000, 'Monthly salary', 'monthly'))
        # Add expense
        db.execute('INSERT INTO expenses (user_id, date, category, amount, description) VALUES (?, ?, ?, ?, ?)',
                   (1, '2024-07-15', 'Rent', 1500, 'Monthly rent'))
        # Add recurring transaction
        db.execute('INSERT INTO recurring_transactions (user_id, type, amount, category, frequency, start_date, end_date, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                   (1, 'expense', 100, 'Subscription', 'monthly', '2024-07-01', '2025-07-01', 'Streaming service'))
        # Add savings goal
        db.execute('INSERT INTO savings_goals (user_id, name, target_amount, current_amount, target_date, priority) VALUES (?, ?, ?, ?, ?, ?)',
                   (1, 'Vacation', 3000, 1000, '2024-12-31', 2))
        db.commit()

def test_budget_forecast_page(logged_in_client):
    """Test accessing the budget forecast page"""
    response = logged_in_client.get('/budget_forecast')
    assert response.status_code == 200
    assert b'Budget Forecast' in response.data

def test_generate_budget_forecast(logged_in_client):
    """Test generating a budget forecast"""
    add_test_financial_data(logged_in_client)
    response = logged_in_client.post('/budget_forecast', data={
        'forecast_months': '6',
        'initial_balance': '1000',
        'monthly_income': '5000',
        'monthly_expenses': '3000',
        'income_change': '2',
        'expense_change': '1',
        'savings_goal': '500',
        'interest_rate': '1'
    })
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'labels' in data
    assert 'projected_balance' in data
    assert 'projected_income' in data
    assert 'projected_expenses' in data
    assert 'projected_savings' in data
    assert len(data['labels']) == 6  # 6 months forecast

# ============================================================================
# Recurring Transactions Management Routes
# ============================================================================


def add_recurring_transaction(user_id, transaction_type, amount, category, frequency, start_date, end_date, description):
    """
    Helper function to add a recurring transaction to the database.
    
    Args:
    user_id (int): The ID of the user associated with the transaction.
    transaction_type (str): The type of transaction ('income' or 'expense').
    amount (float): The amount of the transaction.
    category (str): The category of the transaction.
    frequency (str): The frequency of the transaction (e.g., 'daily', 'weekly', 'monthly', 'yearly').
    start_date (str): The start date of the transaction in 'YYYY-MM-DD' format.
    end_date (str): The end date of the transaction in 'YYYY-MM-DD' format, or None if it's ongoing.
    description (str): A description of the transaction.
    
    Returns:
    int: The ID of the newly created recurring transaction.
    """
    with app.app_context():
        db = get_db(app)
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO recurring_transactions 
            (user_id, type, amount, category, frequency, start_date, end_date, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, transaction_type, amount, category, frequency, start_date, end_date, description))
        db.commit()
        return cursor.lastrowid

def remove_recurring_transaction(transaction_id=None, user_id=None):
    """
    Helper function to remove recurring transaction(s) from the database.
    
    Args:
    transaction_id (int, optional): The ID of the specific transaction to remove.
    user_id (int, optional): The ID of the user whose transactions should be removed.
    
    If both transaction_id and user_id are provided, it will remove the specific transaction for that user.
    If only transaction_id is provided, it will remove that specific transaction.
    If only user_id is provided, it will remove all transactions for that user.
    If neither is provided, it will raise a ValueError.
    
    Returns:
    int: The number of transactions removed.
    """
    with app.app_context():
        db = get_db(app)
        if transaction_id and user_id:
            db.execute('DELETE FROM recurring_transactions WHERE id = ? AND user_id = ?', (transaction_id, user_id))
        elif transaction_id:
            db.execute('DELETE FROM recurring_transactions WHERE id = ?', (transaction_id,))
        elif user_id:
            db.execute('DELETE FROM recurring_transactions WHERE user_id = ?', (user_id,))
        else:
            raise ValueError("Either transaction_id or user_id must be provided")
        
        removed_count = db.total_changes
        db.commit()
        return removed_count

def test_recurring_transactions_page(logged_in_client):
    """Test accessing the recurring transactions page"""
    response = logged_in_client.get('/recurring_transactions')
    print(response.data)
    assert response.status_code == 200
    assert b'Recurring Transactions' in response.data

def test_add_recurring_transaction_page(logged_in_client):
    """Test accessing the add recurring transaction page"""
    response = logged_in_client.get('/add_recurring_transaction')
    assert response.status_code == 200
    assert b'Add Recurring Transaction' in response.data

def test_add_recurring_transaction(logged_in_client):
    """Test adding a new recurring transaction"""
    response = logged_in_client.post('/add_recurring_transaction', data={
        'type': 'income',
        'amount': '500',
        'category': 'Freelance',
        'frequency': 'monthly',
        'start_date': '2024-08-01',
        'end_date': '2025-08-01',
        'description': 'Monthly freelance work'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Freelance' in response.data

def test_delete_recurring_transaction(logged_in_client):
    """Test deleting a recurring transaction"""

    with app.app_context():
        db = get_db(app)
        transaction = db.execute('SELECT id FROM recurring_transactions WHERE category = ?', ('Freelance',)).fetchone()
    
    response = logged_in_client.post(f'/delete_recurring_transaction/{transaction["id"]}', follow_redirects=True)
    print("trnx id", transaction['id'])
    assert response.status_code == 200
    assert b'Freelance' not in response.data
