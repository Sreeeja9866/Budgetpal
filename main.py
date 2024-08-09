# ============================================================================
# Initial setup
# ============================================================================

# Import necessary libraries
import os
import csv
import base64
import sqlite3
import matplotlib
matplotlib.use('Agg')  # Set the backend to Agg for non-interactive environments
import matplotlib.pyplot as plt
from io import BytesIO, TextIOWrapper
from flask import Flask, render_template, request, redirect, url_for, flash, g, session, jsonify, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
# from weasyprint import HTML, CSS
# from weasyprint.text.fonts import FontConfiguration
import heapq

# Initialize Flask application
app = Flask(__name__)

# Set a secret key for the application
# This is used for securely signing the session cookie and can be used for other security-related needs
app.secret_key = 'your_secret_key'

# Define the database file path
DATABASE = 'database.db'

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)  # Connect LoginManager to the Flask app
login_manager.login_view = 'bad_access'  # Set the view to redirect to if login is required

# ============================================================================
# User Model and Authentication
# ============================================================================

# User model
class User(UserMixin):
    """User model for Flask-Login"""
    def __init__(self, user_id, fullname, username, email):
        self.id = user_id
        self.fullname = fullname
        self.username = username
        self.email = email

    def __repr__(self):
        return f"<User id={self.id}, fullname='{self.fullname}', username='{self.username}', email='{self.email}'>"

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        user_obj = User(user['id'], user['fullname'], user['username'], user['email'])
        return user_obj
    return None

# ============================================================================
# Savings Goal and Priority Queue
# ============================================================================

# SavingsGoal class for priority queue
class SavingsGoal:
    def __init__(self, id, name, target_amount, current_amount, target_date, priority):
        self.id = id
        self.name = name
        self.target_amount = target_amount
        self.current_amount = current_amount
        self.target_date = datetime.strptime(target_date, '%Y-%m-%d').date() if isinstance(target_date, str) else target_date
        self.priority = priority

    def __lt__(self, other):
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.target_date < other.target_date

class SavingsGoalPriorityQueue:
    def __init__(self):
        self.queue = []

    def add_goal(self, goal):
        heapq.heappush(self.queue, goal)

    def get_highest_priority_goal(self):
        return heapq.heappop(self.queue) if self.queue else None

    def peek_highest_priority_goal(self):
        return self.queue[0] if self.queue else None

    def update_goal(self, goal):
        self.queue = [g for g in self.queue if g.id != goal.id]
        heapq.heapify(self.queue)
        heapq.heappush(self.queue, goal)

    def get_all_goals(self):
        return sorted(self.queue)

    def clear(self):
        self.queue.clear()

# Global priority queue
savings_goal_pq = SavingsGoalPriorityQueue()

# ============================================================================
# Database Initialization and Management
# ============================================================================

def init_db():
    """Initialize the database with all the tables"""
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            script = f.read()
            if 'CREATE TABLE users' in script:
                # Check if the users table already exists
                table_exists = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
                if not table_exists:
                    # Execute the SQL script to create the users table
                    db.executescript(script)
                    
            # Check if the expenses table exists
            expense_table_exists = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='expenses'").fetchone()
            if not expense_table_exists:
                # Create the expenses table if it doesn't exist
                db.execute('''
                    CREATE TABLE expenses (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        date DATE,
                        category TEXT,
                        amount DECIMAL(10, 2),
                        description TEXT,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')
            
            # Check if the incomes table exists
            income_table_exists = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='incomes'").fetchone()
            if not income_table_exists:
                # Create the incomes table if it doesn't exist
                db.execute('''
                    CREATE TABLE incomes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        date DATE,
                        category TEXT,
                        amount DECIMAL(10, 2),
                        description TEXT,
                        frequency TEXT,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')
            
            # Check if the savings_goals table exists
            savings_goals_table_exists = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='savings_goals'").fetchone()
            if not savings_goals_table_exists:
                # Create the savings_goals table if it doesn't exist
                db.execute('''
                    CREATE TABLE savings_goals (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        name TEXT,
                        target_amount DECIMAL(10, 2),
                        current_amount DECIMAL(10, 2),
                        target_date DATE,
                        priority INTEGER,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')
            else:
                # Check if the priority column exists in the savings_goals table
                column_exists = db.execute("PRAGMA table_info(savings_goals)").fetchall()
                if 'priority' not in [column[1] for column in column_exists]:
                    # Add the priority column if it doesn't exist
                    db.execute('ALTER TABLE savings_goals ADD COLUMN priority INTEGER DEFAULT 3')

            # Check if the recurring_transactions table exists
            recurring_transactions_table_exists = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='recurring_transactions'").fetchone()
            if not recurring_transactions_table_exists:
                # Create the recurring_transactions table if it doesn't exist
                db.execute('''
                    CREATE TABLE recurring_transactions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        type TEXT,
                        amount DECIMAL(10, 2),
                        category TEXT,
                        frequency TEXT,
                        start_date DATE,
                        end_date DATE,
                        description TEXT,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')


            # Commit all changes to the database
            db.commit()

def get_db():
    """Gets database connection"""
    # Retrieve the database connection from the global object
    db = getattr(g, '_database', None)
    if db is None:
        # Create a new database connection if one doesn't exist
        db = g._database = sqlite3.connect(DATABASE)
        # Set the row factory to return dict-like objects
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Close database connection at the end of the request"""
    # Retrieve the database connection from the global object
    db = getattr(g, '_database', None)
    if db is not None:
        # Close the database connection
        db.close()

def clear_flashes():
    """Clear flash messages from the session"""
    # Remove flash messages from the session
    session.pop('_flashes', None)

# ============================================================================
# User Authentication and Management Routes
# ============================================================================

@app.route('/')
def home():
    """renders homepage"""
    # Clear any existing flash messages
    clear_flashes()
    return render_template('homepage.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handles user signup and rendering"""
    # Clear flashes if not coming from signup page
    referrer = request.referrer if request.referrer else 'None'
    if referrer.split('/')[-1] != 'signup':
        clear_flashes()

    if request.method == 'POST':
        # Retrieve form data
        fullname = request.form['fullname']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Password validation
        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('signup.html', fullname=fullname, username=username, email=email)

        # Check password complexity
        if len(password) < 8:
            flash('Password must be at least 8 characters long')
            return render_template('signup.html', fullname=fullname, username=username, email=email)
        if not any(char.isupper() for char in password):
            flash('Password must contain at least one uppercase letter')
            return render_template('signup.html', fullname=fullname, username=username, email=email)
        if not any(char.islower() for char in password):
            flash('Password must contain at least one lowercase letter')
            return render_template('signup.html', fullname=fullname, username=username, email=email)
        if not any(char.isdigit() for char in password):
            flash('Password must contain at least one digit')
            return render_template('signup.html', fullname=fullname, username=username, email=email)

        db = get_db()
        # Check if username or email already exists
        existing_user = db.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email)).fetchone()

        if existing_user:
            flash('Username or email already exists')
            return render_template('signup.html', fullname=fullname, email=email)

        # Hash password and insert new user into database
        password_hash = generate_password_hash(password)
        db.execute('INSERT INTO users (fullname, username, email, password) VALUES (?, ?, ?, ?)', (fullname, username, email, password_hash))
        db.commit()

        # Log in the new user
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        user_obj = User(user['id'], user['fullname'], user['username'], user['email'])
        login_user(user_obj)

        return redirect(url_for('security_questions'))

    return render_template('signup.html')

@app.route('/security_questions', methods=['GET', 'POST'])
def security_questions():
    """Fetches security question answer during signup"""
    if request.method == 'POST':
        # Retrieve security questions and answers
        security_question_1 = request.form['security_question_1']
        security_answer_1 = request.form['security_answer_1']
        security_question_2 = request.form['security_question_2']
        security_answer_2 = request.form['security_answer_2']

        # Ensure security questions are different
        if security_question_1 == security_question_2:
            print("security questions are same")
            flash('Please select different security questions')
            return redirect(url_for('security_questions'))

        # Hash security answers
        hashed_answer_1 = generate_password_hash(security_answer_1)
        hashed_answer_2 = generate_password_hash(security_answer_2)

        # Update user's security questions and answers in the database
        db = get_db()
        db.execute('UPDATE users SET security_question_1 = ?, security_answer_1 = ?, security_question_2 = ?, security_answer_2 = ? WHERE id = ?',
                   (security_question_1, hashed_answer_1, security_question_2, hashed_answer_2, current_user.id))
        db.commit()

        flash('Security questions updated successfully')
        return redirect(url_for('home'))

    return render_template('security_questions.html')

@app.route('/reset_password', methods=['GET', 'POST'])
@login_required
def reset_password():
    """Handles password reset and rendering"""
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Validate new password
        if new_password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('reset_password'))

        # Check password complexity
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long')
            return redirect(url_for('reset_password'))
        if not any(char.isupper() for char in new_password):
            flash('Password must contain at least one uppercase letter')
            return redirect(url_for('reset_password'))
        if not any(char.islower() for char in new_password):
            flash('Password must contain at least one lowercase letter')
            return redirect(url_for('reset_password'))
        if not any(char.isdigit() for char in new_password):
            flash('Password must contain at least one digit')
            return redirect(url_for('reset_password'))

        # Update the password in the database
        hashed_password = generate_password_hash(new_password)
        db = get_db()
        db.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, current_user.id))
        db.commit()

        flash('Password reset successful')
        return redirect(url_for('home'))

    return render_template('reset_password.html')

@app.route('/security_answers', methods=['GET', 'POST'])
@login_required
def security_answers():
    """Fetches security question answers during password reset"""
    if request.method == 'POST':
        security_answer_1 = request.form['security_answer_1']
        security_answer_2 = request.form['security_answer_2']

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()

        # Verify security answers
        if not check_password_hash(user['security_answer_1'], security_answer_1) or \
           not check_password_hash(user['security_answer_2'], security_answer_2):
            flash('Incorrect security answers')
            return redirect(url_for('security_answers'))

        return redirect(url_for('reset_password'))

    # Fetch security questions for the current user
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()
    security_question_1 = user['security_question_1']
    security_question_2 = user['security_question_2']

    return render_template('security_answers.html', security_question_1=security_question_1, security_question_2=security_question_2)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login and rendering"""
    # Clear flashes if not coming from signup or login page
    referrer = request.referrer if request.referrer else 'None'
    if referrer.split('/')[-1] not in ['signup', 'login']:
        clear_flashes()
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user:
            # Check if account is locked
            if user['is_locked']:
                lockout_time = datetime.strptime(user['lockout_time'], '%Y-%m-%d %H:%M:%S')
                current_time = datetime.now()
                remaining_time = lockout_time + timedelta(minutes=30) - current_time
                if remaining_time.total_seconds() > 0:
                    minutes, seconds = divmod(int(remaining_time.total_seconds()), 60)
                    flash(f"Account locked. Try again in {minutes:02d}m:{seconds:02d}s")
                    return redirect(url_for('login'))
                else:
                    # Unlock account if lockout period has passed
                    db.execute('UPDATE users SET is_locked = 0, incorrect_attempts = 0, lockout_time = NULL WHERE id = ?', (user['id'],))
                    db.commit()

            # Verify password
            if check_password_hash(user['password'], password):
                user_obj = User(user['id'], user['fullname'], user['username'], user['email'])
                login_user(user_obj)

                # Check if security questions are set up
                if not user['security_question_1'] or not user['security_question_2']:
                    flash('Please set up security questions to proceed further')
                    return redirect(url_for('security_questions'))

                # Reset incorrect attempts on successful login
                db.execute('UPDATE users SET incorrect_attempts = 0 WHERE id = ?', (user['id'],))
                db.commit()

                flash('Login successful')
                return redirect(url_for('home'))
            else:
                # Increment incorrect attempts
                incorrect_attempts = user['incorrect_attempts'] + 1
                db.execute('UPDATE users SET incorrect_attempts = ? WHERE id = ?', (incorrect_attempts, user['id']))
                db.commit()

                remaining_attempts = 5 - incorrect_attempts
                if incorrect_attempts >= 5:
                    # Lock account after 5 incorrect attempts
                    lockout_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    db.execute('UPDATE users SET is_locked = 1, lockout_time = ? WHERE id = ?', (lockout_time, user['id']))
                    db.commit()
                    flash("Account locked due to too many incorrect attempts. Try again after 30 minutes.")
                else:
                    flash(f"Invalid password. {remaining_attempts} attempt(s) remaining.")
        else:
            flash('Invalid User')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Handles user logout and rendering"""
    # Log out the current user
    logout_user()
    return redirect(url_for('home'))

@app.route('/bad_access')
def bad_access():
    """Renders bad access page, if user tries to access unauthorized pages"""
    # Redirect to login page for unauthorized access
    return redirect(url_for('login'))

# ============================================================================
# Income and Expense Routes
# ============================================================================

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    """Function to add expense"""
    if request.method == 'POST':
        # Retrieve expense details from the form
        date = request.form['date']
        category = request.form['category']
        amount = float(request.form['amount'])
        description = request.form['description']
        
        # Get the current user's ID
        user_id = current_user.id
        
        # Save the expense to the database
        db = get_db()
        db.execute('INSERT INTO expenses (user_id, date, category, amount, description) VALUES (?, ?, ?, ?, ?)',
                   (user_id, date, category, amount, description))
        db.commit()
        
        # Recalculate savings goals progress
        recalculate_savings_goals(user_id)
        
        flash('Expense added successfully')
        return redirect(url_for('view_expenses'))
    
    return render_template('add_expense.html')

@app.route('/add_income', methods=['GET', 'POST'])
@login_required
def add_income():
    """Function to add income"""
    if request.method == 'POST':
        # Retrieve income details from the form
        date = request.form['date']
        category = request.form['category']
        amount = float(request.form['amount'])
        description = request.form['description']
        # Default to 'one-time' if frequency not provided
        frequency = request.form.get('frequency', 'one-time')  
        
        # Get the current user's ID
        user_id = current_user.id
        
        # Save the income to the database
        db = get_db()
        db.execute('INSERT INTO incomes (user_id, date, category, amount, description, frequency) VALUES (?, ?, ?, ?, ?, ?)',
                   (user_id, date, category, amount, description, frequency))
        db.commit()
        
        # Recalculate savings goals progress
        recalculate_savings_goals(user_id)
        
        flash('Income added successfully')
        return redirect(url_for('view_income'))
    
    return render_template('add_expense.html')

@app.route('/expenses')
@login_required
def view_expenses():
    """Function to view expense"""
    # Retrieve all expenses for the current user
    db = get_db()
    expenses = db.execute('SELECT * FROM expenses WHERE user_id = ? ORDER BY date DESC', (current_user.id,)).fetchall()
    return render_template('expenses.html', expenses=expenses)

@app.route('/income')
@login_required
def view_income():
    """Function to add income"""
    # Retrieve all income records for the current user
    db = get_db()
    incomes = db.execute('SELECT * FROM incomes WHERE user_id = ? ORDER BY date DESC', (current_user.id,)).fetchall()
    return render_template('income.html', incomes=incomes)

# ============================================================================
# Savings Goals Management Routes
# ============================================================================

def load_savings_goals():
    """Load savings goals from the database into the priority queue"""
    global savings_goal_pq
    savings_goal_pq.clear()  # Clear existing goals in the queue
    db = get_db()
    goals = db.execute('SELECT * FROM savings_goals WHERE user_id = ?', (current_user.id,)).fetchall()
    for goal in goals:
        new_goal = SavingsGoal(
            goal['id'], 
            goal['name'], 
            goal['target_amount'], 
            goal['current_amount'], 
            goal['target_date'], 
            goal['priority']
        )
        savings_goal_pq.add_goal(new_goal)

@app.route('/savings_goals', methods=['GET'])
@login_required
def savings_goals():
    """Display all savings goals for the current user."""
    load_savings_goals()  # Reload goals from DB
    goals = savings_goal_pq.get_all_goals()
    goals_data = []
    for goal in goals:
        progress = (goal.current_amount / goal.target_amount) * 100 if goal.target_amount > 0 else 0
        goals_data.append({
            'id': goal.id,
            'name': goal.name,
            'target_amount': goal.target_amount,
            'current_amount': goal.current_amount,
            'target_date': goal.target_date.strftime('%Y-%m-%d'),
            'priority': goal.priority,
            'progress': round(progress, 2)
        })
    return render_template('savings_goals.html', savings_goals=goals_data)

@app.route('/add_savings_goal', methods=['POST'])
@login_required
def add_savings_goal():
    """Add a new savings goal for the current user."""
    goal_name = request.form['goal_name']
    target_amount = float(request.form['target_amount'])
    target_date = request.form['target_date']
    priority = int(request.form['priority'])

    # Validate input
    if target_amount <= 0:
        flash('Target amount must be greater than zero')
        return redirect(url_for('savings_goals'))

    if datetime.strptime(target_date, '%Y-%m-%d').date() < datetime.now().date():
        flash('Target date must be in the future')
        return redirect(url_for('savings_goals'))

    if priority < 1 or priority > 5:
        flash('Priority must be between 1 and 5')
        return redirect(url_for('savings_goals'))

    # Add goal to database
    db = get_db()
    cursor = db.cursor()
    cursor.execute('INSERT INTO savings_goals (user_id, name, target_amount, current_amount, target_date, priority) VALUES (?, ?, ?, 0, ?, ?)',
                   (current_user.id, goal_name, target_amount, target_date, priority))
    goal_id = cursor.lastrowid
    db.commit()

    # Reload goals from DB (including the new one)
    load_savings_goals()

    flash('Savings goal added successfully')
    return redirect(url_for('savings_goals'))

def recalculate_savings_goals(user_id):
    """Recalculate progress for all savings goals based on income and expenses."""
    db = get_db()
    
    # Calculate total income and expenses
    total_income = db.execute('SELECT SUM(amount) as total FROM incomes WHERE user_id = ?', (user_id,)).fetchone()['total'] or 0
    total_expenses = db.execute('SELECT SUM(amount) as total FROM expenses WHERE user_id = ?', (user_id,)).fetchone()['total'] or 0
    
    available_amount = total_income - total_expenses
    
    goals = db.execute('SELECT * FROM savings_goals WHERE user_id = ?', (user_id,)).fetchall()
    
    if available_amount > 0:
        # Calculate total weighted target
        total_weighted_target = sum(goal['target_amount'] * (6 - goal['priority']) for goal in goals)
        
        for goal in goals:
            weight = 6 - goal['priority'] 
            goal_percentage = (goal['target_amount'] * weight) / total_weighted_target if total_weighted_target > 0 else 0
            
            amount_to_allocate = available_amount * goal_percentage
            
            new_amount = min(goal['current_amount'] + amount_to_allocate, goal['target_amount'])
            
            # Update goal in database
            db.execute('UPDATE savings_goals SET current_amount = ? WHERE id = ?', (new_amount, goal['id']))
            
            if new_amount == goal['target_amount']:
                flash(f"Congratulations! You've achieved your savings goal: {goal['name']}")
    else:
        # Reset all goals to zero if no available amount
        for goal in goals:
            db.execute('UPDATE savings_goals SET current_amount = 0 WHERE id = ?', (goal['id'],))
    
    db.commit()
    
    # Reload goals into priority queue after recalculation
    load_savings_goals()


@app.route('/update_savings_goal/<int:goal_id>', methods=['POST'])
@login_required
def update_savings_goal(goal_id):
    """Update an existing savings goal."""
    goal_name = request.form['goal_name']
    target_amount = float(request.form['target_amount'])
    current_amount = float(request.form['current_amount'])
    target_date = request.form['target_date']
    priority = int(request.form['priority'])

    # Update goal in database
    db = get_db()
    db.execute('UPDATE savings_goals SET name = ?, target_amount = ?, current_amount = ?, target_date = ?, priority = ? WHERE id = ? AND user_id = ?',
               (goal_name, target_amount, current_amount, target_date, priority, goal_id, current_user.id))
    db.commit()

    # Reload goals from DB
    load_savings_goals()

    flash('Savings goal updated successfully')
    return redirect(url_for('savings_goals'))

@app.route('/delete_savings_goal/<int:goal_id>', methods=['POST'])
@login_required
def delete_savings_goal(goal_id):
    """Delete a savings goal."""
    # Delete goal from database
    db = get_db()
    db.execute('DELETE FROM savings_goals WHERE id = ? AND user_id = ?', (goal_id, current_user.id))
    db.commit()

    # Reload goals from DB
    load_savings_goals()

    flash('Savings goal deleted successfully')
    return redirect(url_for('savings_goals'))

@app.route('/get_highest_priority_goal', methods=['GET'])
@login_required
def get_highest_priority_goal():
    """Get the highest priority savings goal."""
    load_savings_goals()  # Reload goals from DB
    goal = savings_goal_pq.peek_highest_priority_goal()
    if goal:
        return jsonify({
            'id': goal.id,
            'name': goal.name,
            'target_amount': goal.target_amount,
            'current_amount': goal.current_amount,
            'target_date': goal.target_date.strftime('%Y-%m-%d'),
            'priority': goal.priority
        })
    return jsonify({'message': 'No savings goals found'}), 404

# ============================================================================
# Financial Report Generation Routes and Functions
# ============================================================================

@app.route('/get_report', methods=['GET', 'POST'])
@login_required
def get_report():
    """Handle report generation requests."""
    if request.method == 'POST':
        # Extract report parameters from form
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        report_type = request.form['report_type']
        
        # Generate report data
        report_data = generate_report_data(current_user.id, start_date, end_date, report_type)
        
        # Generate charts
        income_chart = generate_chart(report_data['income_by_category'], 'Income by Category')
        expense_chart = generate_chart(report_data['expenses_by_category'], 'Expenses by Category')
        
        # Render report template
        return render_template('report.html', 
                               report_data=report_data, 
                               income_chart=income_chart, 
                               expense_chart=expense_chart,
                               start_date=start_date,
                               end_date=end_date,
                               report_type=report_type,
                               is_pdf=False)
    
    # If GET request, render the report form
    return render_template('get_report.html')

@app.route('/export_report/<format>', methods=['POST'])
@login_required
def export_report(format):
    """Export report in specified format (PDF or CSV)."""
    # Extract report parameters from form
    start_date = request.form['start_date']
    end_date = request.form['end_date']
    report_type = request.form['report_type']
    
    # Generate report data
    report_data = generate_report_data(current_user.id, start_date, end_date, report_type)
    
    if format == 'pdf':
        # try:
        #     # Generate charts for PDF
        #     income_chart = generate_chart(report_data['income_by_category'], 'Income by Category')
        #     expense_chart = generate_chart(report_data['expenses_by_category'], 'Expenses by Category')
            
        #     # Generate PDF
        #     pdf_buffer = generate_pdf_report(report_data, start_date, end_date, report_type, income_chart, expense_chart)
            
        #     # Send PDF file
        #     return send_file(
        #         pdf_buffer,
        #         as_attachment=True,
        #         download_name='financial_report.pdf',
        #         mimetype='application/pdf'
        #     )
        # except Exception as e:
        #     app.logger.error(f"Error generating PDF report: {str(e)}")
        #     flash('An error occurred while generating the PDF report. Please try again.', 'error')
        #     return redirect(url_for('generate_report'))
        pass
    elif format == 'csv':
        try:
            # Generate CSV
            csv_buffer = generate_csv_report(report_data)
            
            # Send CSV file
            return send_file(
                csv_buffer,
                as_attachment=True,
                download_name='financial_report.csv',
                mimetype='text/csv'
            )
        except Exception as e:
            app.logger.error(f"Error generating CSV report: {str(e)}")
            flash('An error occurred while generating the CSV report. Please try again.', 'error')
            return redirect(url_for('generate_report'))
    
    else:
        flash('Invalid export format', 'error')
        return redirect(url_for('generate_report'))
    
def generate_report_data(user_id, start_date, end_date, report_type):
    """Generate report data based on user's financial records."""
    db = get_db()
    
    # Fetch income data
    income_data = db.execute('''
        SELECT category, SUM(amount) as total
        FROM incomes
        WHERE user_id = ? AND date BETWEEN ? AND ?
        GROUP BY category
    ''', (user_id, start_date, end_date)).fetchall()
    
    # Fetch expense data
    expense_data = db.execute('''
        SELECT category, SUM(amount) as total
        FROM expenses
        WHERE user_id = ? AND date BETWEEN ? AND ?
        GROUP BY category
    ''', (user_id, start_date, end_date)).fetchall()
    
    # Fetch savings goals data
    savings_data = db.execute('''
        SELECT name, current_amount, target_amount
        FROM savings_goals
        WHERE user_id = ?
    ''', (user_id,)).fetchall()
    
    # Prepare and return report data
    return {
        'income_by_category': {row['category']: row['total'] for row in income_data},
        'expenses_by_category': {row['category']: row['total'] for row in expense_data},
        'savings_goals': [{
            'name': row['name'],
            'current_amount': row['current_amount'],
            'target_amount': row['target_amount'],
            'progress': (row['current_amount'] / row['target_amount']) * 100 if row['target_amount'] > 0 else 0
        } for row in savings_data],
        'total_income': sum(row['total'] for row in income_data),
        'total_expenses': sum(row['total'] for row in expense_data),
    }

def generate_chart(data, title):
    """Generate a pie chart for the given data."""
    plt.figure(figsize=(10, 6))
    plt.pie(list(data.values()), labels=list(data.keys()), autopct='%1.1f%%')
    plt.title(title)
    
    # Save chart to buffer
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    
    # Encode chart image to base64
    graphic = base64.b64encode(image_png).decode('utf-8')
    plt.close()  # Close the figure to free up memory
    return graphic

# def generate_pdf_report(report_data, start_date, end_date, report_type, income_chart, expense_chart):
#     """Generate a PDF report."""
#     font_config = FontConfiguration()
#     html_content = render_template(
#         'report.html',
#         report_data=report_data,
#         start_date=start_date,
#         end_date=end_date,
#         report_type=report_type,
#         income_chart=income_chart,
#         expense_chart=expense_chart,
#         is_pdf=True
#     )
    
#     # Define CSS for PDF
#     css = CSS(string='''
#         @page {
#             size: letter;
#             margin: 1cm;
#         }
#         @media print {
#             .container {
#                 margin: 0;
#                 max-width: none;
#             }
#         }
#         ''',
#         font_config=font_config)
    
#     # Generate PDF
#     pdf_file = HTML(string=html_content, base_url=request.url_root).write_pdf(stylesheets=[css], font_config=font_config)
    
#     return BytesIO(pdf_file)

def generate_csv_report(report_data):
    """Generate a CSV report."""
    buffer = BytesIO()
    text_wrapper = TextIOWrapper(buffer, encoding='utf-8-sig', write_through=True)
    writer = csv.writer(text_wrapper, dialect='excel', quoting=csv.QUOTE_MINIMAL)

    # Write income data
    writer.writerow(['Income by Category'])
    writer.writerow(['Category', 'Amount'])
    for category, amount in report_data['income_by_category'].items():
        writer.writerow([category, f"${amount:.2f}"])

    # Write expense data
    writer.writerow([])
    writer.writerow(['Expenses by Category'])
    writer.writerow(['Category', 'Amount'])
    for category, amount in report_data['expenses_by_category'].items():
        writer.writerow([category, f"${amount:.2f}"])

    # Write savings goals data
    writer.writerow([])
    writer.writerow(['Savings Goals'])
    writer.writerow(['Goal', 'Current Amount', 'Target Amount', 'Progress'])
    for goal in report_data['savings_goals']:
        writer.writerow([
            goal['name'],
            f"${goal['current_amount']:.2f}",
            f"${goal['target_amount']:.2f}",
            f"{goal['progress']:.2f}%"
        ])

    # Write summary
    writer.writerow([])
    writer.writerow(['Summary'])
    writer.writerow(['Total Income', f"${report_data['total_income']:.2f}"])
    writer.writerow(['Total Expenses', f"${report_data['total_expenses']:.2f}"])
    writer.writerow(['Net Savings', f"${(report_data['total_income'] - report_data['total_expenses']):.2f}"])

    text_wrapper.detach()  # Prevent closing of BytesIO when TextIOWrapper is garbage collected
    buffer.seek(0)
    return buffer

# ============================================================================
# Budget Forecast and Management Routes
# ============================================================================

@app.route('/budget_forecast', methods=['GET', 'POST'])
@login_required
def budget_forecast():
    """Handle budget forecast requests."""
    if request.method == 'POST':
        forecast_months = int(request.form['forecast_months'])
        
        # Get current user's financial data from the database
        db = get_db()
        total_income = db.execute('SELECT SUM(amount) as total FROM incomes WHERE user_id = ?', 
                                  (current_user.id,)).fetchone()['total'] or 0
        total_expenses = db.execute('SELECT SUM(amount) as total FROM expenses WHERE user_id = ?', 
                                    (current_user.id,)).fetchone()['total'] or 0
        current_balance = total_income - total_expenses

        current_monthly_income = db.execute('SELECT AVG(amount) as avg FROM incomes WHERE user_id = ?', 
                                            (current_user.id,)).fetchone()['avg'] or 0
        current_monthly_expenses = db.execute('SELECT AVG(amount) as avg FROM expenses WHERE user_id = ?', 
                                              (current_user.id,)).fetchone()['avg'] or 0

        # Use form data if provided, otherwise use current data
        initial_balance = float(request.form['initial_balance']) if request.form['initial_balance'] else current_balance
        monthly_income = float(request.form['monthly_income']) if request.form['monthly_income'] else current_monthly_income
        monthly_expenses = float(request.form['monthly_expenses']) if request.form['monthly_expenses'] else current_monthly_expenses
        income_change = float(request.form['income_change']) / 100 if request.form['income_change'] else 0
        expense_change = float(request.form['expense_change']) / 100 if request.form['expense_change'] else 0
        savings_goal = float(request.form['savings_goal']) if request.form['savings_goal'] else 0
        interest_rate = float(request.form['interest_rate']) / 100 / 12 if request.form['interest_rate'] else 0  # Convert annual rate to monthly

        # Get recurring transactions
        recurring_transactions = db.execute('''
            SELECT type, amount, frequency, start_date, end_date
            FROM recurring_transactions
            WHERE user_id = ?
        ''', (current_user.id,)).fetchall()

        # Convert SQLite3.Row objects to dictionaries and parse dates
        recurring_transactions = [dict(t) for t in recurring_transactions]
        for transaction in recurring_transactions:
            transaction['start_date'] = datetime.strptime(transaction['start_date'], '%Y-%m-%d').date()
            if transaction['end_date']:
                transaction['end_date'] = datetime.strptime(transaction['end_date'], '%Y-%m-%d').date()
            else:
                transaction['end_date'] = None

        # Initialize forecast data structures
        labels = []
        projected_balance = [initial_balance]
        projected_income = []
        projected_expenses = []
        projected_savings = []
        total_interest_earned = 0

        start_date = datetime.now().date()

        # Calculate forecast for each month
        for month in range(1, forecast_months + 1):
            labels.append(f'Month {month}')
            
            # Calculate base income and expenses for this month
            month_income = monthly_income * (1 + income_change) ** month
            month_expenses = monthly_expenses * (1 + expense_change) ** month
            
            # Add recurring transactions for this month
            current_date = start_date + timedelta(days=30*month)
            for transaction in recurring_transactions:
                if transaction['start_date'] <= current_date and (transaction['end_date'] is None or transaction['end_date'] >= current_date):
                    if transaction['frequency'] == 'monthly' or \
                       (transaction['frequency'] == 'quarterly' and month % 3 == 0) or \
                       (transaction['frequency'] == 'annually' and month % 12 == 0):
                        if transaction['type'] == 'income':
                            month_income += transaction['amount']
                        else:
                            month_expenses += transaction['amount']
            
            # Calculate savings (consider savings goal if set)
            month_savings = max(month_income - month_expenses, savings_goal)
            
            # Calculate interest earned this month
            interest_earned = projected_balance[-1] * interest_rate
            total_interest_earned += interest_earned
            
            # Calculate balance for this month
            month_balance = projected_balance[-1] + month_savings + interest_earned
            
            # Append calculated values to respective lists
            projected_income.append(month_income)
            projected_expenses.append(month_expenses)
            projected_savings.append(month_savings)
            projected_balance.append(month_balance)

        # Remove the initial balance from projected_balance
        projected_balance = projected_balance[1:]

        # Prepare forecast data for JSON response
        forecast_data = {
            'labels': labels,
            'projected_balance': projected_balance,
            'projected_income': projected_income,
            'projected_expenses': projected_expenses,
            'projected_savings': projected_savings,
            'total_projected_income': sum(projected_income),
            'total_projected_expenses': sum(projected_expenses),
            'total_projected_savings': sum(projected_savings),
            'total_interest_earned': total_interest_earned
        }

        return jsonify(forecast_data)

    # If GET request, render the budget forecast form
    return render_template('budget_forecast.html')

@app.route('/budget_management')
@login_required
def budget_management():
    """Handle budget management page requests."""
    db = get_db()
    
    # Fetch summary data for the current month
    current_date = datetime.now()
    start_of_month = current_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end_of_month = (start_of_month + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)

    # Get total income for the current month
    total_income = db.execute('''
        SELECT SUM(amount) as total
        FROM incomes
        WHERE user_id = ? AND date BETWEEN ? AND ?
    ''', (current_user.id, start_of_month, end_of_month)).fetchone()['total'] or 0

    # Get total expenses for the current month
    total_expenses = db.execute('''
        SELECT SUM(amount) as total
        FROM expenses
        WHERE user_id = ? AND date BETWEEN ? AND ?
    ''', (current_user.id, start_of_month, end_of_month)).fetchone()['total'] or 0

    # Get count of recurring transactions
    recurring_transactions = db.execute('''
        SELECT COUNT(*) as count
        FROM recurring_transactions
        WHERE user_id = ?
    ''', (current_user.id,)).fetchone()['count']

    # Get count of savings goals
    savings_goals = db.execute('''
        SELECT COUNT(*) as count
        FROM savings_goals
        WHERE user_id = ?
    ''', (current_user.id,)).fetchone()['count']

    # Prepare summary data
    summary = {
        'total_income': total_income,
        'total_expenses': total_expenses,
        'balance': total_income - total_expenses,
        'recurring_transactions': recurring_transactions,
        'savings_goals': savings_goals
    }

    return render_template('budget_management.html', summary=summary)

# ============================================================================
# Recurring Transactions Management Routes
# ============================================================================

@app.route('/recurring_transactions')
@login_required
def recurring_transactions():
    """Display all recurring transactions for the current user."""
    db = get_db()
    transactions = db.execute('''
        SELECT * FROM recurring_transactions 
        WHERE user_id = ? 
        ORDER BY start_date DESC
    ''', (current_user.id,)).fetchall()
    return render_template('recurring_transactions.html', transactions=transactions)

@app.route('/add_recurring_transaction', methods=['GET', 'POST'])
@login_required
def add_recurring_transaction():
    """Handle adding a new recurring transaction."""
    if request.method == 'POST':
        # Extract transaction details from form
        transaction_type = request.form['type']
        amount = float(request.form['amount'])
        category = request.form['category']
        frequency = request.form['frequency']
        start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d').date()
        end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d').date() if request.form['end_date'] else None
        description = request.form['description']

        db = get_db()
        try:
            # Insert new recurring transaction into database
            db.execute('''
                INSERT INTO recurring_transactions 
                (user_id, type, amount, category, frequency, start_date, end_date, description) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (current_user.id, transaction_type, amount, category, frequency, start_date, end_date, description))
            db.commit()
            flash('Recurring transaction added successfully', 'success')
            return redirect(url_for('recurring_transactions'))
        except Exception as e:
            flash(f'Error adding recurring transaction: {str(e)}', 'error')
    
    return render_template('add_recurring_transaction.html')

@app.route('/edit_recurring_transaction/<int:transaction_id>', methods=['GET', 'POST'])
@login_required
def edit_recurring_transaction(transaction_id):
    """Handle editing an existing recurring transaction."""
    db = get_db()
    # Fetch the transaction to be edited
    transaction = db.execute('SELECT * FROM recurring_transactions WHERE id = ? AND user_id = ?', 
                             (transaction_id, current_user.id)).fetchone()

    if not transaction:
        flash('Transaction not found', 'error')
        return redirect(url_for('recurring_transactions'))

    if request.method == 'POST':
        # Extract updated transaction details from form
        transaction_type = request.form['type']
        amount = float(request.form['amount'])
        category = request.form['category']
        frequency = request.form['frequency']
        start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d').date()
        end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d').date() if request.form['end_date'] else None
        description = request.form['description']

        try:
            # Update the recurring transaction in the database
            db.execute('''
                UPDATE recurring_transactions 
                SET type = ?, amount = ?, category = ?, frequency = ?, start_date = ?, end_date = ?, description = ?
                WHERE id = ? AND user_id = ?
            ''', (transaction_type, amount, category, frequency, start_date, end_date, description, transaction_id, current_user.id))
            db.commit()
            flash('Recurring transaction updated successfully', 'success')
            return redirect(url_for('recurring_transactions'))
        except Exception as e:
            flash(f'Error updating recurring transaction: {str(e)}', 'error')

    return render_template('edit_recurring_transaction.html', transaction=transaction)

@app.route('/delete_recurring_transaction/<int:transaction_id>', methods=['POST'])
@login_required
def delete_recurring_transaction(transaction_id):
    """Handle deleting a recurring transaction."""
    db = get_db()
    try:
        # Delete the recurring transaction from the database
        db.execute('DELETE FROM recurring_transactions WHERE id = ? AND user_id = ?', (transaction_id, current_user.id))
        db.commit()
        flash('Recurring transaction deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting recurring transaction: {str(e)}', 'error')
    return redirect(url_for('recurring_transactions'))

# ============================================================================
# Database Backup and Restore Functions
# ============================================================================

def backup_database():
    """Create a backup of the current database."""
    source = sqlite3.connect(DATABASE)
    backup_dir = 'backups'
    
    # Create backup directory if it doesn't exist
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    
    # Generate timestamp for unique backup file name
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(backup_dir, f'database_backup_{timestamp}.db')
    
    # Create backup
    destination = sqlite3.connect(backup_file)
    with source:
        source.backup(destination)
    
    # Close connections
    destination.close()
    source.close()
    
    # Maintain only the last 5 backups
    backups = sorted([f for f in os.listdir(backup_dir) if f.startswith('database_backup_') and f.endswith('.db')])
    while len(backups) > 5:
        os.remove(os.path.join(backup_dir, backups.pop(0)))
    
    print(f"Database backed up to {backup_file}")

def restore_from_backup():
    """Restore the database from the most recent backup."""
    backup_dir = 'backups'
    
    # Check if backup directory exists
    if not os.path.exists(backup_dir):
        print("No backups found.")
        return
    
    # Get list of backup files
    backups = [f for f in os.listdir(backup_dir) if f.startswith('database_backup_') and f.endswith('.db')]
    if not backups:
        print("No backups found.")
        return
    
    # Get the most recent backup
    latest_backup = max(backups)
    backup_file = os.path.join(backup_dir, latest_backup)
    
    # Restore from backup
    source = sqlite3.connect(backup_file)
    destination = sqlite3.connect(DATABASE)
    with source:
        source.backup(destination)
    
    # Close connections
    destination.close()
    source.close()
    
    print(f"Database restored from {backup_file}")

# Register the backup function to run when the application is about to exit
@app.teardown_appcontext
def backup_on_exit(exception):
    """Backup the database when the application context is torn down."""
    backup_database()

# Add a route for manual backup
@app.route('/backup', methods=['POST'])
@login_required
def manual_backup():
    """Handle manual backup requests."""
    backup_database()
    flash('Database backed up successfully', 'success')
    return redirect(url_for('budget_management'))

# Add a route for manual restore
@app.route('/restore', methods=['POST'])
@login_required
def manual_restore():
    """Handle manual restore requests."""
    restore_from_backup()
    flash('Database restored from the latest backup', 'success')
    return redirect(url_for('budget_management'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)