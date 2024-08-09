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
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, g
from flask_login import LoginManager, login_user, login_required, logout_user, current_user

from src.models import User, SavingsGoal, SavingsGoalPriorityQueue
from src.database import get_db, init_db, DATABASE
from src.authentication import auth
from src.backup import backup, backup_database
from src.reports import reports

# from weasyprint import HTML, CSS
# from weasyprint.text.fonts import FontConfiguration


# Initialize Flask application
app = Flask(__name__)

# Set a secret key for the application
# This is used for securely signing the session cookie and can be used for other security-related needs
app.secret_key = 'your_secret_key'
app.register_blueprint(auth)
app.register_blueprint(backup)
app.register_blueprint(reports)
# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)  # Connect LoginManager to the Flask app
login_manager.login_view = 'auth.bad_access'  # Set the view to redirect to if login is required

# ============================================================================
# loading users
# ============================================================================

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    db = get_db(app)
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        user_obj = User(user['id'], user['fullname'], user['username'], user['email'])
        return user_obj
    return None

# ============================================================================
# Initializing savings goal priority queue
# ============================================================================

# Global priority queue
savings_goal_pq = SavingsGoalPriorityQueue()

# ============================================================================
# Routes to close db connection and clear flashes
# ============================================================================

@app.teardown_appcontext
def close_connection(exception):
    """Close database connection at the end of the request"""
    # Retrieve the database connection from the global object
    db = getattr(g, '_database', None)
    if db is not None:
        # Close the database connection
        db.close()

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
        db = get_db(app)
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
        db = get_db(app)
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
    db = get_db(app)
    expenses = db.execute('SELECT * FROM expenses WHERE user_id = ? ORDER BY date DESC', (current_user.id,)).fetchall()
    return render_template('expenses.html', expenses=expenses)

@app.route('/income')
@login_required
def view_income():
    """Function to add income"""
    # Retrieve all income records for the current user
    db = get_db(app)
    incomes = db.execute('SELECT * FROM incomes WHERE user_id = ? ORDER BY date DESC', (current_user.id,)).fetchall()
    return render_template('income.html', incomes=incomes)

# ============================================================================
# Savings Goals Management Routes
# ============================================================================

def load_savings_goals():
    """Load savings goals from the database into the priority queue"""
    global savings_goal_pq
    savings_goal_pq.clear()  # Clear existing goals in the queue
    db = get_db(app)
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
    db = get_db(app)
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
    db = get_db(app)
    
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
    db = get_db(app)
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
    db = get_db(app)
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
# Budget Forecast and Management Routes
# ============================================================================

@app.route('/budget_forecast', methods=['GET', 'POST'])
@login_required
def budget_forecast():
    """Handle budget forecast requests."""
    if request.method == 'POST':
        forecast_months = int(request.form['forecast_months'])
        
        # Get current user's financial data from the database
        db = get_db(app)
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
    db = get_db(app)
    
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
    db = get_db(app)
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

        db = get_db(app)
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
    db = get_db(app)
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
    db = get_db(app)
    try:
        # Delete the recurring transaction from the database
        db.execute('DELETE FROM recurring_transactions WHERE id = ? AND user_id = ?', (transaction_id, current_user.id))
        db.commit()
        flash('Recurring transaction deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting recurring transaction: {str(e)}', 'error')
    return redirect(url_for('recurring_transactions'))

# ============================================================================
# Backing up database on exit
# ============================================================================

# Register the backup function to run when the application is about to exit
@app.teardown_appcontext
def backup_on_exit(exception):
    """Backup the database when the application context is torn down."""
    backup_database()

if __name__ == '__main__':
    init_db(app)
    app.run(debug=True)