import matplotlib
matplotlib.use('Agg')  # Use the 'Agg' backend
import matplotlib.pyplot as plt
from io import BytesIO, TextIOWrapper
import base64
from flask import Flask, render_template, request, redirect, url_for, flash, g, session, jsonify, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import csv
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATABASE = 'database.db'

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'bad_access'

# User model
class User(UserMixin):
    def __init__(self, user_id, fullname, username, email):
        self.id = user_id
        self.fullname = fullname
        self.username = username
        self.email = email

    def __repr__(self):
        return f"<User id={self.id}, fullname='{self.fullname}', username='{self.username}', email='{self.email}'>"

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        user_obj = User(user['id'], user['fullname'], user['username'], user['email'])
        return user_obj
    return None

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            script = f.read()
            if 'CREATE TABLE users' in script:
                # Check if the users table already exists
                table_exists = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
                if not table_exists:
                    db.executescript(script)
                    
                    # Check if the expenses table exists
                    expense_table_exists = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='expenses'").fetchone()
                    if not expense_table_exists:
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
                        # Add priority column if it doesn't exist
                        column_exists = db.execute("PRAGMA table_info(savings_goals)").fetchall()
                        if 'priority' not in [column[1] for column in column_exists]:
                            db.execute('ALTER TABLE savings_goals ADD COLUMN priority INTEGER DEFAULT 3')
                    db.commit()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def clear_flashes():
    session.pop('_flashes', None)

@app.route('/')
def home():
    clear_flashes()
    return render_template('homepage.html')

# user auth
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    referrer = request.referrer if request.referrer else 'None'
    if referrer.split('/')[-1] != 'signup':
        clear_flashes()

    if request.method == 'POST':
        fullname = request.form['fullname']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

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
        existing_user = db.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email)).fetchone()

        if existing_user:
            flash('Username or email already exists')
            return render_template('signup.html', fullname=fullname, email=email)

        password_hash = generate_password_hash(password)
        db.execute('INSERT INTO users (fullname, username, email, password) VALUES (?, ?, ?, ?)', (fullname, username, email, password_hash))
        db.commit()

        # Log in the user
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        user_obj = User(user['id'], user['fullname'], user['username'], user['email'])
        login_user(user_obj)

        return redirect(url_for('security_questions'))

    return render_template('signup.html')

@app.route('/security_questions', methods=['GET', 'POST'])
def security_questions():
    if request.method == 'POST':
        security_question_1 = request.form['security_question_1']
        security_answer_1 = request.form['security_answer_1']
        security_question_2 = request.form['security_question_2']
        security_answer_2 = request.form['security_answer_2']

        if security_question_1 == security_question_2:
            print("security questions are same")
            flash('Please select different security questions')
            return redirect(url_for('security_questions'))

        hashed_answer_1 = generate_password_hash(security_answer_1)
        hashed_answer_2 = generate_password_hash(security_answer_2)

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
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

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
    if request.method == 'POST':
        security_answer_1 = request.form['security_answer_1']
        security_answer_2 = request.form['security_answer_2']

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()

        if not check_password_hash(user['security_answer_1'], security_answer_1) or \
           not check_password_hash(user['security_answer_2'], security_answer_2):
            flash('Incorrect security answers')
            return redirect(url_for('security_answers'))

        return redirect(url_for('reset_password'))

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()
    security_question_1 = user['security_question_1']
    security_question_2 = user['security_question_2']

    return render_template('security_answers.html', security_question_1=security_question_1, security_question_2=security_question_2)

@app.route('/login', methods=['GET', 'POST'])
def login():
    referrer = request.referrer if request.referrer else 'None'
    if referrer.split('/')[-1] not in ['signup', 'login']:
        clear_flashes()
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user:
            if user['is_locked']:
                lockout_time = datetime.strptime(user['lockout_time'], '%Y-%m-%d %H:%M:%S')
                current_time = datetime.now()
                remaining_time = lockout_time + timedelta(minutes=30) - current_time
                if remaining_time.total_seconds() > 0:
                    minutes, seconds = divmod(int(remaining_time.total_seconds()), 60)
                    flash(f"Account locked. Try again in {minutes:02d}m:{seconds:02d}s")
                    return redirect(url_for('login'))
                else:
                    db.execute('UPDATE users SET is_locked = 0, incorrect_attempts = 0, lockout_time = NULL WHERE id = ?', (user['id'],))
                    db.commit()

            if check_password_hash(user['password'], password):
                user_obj = User(user['id'], user['fullname'], user['username'], user['email'])
                login_user(user_obj)

                # Check if the user has set up security questions
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
    logout_user()
    return redirect(url_for('home'))

@app.route('/bad_access')
def bad_access():
    return redirect(url_for('login'))

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    if request.method == 'POST':
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
    if request.method == 'POST':
        date = request.form['date']
        category = request.form['category']
        amount = float(request.form['amount'])
        description = request.form['description']
        frequency = request.form.get('frequency', 'one-time')  # Default to 'one-time' if not provided

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
    db = get_db()
    expenses = db.execute('SELECT * FROM expenses WHERE user_id = ? ORDER BY date DESC', (current_user.id,)).fetchall()
    return render_template('expenses.html', expenses=expenses)

@app.route('/income')
@login_required
def view_income():
    db = get_db()
    incomes = db.execute('SELECT * FROM incomes WHERE user_id = ? ORDER BY date DESC', (current_user.id,)).fetchall()
    return render_template('income.html', incomes=incomes)

# Routes for Savings Goals
@app.route('/savings_goals', methods=['GET'])
@login_required
def savings_goals():
    db = get_db()
    goals_data = db.execute('SELECT * FROM savings_goals WHERE user_id = ? ORDER BY priority, target_date', (current_user.id,)).fetchall()
    
    goals = []
    for goal in goals_data:
        goal_dict = dict(goal)
        goal_dict['progress'] = (goal_dict['current_amount'] / goal_dict['target_amount']) * 100 if goal_dict['target_amount'] > 0 else 0
        goal_dict['progress'] = round(goal_dict['progress'], 2)
        goals.append(goal_dict)
    
    return render_template('savings_goals.html', savings_goals=goals)


@app.route('/add_savings_goal', methods=['POST'])
@login_required
def add_savings_goal():
    goal_name = request.form['goal_name']
    target_amount = float(request.form['target_amount'])
    target_date = request.form['target_date']
    priority = int(request.form['priority'])

    if target_amount <= 0:
        flash('Target amount must be greater than zero')
        return redirect(url_for('savings_goals'))

    if datetime.strptime(target_date, '%Y-%m-%d').date() < datetime.now().date():
        flash('Target date must be in the future')
        return redirect(url_for('savings_goals'))

    if priority < 1 or priority > 5:
        flash('Priority must be between 1 and 5')
        return redirect(url_for('savings_goals'))

    db = get_db()
    db.execute('INSERT INTO savings_goals (user_id, name, target_amount, current_amount, target_date, priority) VALUES (?, ?, ?, 0, ?, ?)',
               (current_user.id, goal_name, target_amount, target_date, priority))
    db.commit()

    recalculate_savings_goals(current_user.id)

    flash('Savings goal added successfully')
    return redirect(url_for('savings_goals'))

def recalculate_savings_goals(user_id):
    db = get_db()
    
    total_income = db.execute('SELECT SUM(amount) as total FROM incomes WHERE user_id = ?', (user_id,)).fetchone()['total'] or 0
    total_expenses = db.execute('SELECT SUM(amount) as total FROM expenses WHERE user_id = ?', (user_id,)).fetchone()['total'] or 0
    
    available_amount = total_income - total_expenses
    
    goals = db.execute('SELECT * FROM savings_goals WHERE user_id = ? ORDER BY priority, target_date', (user_id,)).fetchall()
    
    if available_amount > 0:
        # Calculate total weighted target amount
        total_weighted_target = sum(goal['target_amount'] * (6 - goal['priority']) for goal in goals)
        
        for goal in goals:
            # Calculate the weighted percentage this goal contributes to the total
            weight = 6 - goal['priority']  # Invert priority so that 1 has the highest weight
            goal_percentage = (goal['target_amount'] * weight) / total_weighted_target if total_weighted_target > 0 else 0
            
            # Calculate the amount to allocate to this goal
            amount_to_allocate = available_amount * goal_percentage
            
            # Update the current amount, ensuring it doesn't exceed the target
            new_amount = min(amount_to_allocate, goal['target_amount'])
            
            # Update the database
            db.execute('UPDATE savings_goals SET current_amount = ? WHERE id = ?', (new_amount, goal['id']))
            
            if new_amount == goal['target_amount']:
                flash(f"Congratulations! You've achieved your savings goal: {goal['name']}")
    else:
        # If available amount is negative or zero, reset all goals to zero
        db.execute('UPDATE savings_goals SET current_amount = 0 WHERE user_id = ?', (user_id,))
    
    db.commit()

# report routes
@app.route('/get_report', methods=['GET', 'POST'])
@login_required
def get_report():
    if request.method == 'POST':
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        report_type = request.form['report_type']
        
        # Generate report data
        report_data = generate_report_data(current_user.id, start_date, end_date, report_type)
        
        # Generate charts
        income_chart = generate_chart(report_data['income_by_category'], 'Income by Category')
        expense_chart = generate_chart(report_data['expenses_by_category'], 'Expenses by Category')
        
        return render_template('report.html', 
                               report_data=report_data, 
                               income_chart=income_chart, 
                               expense_chart=expense_chart,
                               start_date=start_date,
                               end_date=end_date,
                               report_type=report_type,
                               is_pdf=False)
    
    return render_template('get_report.html')

@app.route('/export_report/<format>', methods=['POST'])
@login_required
def export_report(format):
    start_date = request.form['start_date']
    end_date = request.form['end_date']
    report_type = request.form['report_type']
    
    # Generate report data
    report_data = generate_report_data(current_user.id, start_date, end_date, report_type)
    
    if format == 'pdf':
        try:
            # Generate charts
            income_chart = generate_chart(report_data['income_by_category'], 'Income by Category')
            expense_chart = generate_chart(report_data['expenses_by_category'], 'Expenses by Category')
            
            # Generate PDF
            pdf_buffer = generate_pdf_report(report_data, start_date, end_date, report_type, income_chart, expense_chart)
            
            return send_file(
                pdf_buffer,
                as_attachment=True,
                download_name='financial_report.pdf',
                mimetype='application/pdf'
            )
        except Exception as e:
            app.logger.error(f"Error generating PDF report: {str(e)}")
            flash('An error occurred while generating the PDF report. Please try again.', 'error')
            return redirect(url_for('generate_report'))
        
    elif format == 'csv':
        try:
            # Generate CSV
            csv_buffer = generate_csv_report(report_data)
            
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
    db = get_db()
    
    income_data = db.execute('''
        SELECT category, SUM(amount) as total
        FROM incomes
        WHERE user_id = ? AND date BETWEEN ? AND ?
        GROUP BY category
    ''', (user_id, start_date, end_date)).fetchall()
    
    expense_data = db.execute('''
        SELECT category, SUM(amount) as total
        FROM expenses
        WHERE user_id = ? AND date BETWEEN ? AND ?
        GROUP BY category
    ''', (user_id, start_date, end_date)).fetchall()
    
    savings_data = db.execute('''
        SELECT name, current_amount, target_amount
        FROM savings_goals
        WHERE user_id = ?
    ''', (user_id,)).fetchall()
    
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
    plt.figure(figsize=(10, 6))
    plt.pie(list(data.values()), labels=list(data.keys()), autopct='%1.1f%%')
    plt.title(title)
    
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    
    graphic = base64.b64encode(image_png).decode('utf-8')
    plt.close()  # Close the figure to free up memory
    return graphic

def generate_pdf_report(report_data, start_date, end_date, report_type, income_chart, expense_chart):
    font_config = FontConfiguration()
    html_content = render_template(
        'report.html',
        report_data=report_data,
        start_date=start_date,
        end_date=end_date,
        report_type=report_type,
        income_chart=income_chart,
        expense_chart=expense_chart,
        is_pdf=True
    )
    
    css = CSS(string='''
        @page {
            size: letter;
            margin: 1cm;
        }
        @media print {
            .container {
                margin: 0;
                max-width: none;
            }
        }
    ''', font_config=font_config)
    
    pdf_file = HTML(string=html_content, base_url=request.url_root).write_pdf(stylesheets=[css], font_config=font_config)
    
    return BytesIO(pdf_file)

def generate_csv_report(report_data):
    buffer = BytesIO()
    text_wrapper = TextIOWrapper(buffer, encoding='utf-8-sig', write_through=True)
    writer = csv.writer(text_wrapper, dialect='excel', quoting=csv.QUOTE_MINIMAL)

    writer.writerow(['Income by Category'])
    writer.writerow(['Category', 'Amount'])
    for category, amount in report_data['income_by_category'].items():
        writer.writerow([category, f"${amount:.2f}"])

    writer.writerow([])
    writer.writerow(['Expenses by Category'])
    writer.writerow(['Category', 'Amount'])
    for category, amount in report_data['expenses_by_category'].items():
        writer.writerow([category, f"${amount:.2f}"])

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

    writer.writerow([])
    writer.writerow(['Summary'])
    writer.writerow(['Total Income', f"${report_data['total_income']:.2f}"])
    writer.writerow(['Total Expenses', f"${report_data['total_expenses']:.2f}"])
    writer.writerow(['Net Savings', f"${(report_data['total_income'] - report_data['total_expenses']):.2f}"])

    text_wrapper.detach()  # Prevent closing of BytesIO when TextIOWrapper is garbage collected
    buffer.seek(0)
    return buffer

if __name__ == '__main__':
    init_db()
    app.run(debug=True)