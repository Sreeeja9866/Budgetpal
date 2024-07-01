from flask import Flask, render_template, request, redirect, url_for, flash, g, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

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

if __name__ == '__main__':
    init_db()
    app.run(debug=True)