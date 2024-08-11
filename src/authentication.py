from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask import Flask, Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, send_file, g
from src.models import User
from src.database import get_db
from datetime import datetime, timedelta

auth = Blueprint('auth', __name__)

def clear_flashes():
    """Clear flash messages from the session"""
    # Remove flash messages from the session
    session.pop('_flashes', None)

# ============================================================================
# User Authentication and Management Routes
# ============================================================================

@auth.route('/')
def home():
    """renders homepage"""
    # Clear any existing flash messages
    clear_flashes()
    return render_template('homepage.html')

@auth.route('/signup', methods=['GET', 'POST'])
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

        db = get_db(auth)
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

        return redirect(url_for('auth.security_questions'))

    return render_template('signup.html')

@auth.route('/security_questions', methods=['GET', 'POST'])
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
            return redirect(url_for('auth.security_questions'))

        # Hash security answers
        hashed_answer_1 = generate_password_hash(security_answer_1)
        hashed_answer_2 = generate_password_hash(security_answer_2)

        # Update user's security questions and answers in the database
        db = get_db(auth)
        db.execute('UPDATE users SET security_question_1 = ?, security_answer_1 = ?, security_question_2 = ?, security_answer_2 = ? WHERE id = ?',
                   (security_question_1, hashed_answer_1, security_question_2, hashed_answer_2, current_user.id))
        db.commit()

        flash('Security questions updated successfully')
        return redirect(url_for('auth.home'))

    return render_template('security_questions.html')

@auth.route('/reset_password', methods=['GET', 'POST'])
@login_required
def reset_password():
    """Handles password reset and rendering"""
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Validate new password
        if new_password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('auth.reset_password'))

        # Check password complexity
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long')
            return redirect(url_for('auth.reset_password'))
        if not any(char.isupper() for char in new_password):
            flash('Password must contain at least one uppercase letter')
            return redirect(url_for('auth.reset_password'))
        if not any(char.islower() for char in new_password):
            flash('Password must contain at least one lowercase letter')
            return redirect(url_for('auth.reset_password'))
        if not any(char.isdigit() for char in new_password):
            flash('Password must contain at least one digit')
            return redirect(url_for('auth.reset_password'))

        # Update the password in the database
        hashed_password = generate_password_hash(new_password)
        db = get_db(auth)
        db.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, current_user.id))
        db.commit()

        flash('Password reset successful')
        return redirect(url_for('auth.home'))

    return render_template('reset_password.html')

@auth.route('/security_answers', methods=['GET', 'POST'])
@login_required
def security_answers():
    """Fetches security question answers during password reset"""
    if request.method == 'POST':
        security_answer_1 = request.form['security_answer_1']
        security_answer_2 = request.form['security_answer_2']

        db = get_db(auth)
        user = db.execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()

        # Verify security answers
        if not check_password_hash(user['security_answer_1'], security_answer_1) or \
           not check_password_hash(user['security_answer_2'], security_answer_2):
            flash('Incorrect security answers')
            return redirect(url_for('auth.security_answers'))

        return redirect(url_for('auth.reset_password'))

    # Fetch security questions for the current user
    db = get_db(auth)
    user = db.execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()
    security_question_1 = user['security_question_1']
    security_question_2 = user['security_question_2']

    return render_template('security_answers.html', security_question_1=security_question_1, security_question_2=security_question_2)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login and rendering"""
    # Clear flashes if not coming from signup or login page
    referrer = request.referrer if request.referrer else 'None'
    if referrer.split('/')[-1] not in ['signup', 'login']:
        clear_flashes()
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db(auth)
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
                    return redirect(url_for('auth.login'))
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
                    return redirect(url_for('auth.security_questions'))

                # Reset incorrect attempts on successful login
                db.execute('UPDATE users SET incorrect_attempts = 0 WHERE id = ?', (user['id'],))
                db.commit()

                flash('Login successful')
                return redirect(url_for('auth.home'))
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

@auth.route('/logout')
@login_required
def logout():
    """Handles user logout and rendering"""
    # Log out the current user
    logout_user()
    return redirect(url_for('auth.home'))

@auth.route('/bad_access')
def bad_access():
    """Renders bad access page, if user tries to access unauthorized pages"""
    # Redirect to login page for unauthorized access
    return redirect(url_for('auth.login'))
