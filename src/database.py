import sqlite3
from flask import g

# Define the database file path
DATABASE = 'database.db'

def init_db(app):
    """Initialize the database with all the tables"""
    with app.app_context():
        db = get_db(app)
        with app.open_resource('src/schema.sql', mode='r') as f:
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

def get_db(app):
    """Gets database connection"""
    # Retrieve the database connection from the global object
    db = getattr(g, '_database', None)
    if db is None:
        # Create a new database connection if one doesn't exist
        db = g._database = sqlite3.connect(DATABASE)
        # Set the row factory to return dict-like objects
        db.row_factory = sqlite3.Row
    return db

