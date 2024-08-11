from flask_login import login_required
from flask import Blueprint, redirect, url_for, flash
from datetime import datetime
import sqlite3
import os

backup = Blueprint('backup', __name__)

# Define the database file path
DATABASE = 'database.db'

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

# Add a route for manual backup
@backup.route('/backup', methods=['POST'])
@login_required
def manual_backup():
    """Handle manual backup requests."""
    backup_database()
    flash('Database backed up successfully', 'success')
    return redirect(url_for('budget_management'))

# Add a route for manual restore
@backup.route('/restore', methods=['POST'])
@login_required
def manual_restore():
    """Handle manual restore requests."""
    restore_from_backup()
    flash('Database restored from the latest backup', 'success')
    return redirect(url_for('budget_management'))
