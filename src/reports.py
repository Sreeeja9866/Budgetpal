
import csv
import base64
import matplotlib
matplotlib.use('Agg')  # Set the backend to Agg for non-interactive environments
import matplotlib.pyplot as plt
from io import BytesIO, TextIOWrapper
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file
from flask_login import login_required, current_user
from src.database import get_db

reports = Blueprint('reports', __name__)

# ============================================================================
# Financial Report Generation Routes and Functions
# ============================================================================

@reports.route('/get_report', methods=['GET', 'POST'])
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

@reports.route('/export_report/<format>', methods=['POST'])
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
            reports.logger.error(f"Error generating CSV report: {str(e)}")
            flash('An error occurred while generating the CSV report. Please try again.', 'error')
            return redirect(url_for('reports.generate_report'))
    
    else:
        flash('Invalid export format', 'error')
        return redirect(url_for('reports.generate_report'))
    
def generate_report_data(user_id, start_date, end_date, report_type):
    """Generate report data based on user's financial records."""
    db = get_db(reports)
    
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
