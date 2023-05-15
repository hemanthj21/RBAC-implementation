from flask import Flask, render_template, request, redirect, flash, session
from flask_bcrypt import Bcrypt
import pandas as pd
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

bcrypt = Bcrypt()

# Load the users data from Excel file or create a new file if it doesn't exist
excel_file = 'users.xlsx'
if not os.path.exists(excel_file):
    users_table = pd.DataFrame(columns=['username', 'password', 'role'])
    users_table.to_excel(excel_file, index=False)

users_table = pd.read_excel(excel_file)

roles = {
    'Admin': ['view_patients', 'add_patients', 'edit_patients', 'delete_patients'],
    'Doctor': ['view_patients', 'add_patients', 'edit_patients', 'view_reports', 'generate_reports'],
    'Nurse': ['view_patients', 'view_reports'],
    'Patient': ['view_own_reports'],
    'Staff': ['view_patients']
}

permissions = {
    'view_patients': 'View Patients',
    'add_patients': 'Add Patients',
    'edit_patients': 'Edit Patients',
    'delete_patients': 'Delete Patients',
    'view_reports': 'View Reports',
    'generate_reports': 'Generate Reports',
    'view_own_reports': 'View own Reports'
}

def get_user_role(username):
    user = users_table.loc[users_table['username'] == username]
    if not user.empty:
        return user['role'].values[0]
    return None

def get_permissions_for_role(role):
    if role in roles:
        return [permissions[permission] for permission in roles[role]]
    return []


# Route for the home page
@app.route('/')
def home():
    if 'username' in session:
        return redirect('/landing')
    return render_template('welcome.html')

# Route for user registration form
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')

        # Password complexity validation
        has_capital = any(char.isupper() for char in password)
        has_number = any(char.isdigit() for char in password)
        has_symbol = any(char in '-!$%^&*()_+|~=`{}[]:";\'<>?,./' for char in password)
        is_valid_password = len(password) >= 8 and has_capital and has_number and has_symbol

        if not is_valid_password:
            flash('Invalid password. Password must have at least one capital letter, one number, one symbol, and a minimum length of 8 characters.', 'error')
            return redirect('/register')

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect('/register')

        if not is_valid_password:
            flash(
                'Invalid password. Password must have at least one capital letter, one number, one symbol, and a minimum length of 8 characters.',
                'error')
            return redirect('/register')

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect('/register')

        users_table = pd.read_excel(excel_file)
        existing_user = users_table.loc[users_table['username'] == username]
        if not existing_user.empty:
            flash('Username already exists.', 'error')
            return redirect('/register')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = pd.DataFrame({'username': [username], 'password': [hashed_password], 'role': [role]})
        users_table = pd.concat([users_table, new_user])
        users_table.to_excel(excel_file, index=False)

        flash('Registration successful. You can now log in.', 'success')
        return redirect('/')

    return render_template('register.html')


# Route for user login form
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = users_table.loc[users_table['username'] == username]

        if user.empty:
            flash('Invalid username or password.', 'error')
            return redirect('/login')

        hashed_password = user['password'].values[0]
        if not bcrypt.check_password_hash(hashed_password, password):
            flash('Invalid username or password.', 'error')
            return redirect('/login')

        session['username'] = username
        return redirect('/landing')

    return render_template('login.html')


# Route for user landing page
@app.route('/landing')
def landing():
    if 'username' in session:
        username = session['username']
        user_role = get_user_role(username)
        user_permissions = get_permissions_for_role(user_role)
        return render_template('landing.html', username=username, user_permissions=user_permissions)

    return redirect('/')

# Route for user logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
