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
    users_table = pd.DataFrame(columns=['username', 'password', 'permissions'])
    users_table.to_excel(excel_file, index=False)


def get_user_permissions(username):
    user = users_table.loc[users_table['username'] == username]
    if not user.empty:
        permissions = user['permissions'].values[0]
        return permissions
    return None

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

        users_table = pd.read_excel(excel_file)
        existing_user = users_table.loc[users_table['username'] == username]
        if not existing_user.empty:
            flash('Username already exists.', 'error')
            return redirect('/register')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = pd.DataFrame({'username': [username], 'password': [hashed_password], 'permissions': ['']})
        users_table = users_table.append(new_user, ignore_index=True)
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

        users_table = pd.read_excel(excel_file)
        user = users_table.loc[users_table['username'] == username]

        if user.empty or not bcrypt.check_password_hash(user['password'].values[0], password):
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
        user_permissions = get_user_permissions(username)
        return render_template('landing.html', username=username, user_permissions=user_permissions)
    return redirect('/login')

# Route for user logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
