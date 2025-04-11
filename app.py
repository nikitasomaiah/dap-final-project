from flask import Flask, render_template, request, redirect, url_for, flash, g, jsonify
from flask_wtf.csrf import CSRFProtect
import sqlite3
import secrets
import time
import re
from flask_bcrypt  import bcrypt
import logging
import re

# Password policy requirements
MIN_PASSWORD_LENGTH = 8
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_DIGITS = True
REQUIRE_SPECIAL_CHARS = True
SPECIAL_CHARS_REGEX = r'[!@#$%^&*()-=_+`~[\]{}|;:,.<>?]'

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['WTF_CSRF_SECRET_KEY'] = secrets.token_hex(16)  # Set your CSRF secret key here
csrf = CSRFProtect(app)
app.config['DATABASE'] = 'database.db'


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bookings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                seat_number TEXT NOT NULL,
                total_amount REAL NOT NULL,
                movie_name TEXT NOT NULL,
                UNIQUE(seat_number)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS movies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price INTEGER NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        ''')

        db.commit()


@app.route('/')
def login_form():
    return render_template('login.html')


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        admin_user = request.form['username']
        admin_pass = request.form['password']
        
        admin_credentials = {'Admin': 'Password##'}
        
        if admin_user in admin_credentials and admin_pass == admin_credentials[admin_user]:
            return redirect(url_for('admin_page'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('login_form'))
    else:
        return render_template('admin_login.html')


@app.route('/login', methods=['POST'])
def login():
    uname = request.form['username']
    pwd = request.form['password']
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (uname,))
    user = cursor.fetchone()
    conn.close()
    if user and bcrypt.checkpw(pwd.encode('utf-8'), user['password']):
        return redirect(url_for('main_page'))
    else:
        flash('Invalid username or password', 'error')
        return redirect(url_for('login_form'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email address.', 'error')
            return redirect(url_for('register'))
        
        if not (username and email and password and confirm_password):
            flash('All fields are required.', 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))
        
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('register'))
          
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, hashed_password))
            conn.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login_form'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'error')
            return redirect(url_for('register'))
        finally:
            conn.close()
    
    return render_template('register.html')

def validate_password(password):
    # Check minimum length
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f'Password must be at least {MIN_PASSWORD_LENGTH} characters long.'

    # Check uppercase requirement
    if REQUIRE_UPPERCASE and not any(char.isupper() for char in password):
        return False, 'Password must contain at least one uppercase letter.'

    # Check lowercase requirement
    if REQUIRE_LOWERCASE and not any(char.islower() for char in password):
        return False, 'Password must contain at least one lowercase letter.'

    # Check digits requirement
    if REQUIRE_DIGITS and not any(char.isdigit() for char in password):
        return False, 'Password must contain at least one digit.'

    # Check special characters requirement
    if REQUIRE_SPECIAL_CHARS and not re.search(SPECIAL_CHARS_REGEX, password):
        return False, 'Password must contain at least one special character.'

    # Password meets all requirements
    return True, 'Password is valid.'


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        uname = request.form.get('name')
        password = request.form.get('newPassword')
        confirm_password = request.form.get('confirmPassword')

        if not uname or not password or not confirm_password:
            flash('All fields are required.', 'error')
            return redirect(url_for('forgot_password'))

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('forgot_password'))
        
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('forgot_password'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        # Debugging: Log username and hashed_password
        logging.info(f"Username: {uname}, Hashed Password: {hashed_password}")
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (uname,))
        user_name = cursor.fetchone()
        if user_name is None:
          conn.close()
          flash('User not found.', 'error')
          # Debugging: Log user not found
          logging.info(f"User not found: {uname}")
          return render_template('forgot_password.html')
        else:
          cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, uname))
          conn.commit()
          flash('Password reset successfully!', 'success')
           # Debugging: Log successful password update
          logging.info(f"Password updated for user: {uname}")
          conn.close()
          return redirect(url_for('login_go'))
    return render_template('forgot_password.html')  

     
@app.route('/login_go')
def login_go():
    return render_template('login.html')



@app.route('/admin_page')
def admin_page():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT movie_name, GROUP_CONCAT(seat_number) AS booked_seats, COUNT(id) AS booked_seats_count FROM bookings GROUP BY movie_name')
    movie_bookings = cursor.fetchall()
    conn.close()
    return render_template('admin.html', movie_bookings=movie_bookings)


@app.route('/main')
def main():
    return render_template('main.html')


@app.route('/book_ticket', methods=['POST'])
def book_ticket():
    name = request.form['movie_name']
    price = request.form['price']
    if not name or not price:
        flash('All fields are required.', 'error')
        return redirect(url_for('main_page'))
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO movies (name, price) VALUES (?, ?)', (name, price))
        conn.commit()
        flash('Movie added successfully!')
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
    finally:
        conn.close()
    return redirect(url_for('seat'))


@app.route('/seat')
def seat():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM movies ORDER BY id DESC LIMIT 1')
    movie = cursor.fetchone()
    movie_name = movie['name']
    cursor.execute('SELECT seat_number FROM bookings WHERE movie_name = ?', (movie_name,))
    booked_seats = [row['seat_number'] for row in cursor.fetchall()]
    conn.close()
    return render_template('seat.html', movie=movie, booked_seats=booked_seats)


@app.route('/book_seat', methods=['POST'])
def book_seat():
    name = request.form['name']
    email = request.form['email']
    selected_seats = request.form.getlist('seats[]')
    movie_name = request.form.get('movie_name')
    if not name or not email or not selected_seats:
        flash('All fields are required.', 'error')
        return redirect(url_for('seat'))
    total_price = 0
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT price FROM movies ORDER BY id DESC LIMIT 1')
    result = cursor.fetchone()
    seat_price = result['price'] if result else 0
    total_price = seat_price * len(selected_seats)
    for seat in selected_seats:
        try:
            cursor.execute('INSERT INTO bookings (name, email, seat_number, total_amount, movie_name) VALUES (?, ?, ?, ?, ?)',
                           (name, email, seat, total_price, movie_name))
            conn.commit()
        except sqlite3.IntegrityError:
            flash(f'Seat {seat} is already booked.', 'error')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')
    conn.close()
    return redirect(url_for('payment_page'))


@app.route('/payment_page')
def payment_page():
    movie_names = []
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT name FROM movies ORDER BY id DESC LIMIT 1')
    result = cursor.fetchone()
    if result:
        movie_names.append(result[0])
    cursor.execute('SELECT total_amount FROM bookings ORDER BY id DESC LIMIT 1')
    latest_booking = cursor.fetchone()
    conn.close()
    if latest_booking:
        total_amount = latest_booking['total_amount']
    else:
        total_amount = 0
    return render_template('payment.html', total_amount=total_amount, movie_name=movie_names)


@app.route('/payment', methods=['POST'])
def payment():
    try:
        name = request.form['cardholder_name']
        cvv = request.form['cvv']
        card_no = request.form['card_number']
        expiry = request.form['expiry_date']
        return render_template('payment_confirmation.html')
    except KeyError as e:
        return f"Error: Missing form field {str(e)}", 400


@app.route('/confirmation_page')
def confirmation_page():
    return render_template('confirmation.html')


@app.route('/confirmation')
def confirmation():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM bookings ORDER BY id DESC LIMIT 1')
    latest_booking = cursor.fetchone()
    if latest_booking:
        name = latest_booking['name']
        email = latest_booking['email']
        total_amount = latest_booking['total_amount']
    cursor.execute('SELECT seat_number FROM bookings WHERE name = ?', (name,))
    bookings = cursor.fetchall()
    reserved_seats = [booking['seat_number'] for booking in bookings]
    cursor.execute('SELECT name FROM movies ORDER BY id DESC LIMIT 1')
    result = cursor.fetchone()
    movie_names = [result['name']] if result else []
    conn.close()
    return render_template('confirmation.html', name=name, email=email, movie_names=movie_names, seats=reserved_seats, total_amount=total_amount)


@app.route('/main_page')
def main_page():
    return render_template('main.html')


if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(port=9025)
