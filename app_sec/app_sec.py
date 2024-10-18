from flask import Flask, render_template, request, redirect, url_for,jsonify,session
from markupsafe import escape
import sqlite3
from flask_bcrypt import Bcrypt
import re
import requests
import hashlib
import secrets
import pyotp
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__, static_folder="./static", template_folder="./templates")
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
app.debug = False

csrf.init_app(app)

# error handling
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(str(e))
    return render_template('error.html'), 500


# Generate a secure random secret key
app.secret_key = secrets.token_hex(16)

# Initialize database connection and cursor
connection = sqlite3.connect("detishop.db", check_same_thread=False)
cursor = connection.cursor()


# Allowed query values
allowed_q_values = {"index", "login", "signup", "shop", "checkout", "reviews", ""}
# Username must start with a letter and be at least 3 characters long
username_pattern = re.compile(r'^[a-zA-ZÀ-ÖØ-öø-ÿ0-9_ \'-]+$')
# List of reserved usernames
reserved_usernames = ["admin", "root", "system"]
# List of valid product names
product_names = ["black deti cup", "black deti mug", "black deti shirt", "deti cup", "deti mug", "deti shirt"]


# Validate the request method
@app.before_request
def validate_request_method():
    valid_methods = {'GET', 'POST'}
    if request.method not in valid_methods:
        # Log or alert about the invalid request method
        app.logger.warning(f"Invalid HTTP method: {request.method} for URL: {request.url}")
        return "Invalid request method", 405



# Content Security Policy header to all responses
@app.after_request
def add_csp_header(response):
    csp_policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'"
    response.headers["Content-Security-Policy"] = csp_policy
    return response
# X-Content-Type-Options header to all responses
def add_content_type_options_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
# Strict-Transport-Security header to all responses
def add_strict_transport_security_header(response):
    max_age_seconds = 15724800
    # Set the header with includeSubdomains directive
    response.headers['Strict-Transport-Security'] = f'max-age={max_age_seconds}; includeSubdomains'
    return response
# Referrer-Policy header to all responses
def add_referrer_policy_header(response):
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response


@app.route('/')
def index():
    if 'user_id' in session:
        # Get the 'q' query parameter
        q = request.args.get('q', '')
        # Sanitize and escape the 'q' parameter
        q = escape(q)
        return render_template('index.html', q=q)
    else:
        return render_template('index.html')


@app.route('/<path:invalid_path>')
def handle_invalid_path(invalid_path):
    q = request.args.get('q', '')
    if q not in allowed_q_values:
        return "Invalid query. This page does not exist."
    return f"This page does not exist: {invalid_path}"


MAX_LOGIN_ATTEMPTS = 3

# not vulnerable to SQL injection
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == "POST":
        username = request.form.get("username", False)
        password = request.form.get("password", False)
        totp_code = request.form.get("totp_code", False)

        connection = sqlite3.connect("detishop.db")
        cursor = connection.cursor()

        query = "SELECT username, password, login_attempts, totp_secret FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        if user:
            # Check if the user has totp enabled
            if user[3]:
                totp = pyotp.TOTP(user[3])
                if not totp.verify(totp.now()):
                    error_message = "Incorrect TOTP code. Please try again."
                    return render_template("login.html", error=error_message)
                
                
            if bcrypt.check_password_hash(user[1], password):
                # Reset login attempts on successful login
                cursor.execute("UPDATE users SET login_attempts = 0 WHERE username = ?", (username,))
                connection.commit()
                return render_template("logged_in.html")
            else:
                # Increment login attempts and lock account if necessary
                login_attempts = user[2] + 1
                if login_attempts >= MAX_LOGIN_ATTEMPTS:
                    error_message = "Account locked due to excessive login attempts. Please contact support."
                    cursor.execute("UPDATE users SET login_attempts = ? WHERE username = ?", (login_attempts, username))
                    connection.commit()
                else:
                    error_message = "Incorrect credentials. Please check your username and password and try again."
                    cursor.execute("UPDATE users SET login_attempts = ? WHERE username = ?", (login_attempts, username))
                    connection.commit()
                return render_template("login.html", error=error_message)

        else:
            error_message = "Incorrect credentials. Please check your username and password and try again."
            return render_template("login.html", error=error_message)

        connection.close()

    return render_template("login.html")


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        username = request.form.get("username", False)
        email = request.form.get("email", False)
        password = request.form.get("password", False)

        # Check if the password meets the minimum length requirement
        if len(password) < 12:
            error_message = "Password must be at least 12 characters long."
            return render_template("signup.html", error=error_message)
        if len(password) > 128:
            error_message = "Password must be at most 128 characters long."
            return render_template("signup.html", error=error_message)
        
        # password with double spaces convert to only one
        password = password.replace("  ", " ")

        hash_password_api = hashlib.sha1(password.encode()).hexdigest().upper()
        hash_prefix_api = hash_password_api[:5]
        hash_suffix_api = hash_password_api[5:]

        # Check if the password has been breached
        if is_password_breached(hash_prefix_api, hash_suffix_api):
            error_message = "This password has been compromised in a data breach. Choose a different one."
            return render_template("signup.html", error=error_message)


        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Generate a TOTP secret for the user
        totp_secret = pyotp.random_base32()

        query = "INSERT INTO users (username, email, password, totp_secret) VALUES (?, ?, ?, ?)"
        try:
            cursor.execute(query, (username, email, hashed_password, totp_secret))
            connection.commit()
            # Provide the TOTP secret to the user
            alert_message = f"Signup successful! Your TOTP code: {totp_secret}"
            #return render_template("login.html", totp_alert=totp_alert)
            return render_template("signup.html", alert_message=alert_message)
        
            #print("Signup successful")
            #return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            print("Email already exists. Try a different one.")

    return render_template("signup.html")

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Retrieve user information from the database
        user_id = session['user_id']
        cursor.execute("SELECT password FROM users WHERE user_id = ?", (user_id,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[0], current_password):
            # checks if new password and confirm password match
            if new_password == confirm_password:
                # security requirements
                if len(new_password) < 12:
                    error_message = "Password must be at least 12 characters long."
                elif len(new_password) > 128:
                    error_message = "Password must be at most 128 characters long."
                else:
                    # Hash the new password and update it in the database
                    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                    cursor.execute("UPDATE users SET password = ? WHERE user_id = ?", (hashed_password, user_id))
                    connection.commit()

                    return render_template("change_password.html", success_message="Password changed successfully.")
            else:
                error_message = "New password and confirm password do not match."
        else:
            error_message = "Incorrect current password."

        return render_template("change_password.html", error=error_message)

    return render_template("change_password.html")

@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/shop')
def shop():
    return render_template('shop.html')



@app.route('/checkout')
def checkout():
    return render_template('checkout.html')

# A dictionary of valid coupons with corresponding discounts
valid_coupons = {
    '20%OFF': 0.20,  # 20% discount
    'SAVE10': 0.10,  # 10% discount
    'RIC': 0.75,
    # Add more coupons and their respective discounts as needed
}

# Function to process the coupon code and calculate the discount
@app.route('/apply_coupon', methods=['POST'])
def apply_coupon():
    print("POST request received!")
    data = request.get_json()
    coupon_code = data.get('coupon')

    # Calculate the updated price
    updated_price = process_coupon(coupon_code)

    if updated_price is not None:
        return jsonify(message='Coupon applied!', updated_price=updated_price)
    else:
        return jsonify(message='Invalid coupon code'), 400


def process_coupon(coupon_code):
    # Check if the provided coupon code is in the valid_coupons dictionary
    if coupon_code in valid_coupons:
        # Calculate the discount based on the coupon code
        discount_percentage = valid_coupons[coupon_code]
        print("Discount percentage: ", discount_percentage)

        # Replace this with your actual price calculation logic
        original_price = calculate_original_price()
        print("Original price: ", original_price)

        # Calculate the updated price with the discount
        updated_price = original_price * (1 - discount_percentage)

        print("Updated price: ", updated_price)
        return updated_price
    else:
        # If the coupon code is not valid, return None
        return None


# Function to calculate the original price (replace with your actual logic)
def calculate_original_price():
    # Replace this with your logic to calculate the original price
    original_price = 750.99  # TODO: Fazer isto dinâmico
    return original_price


@app.route('/reviews')
def reviews():
    cursor.execute("SELECT * FROM reviews")
    rows = cursor.fetchall()

    # Create a list of dictionaries with named attributes
    reviews = []
    for row in rows:
        review = {
            'id': row[0],
            'user_name': row[1],
            'product_name': row[2],
            'review': row[3],
            'user_id': row[4],
            'timestamp': row[5]
        }
        reviews.append(review)

    return render_template('reviews.html', reviews=reviews)

@app.route('/submit_review', methods=['POST'])
def submit_review():
    if request.method == "POST":
        name = request.form.get("user_name")
        item = request.form.get("product_name")
        review_text = request.form.get("review")

        # Check if the name is valid
        if not username_pattern.match(name):
            return "Invalid username. Usernames must start with a letter and be at least 3 characters long."
        
        # Check if the name is in the list of reserved usernames
        if name.lower() in reserved_usernames:
            return "Invalid username. Please choose a different username."
        
        # Check if the product name is valid
        if item.lower() not in product_names:
            return "Invalid product name. Please choose a product sold in our shop."

        user_id = 1  # Replace with the actual user_id

        # Insert the review into the database
        cursor.execute("INSERT INTO reviews (user_name, product_name, review, user_id) VALUES (?, ?, ?, ?)", (name, item, review_text, user_id ))
        connection.commit()

        print("Review submitted successfully")
        return redirect(url_for("reviews"))
    
@app.route('/perform_operation', methods=['POST'])
def perform_operation():
    try:
        selected_number = int(request.form.get('number'))
        
        # Set a resource consumption limit
        resource_limit = 10 # Adjust based on your server's capacity

        if selected_number > resource_limit:
            return f"Selected number ({selected_number}) exceeds the resource limit ({resource_limit}). Please choose a smaller number."

        result = fibonacci(selected_number)
        return f"Fibonacci({selected_number}) = {result}"
    except ValueError:
        return "Invalid input. Please provide a valid number."

def fibonacci(n):
    if n <= 1:
        return n
    else:
        return fibonacci(n - 1) + fibonacci(n - 2)

def is_password_breached(hash_prefix, hash_suffix_api):
    # Have I Been Pwned API 
    api_url = f'https://api.pwnedpasswords.com/range/{hash_prefix}'
    response = requests.get(api_url)
    if response.status_code == 200:
        # Check if the password's hash sufix exists in the response
        hash_suffixes = [line.split(':')[0] for line in response.text.splitlines()]
        return hash_suffix_api.upper() in hash_suffixes
    else:
        print(f"API request failed with status code {response.status_code}")
        print(response.text)  
        print("returning false")
        return False


if __name__ == '__main__':
    app.run(debug=False, ssl_context=('cert.pem','key.pem'))
