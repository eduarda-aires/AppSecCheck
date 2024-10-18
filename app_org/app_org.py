from flask import Flask, render_template, request, redirect, url_for,jsonify
from markupsafe import escape
import sqlite3
from flask_bcrypt import Bcrypt


app = Flask(__name__, static_folder="./static", template_folder="./templates")
bcrypt = Bcrypt(app)

# Initialize database connection and cursor
connection = sqlite3.connect("detishop.db", check_same_thread=False)
cursor = connection.cursor()


@app.route('/')
def index():
    # Get the 'q' query parameter
    q = request.args.get('q', '')

    # Sanitize and escape the 'q' parameter
    q = escape(q)
    return render_template('index.html', q=q)

MAX_LOGIN_ATTEMPTS = 3

# not vulnerable to SQL injection
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == "POST":
        username = request.form.get("username", False)
        password = request.form.get("password", False)

        connection = sqlite3.connect("detishop.db")
        cursor = connection.cursor()

        query = "SELECT username, password, login_attempts FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        if user:
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

         # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')


        query = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)"
        try:
            cursor.execute(query, (username, email, hashed_password))
            connection.commit()
            print("Signup successful")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            print("Email already exists. Try a different one.")

    return render_template("signup.html")


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


@app.route('/reviews.html')
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



if __name__ == '__main__':
    app.run(debug=False)
