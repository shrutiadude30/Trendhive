from flask import Flask, request, jsonify, session
import mysql.connector
from passlib.hash import sha256_crypt
from flask_cors import CORS

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = "trendhive_secret_key"
app.config["SESSION_TYPE"] = "filesystem"

# ---------------- DB CONNECTION ----------------
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="trendhive_db"
    )

# ---------------- REGISTER ----------------
@app.route("/register", methods=["POST"])
def register():
    # Accept both JSON and form data
    data = request.get_json() or request.form
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    confirm_password = data.get("confirm_password")

    if not all([username, email, password, confirm_password]):
        return jsonify({"error": "All fields are required!"})
    if password != confirm_password:
        return jsonify({"error": "Passwords do not match!"})

    hashed_password = sha256_crypt.hash(password)

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
            (username, email, hashed_password)
        )
        conn.commit()
        session["user"] = {"user_id": cursor.lastrowid, "username": username, "email": email}
        return jsonify({"message": f"User {username} registered successfully!"})
    except mysql.connector.Error as err:
        if err.errno == 1062:  # Duplicate entry
            return jsonify({"error": "Email or Username already exists!"})
        return jsonify({"error": str(err)})
    finally:
        cursor.close()
        conn.close()

# ---------------- LOGIN ----------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or request.form
    email = data.get("email")
    password = data.get("password")

    if not all([email, password]):
        return jsonify({"error": "Email and password are required!"})

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user and sha256_crypt.verify(password, user["password"]):
        session["user"] = {"user_id": user["user_id"], "username": user["username"], "email": user["email"]}
        return jsonify({"message": f"Welcome {user['username']}!"})
    else:
        return jsonify({"error": "Invalid email or password!"})

# ---------------- LOGOUT ----------------
@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    return jsonify({"message": "Logged out successfully!"})

# ---------------- CHECK SESSION ----------------
@app.route("/check_session", methods=["GET"])
def check_session():
    if "user" in session:
        return jsonify({"logged_in": True, "user": session["user"]})
    else:
        return jsonify({"logged_in": False})

# ---------------- ADD TO CART ----------------
@app.route("/add_to_cart", methods=["POST"])
def add_to_cart():
    if "user" not in session:
        return jsonify({"error": "User not logged in!"})

    data = request.get_json() or request.form
    product_id = data.get("product_id")
    quantity = int(data.get("quantity", 1))
    user_id = session["user"]["user_id"]

    if not product_id:
        return jsonify({"error": "Product ID is required!"})

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if product already in cart
        cursor.execute("SELECT * FROM cart WHERE user_id=%s AND product_id=%s", (user_id, product_id))
        existing = cursor.fetchone()
        if existing:
            cursor.execute(
                "UPDATE cart SET quantity = quantity + %s WHERE user_id=%s AND product_id=%s",
                (quantity, user_id, product_id)
            )
        else:
            cursor.execute(
                "INSERT INTO cart (user_id, product_id, quantity) VALUES (%s, %s, %s)",
                (user_id, product_id, quantity)
            )
        conn.commit()
        return jsonify({"message": "Product added to cart successfully!"})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)})
    finally:
        cursor.close()
        conn.close()

# ---------------- VIEW CART ----------------
@app.route("/cart", methods=["GET"])
def view_cart():
    if "user" not in session:
        return jsonify({"error": "User not logged in!"})

    user_id = session["user"]["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT c.cart_id, c.quantity, p.product_id, p.product_name, p.price
            FROM cart c
            JOIN products p ON c.product_id = p.product_id
            WHERE c.user_id = %s
        """, (user_id,))
        cart_items = cursor.fetchall()
        return jsonify({"cart": cart_items})
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    app.run(debug=True)
