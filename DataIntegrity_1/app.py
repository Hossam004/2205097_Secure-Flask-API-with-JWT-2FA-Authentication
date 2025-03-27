from flask import Flask, request, jsonify, send_file
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import pyotp
import qrcode
import io
import datetime
import mysql.connector

app = Flask(__name__)

# MySQL Configuration
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="flask_api_db"
)
cursor = db.cursor()

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = 'your_secret_key'

#------------------------------------------------------------------------------------------------

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    if not all(k in data for k in ['name', 'username', 'password']):
        return jsonify({'error': 'Missing fields'}), 400

    cursor.execute("SELECT * FROM users WHERE username=%s", (data['username'],))
    if cursor.fetchone():
        return jsonify({'error': 'Username already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    secret = pyotp.random_base32()
    cursor.execute("INSERT INTO users (name, username, password, twofa_secret) VALUES (%s, %s, %s, %s)",
                   (data['name'], data['username'], hashed_password, secret))
    db.commit()

    return jsonify({'message': 'User registered successfully, please set up 2FA'}), 201

#------------------------------------------------------------------------------------------------

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    cursor.execute("SELECT id, username, password FROM users WHERE username=%s", (data['username'],))
    user = cursor.fetchone()
    if not user or not bcrypt.check_password_hash(user[2], data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401

    return jsonify({'message': 'Enter 2FA code', 'username': user[1]}), 200

#------------------------------------------------------------------------------------------------

@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    data = request.json
    cursor.execute("SELECT id, twofa_secret FROM users WHERE username=%s", (data['username'],))
    user = cursor.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    totp = pyotp.TOTP(user[1])
    if totp.verify(data['code']):
        token = create_access_token(identity=user[0], expires_delta=datetime.timedelta(minutes=10))
        return jsonify({'message': '2FA verified successfully', 'token': token})
    else:
        return jsonify({'error': 'Invalid or expired code'}), 401

#------------------------------------------------------------------------------------------------

@app.route('/generate-2fa/<username>', methods=['GET'])
def generate_2fa(username):
    cursor.execute("SELECT twofa_secret FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    uri = pyotp.totp.TOTP(user[0]).provisioning_uri(name=username, issuer_name='FlaskAPI_2FA')
    qr = qrcode.make(uri)
    img = io.BytesIO()
    qr.save(img)
    img.seek(0)
    return send_file(img, mimetype='image/png')

#------------------------------------------------------------------------------------------------

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="flask_api_db"
    )

@app.route('/products', methods=['POST'])
@jwt_required()
def add_product():
    current_user = get_jwt_identity()
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO products (pname, description, price, stock) VALUES (%s, %s, %s, %s)", 
                   (data['pname'], data.get('description', ''), data['price'], data['stock']))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Product added successfully'})

#------------------------------------------------------------------------------------------------

@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    conn.close()
    return jsonify({'products': products})

#------------------------------------------------------------------------------------------------

@app.route('/products/<int:pid>', methods=['GET'])
@jwt_required()
def get_product(pid):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE pid=%s", (pid,))
    product = cursor.fetchone()
    conn.close()
    if product:
        return jsonify({'product': product})
    return jsonify({'message': 'Product not found'}), 404

#------------------------------------------------------------------------------------------------

@app.route('/products/<int:pid>', methods=['PUT'])
@jwt_required()
def update_product(pid):
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE products SET pname=%s, description=%s, price=%s, stock=%s WHERE pid=%s", 
                   (data['pname'], data.get('description', ''), data['price'], data['stock'], pid))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Product updated successfully'})

#------------------------------------------------------------------------------------------------

@app.route('/products/<int:pid>', methods=['DELETE'])
@jwt_required()
def delete_product(pid):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM products WHERE pid=%s", (pid,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Product deleted successfully'})

if __name__ == '__main__':
    app.run(debug=True)
