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

@app.route('/products', methods=['POST'])
@jwt_required()
def create_product():
    data = request.json
    cursor.execute("INSERT INTO products (name, description, price, quantity) VALUES (%s, %s, %s, %s)",
                   (data['pname'], data.get('description', ''), data['price'], data['stock']))
    db.commit()
    return jsonify({'message': 'Product added'}), 201

#------------------------------------------------------------------------------------------------

@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    return jsonify(products)

#------------------------------------------------------------------------------------------------

@app.route('/products/<int:pid>', methods=['GET'])
@jwt_required()
def get_product(pid):
    cursor.execute("SELECT * FROM products WHERE id=%s", (pid,))
    product = cursor.fetchone()
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    return jsonify(product)

#------------------------------------------------------------------------------------------------

@app.route('/products/<int:pid>', methods=['PUT'])
@jwt_required()
def update_product(pid):
    data = request.json
    cursor.execute("UPDATE products SET name=%s, description=%s, price=%s, quantity=%s WHERE id=%s",
                   (data['pname'], data.get('description', ''), data['price'], data['stock'], pid))
    db.commit()
    return jsonify({'message': 'Product updated successfully'})

#------------------------------------------------------------------------------------------------

@app.route('/products/<int:pid>', methods=['DELETE'])
@jwt_required()
def delete_product(pid):
    cursor.execute("DELETE FROM products WHERE id=%s", (pid,))
    db.commit()
    return jsonify({'message': 'Product deleted'})


if __name__ == '__main__':
    app.run(debug=True)
