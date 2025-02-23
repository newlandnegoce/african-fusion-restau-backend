import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS
import logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///african_fusion.db')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'votre-secret-key-super-secret')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    def __init__(self, username, email, password, role):
        self.username = username
        self.email = email
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.role = role

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def has_permission(self, action):
        if self.role == 'super_admin':
            return True
        elif self.role == 'admin' and action in ['add', 'view']:
            return True
        elif self.role == 'user' and action == 'view':
            return True
        return False

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    price = db.Column(db.Float, nullable=False)

@app.route('/register', methods=['POST'])
@jwt_required()
def register():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    if not current_user.has_permission('add'):
        return jsonify({"msg": "Permission denied"}), 403
    data = request.get_json()
    new_user = User(username=data['username'], email=data['email'], password=data['password'], role=data['role'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    user = User.query.filter_by(email=auth['email']).first()
    if user and user.check_password(auth['password']):
        access_token = create_access_token(identity=str(user.id))
        return jsonify(access_token=access_token), 200
    return jsonify({"msg": "Bad email or password"}), 401

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    if current_user.has_permission('view'):
        users = User.query.all()
        return jsonify([{"id": user.id, "username": user.username, "email": user.email, "role": user.role} for user in users if current_user.role == 'super_admin' or user.role != 'super_admin'])
    return jsonify({"msg": "Permission denied"}), 403

@app.route('/init_super_admin', methods=['POST'])
def init_super_admin():
    with app.app_context():
        if not User.query.filter_by(role='super_admin').first():
            super_admin = User(username='superadmin', email='super@admin.com', password='admin123', role='super_admin')
            db.session.add(super_admin)
            db.session.commit()
            return jsonify({"msg": "Super Admin created"}), 201
        return jsonify({"msg": "Super Admin already exists"}), 400

@app.route('/menu', methods=['GET'])
def get_menu():
    items = MenuItem.query.all()
    return jsonify([{"id": item.id, "name": item.name, "description": item.description, "price": item.price} for item in items]), 200

import logging  # Ajoute ceci au début du fichier, juste après les autres imports

@app.route('/menu', methods=['POST'])
@jwt_required()
def add_menu_item():
    try:
        logging.debug(f"Authorization header: {request.headers.get('Authorization')}")
        current_user_id = get_jwt_identity()
        logging.debug(f"Current user ID: {current_user_id}")
        current_user = User.query.get(int(current_user_id))
        if not current_user:
            return jsonify({"msg": "User not found"}), 404
        if not current_user.has_permission('add'):
            return jsonify({"msg": "Permission denied"}), 403
        # Vérifiez le corps brut avant parsing
        raw_body = request.get_data(as_text=True)
        logging.debug(f"Raw request body: {raw_body}")
        try:
            data = request.get_json(force=True)
        except Exception as json_error:
            logging.error(f"Failed to parse JSON: {str(json_error)}")
            return jsonify({"msg": "Invalid JSON format"}), 400
        logging.debug(f"Parsed data: {data}")
        if not data or 'name' not in data or 'price' not in data:
            return jsonify({"msg": "Missing required fields: 'name' and 'price' are required"}), 400
        try:
            price = float(data['price'])
        except (ValueError, TypeError):
            return jsonify({"msg": "Invalid price: must be a number"}), 400
        new_item = MenuItem(name=data['name'], description=data.get('description', ''), price=price)
        db.session.add(new_item)
        db.session.commit()
        return jsonify({"msg": "Menu item added successfully"}), 201
    except Exception as e:
        logging.error(f"Error in add_menu_item: {str(e)}")
        return jsonify({"msg": f"Server error: {str(e)}"}), 500

@app.route('/reset_db', methods=['POST'])
def reset_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        return jsonify({"msg": "Database reset and tables created"}), 200

def init_db():
    with app.app_context():
        db.create_all()

init_db()  # Appelé au démarrage

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)