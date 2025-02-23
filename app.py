from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///african_fusion.db')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'votre-secret-key-super-secret')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Modèles (User et MenuItem restent identiques)

# Routes (inchangées)

def init_db():
    with app.app_context():
        db.create_all()  # Crée toutes les tables définies dans les modèles
        print("Database tables created")  # Log pour confirmer

# Appelez init_db() au démarrage
init_db()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
    @app.route('/reset_db', methods=['POST'])
def reset_db():
    with app.app_context():
        db.drop_all()  # Supprime toutes les tables existantes
        db.create_all()  # Recrée les tables
        return jsonify({"msg": "Database reset and tables created"}), 200

# Le reste du code (User, MenuItem, routes) reste identique au précédent message

# Modèle Utilisateur
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

# Modèle Plat
class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    price = db.Column(db.Float, nullable=False)

# Routes Utilisateur
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

# Routes Menu
@app.route('/menu', methods=['GET'])
def get_menu():
    items = MenuItem.query.all()
    return jsonify([{"id": item.id, "name": item.name, "description": item.description, "price": item.price} for item in items]), 200

@app.route('/menu', methods=['POST'])
@jwt_required()
def add_menu_item():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    if not current_user.has_permission('add'):
        return jsonify({"msg": "Permission denied"}), 403
    data = request.get_json()
    new_item = MenuItem(name=data['name'], description=data.get('description', ''), price=data['price'])
    db.session.add(new_item)
    db.session.commit()
    return jsonify({"msg": "Menu item added successfully"}), 201

def init_db():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)