import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS
import logging
from sqlalchemy import text

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["http://localhost:3000", "https://african-fusion-restau-frontend.netlify.app"]}})
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///african_fusion.db')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'votre-secret-key-super-secret')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

logging.basicConfig(level=logging.DEBUG)

# Modèles
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    full_name = db.Column(db.String(100), default='')
    phone = db.Column(db.String(20), default='')
    email = db.Column(db.String(120), unique=True, nullable=False)
    address = db.Column(db.String(200), default='')

    def __init__(self, username, email, password, role, full_name='', phone='', address=''):
        self.username = username
        self.email = email
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.role = role
        self.full_name = full_name
        self.phone = phone
        self.address = address

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def has_permission(self, action):
        if self.role == 'super_admin':
            return True
        elif self.role == 'admin' and action in ['add', 'view']:
            return True
        elif self.role in ['serveur', 'cuisine'] and action == 'view':
            return True
        return False

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_time = db.Column(db.String(50), default=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    table_id = db.Column(db.Integer)
    items = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Commande reçue')
    total_price = db.Column(db.Float)

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), default='Plat Principal')

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='En attente')
    method = db.Column(db.String(20))
    payment_date = db.Column(db.String(50), default=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

class Stock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ingredient = db.Column(db.String(100), unique=True, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

# Initialisation et migration robuste
def init_db():
    with app.app_context():
        # Crée toutes les tables définies
        db.create_all()
        logging.debug("Database tables created")

        # Vérifie et ajoute la colonne 'category' si elle n'existe pas
        inspector = db.inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('menu_item')]
        if 'category' not in columns:
            logging.debug("Adding 'category' column to menu_item table")
            try:
                db.session.execute(text("ALTER TABLE menu_item ADD COLUMN category VARCHAR(50) DEFAULT 'Plat Principal'"))
                db.session.commit()
                logging.debug("Column 'category' added successfully")
            except Exception as e:
                logging.error(f"Failed to add 'category' column: {str(e)}")
                db.session.rollback()
        else:
            logging.debug("'category' column already exists in menu_item table")

# Routes
@app.route('/register', methods=['POST'])
@jwt_required()
def register():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    if not current_user.has_permission('add'):
        return jsonify({"msg": "Permission denied"}), 403
    data = request.get_json()
    new_user = User(
        username=data['username'],
        email=data['email'],
        password=data['password'],
        role=data['role'],
        full_name=data.get('full_name', ''),
        phone=data.get('phone', ''),
        address=data.get('address', '')
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    user = User.query.filter_by(email=auth['email']).first()
    if user and user.check_password(auth['password']):
        access_token = create_access_token(identity=str(user.id))
        return jsonify({"access_token": access_token, "role": user.role}), 200
    return jsonify({"msg": "Bad email or password"}), 401

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    if not current_user.has_permission('view'):
        return jsonify({"msg": "Permission denied"}), 403
    users = User.query.all()
    return jsonify([{"id": u.id, "username": u.username, "role": u.role, "full_name": u.full_name, "phone": u.phone, "email": u.email, "address": u.address} for u in users]), 200

@app.route('/menu', methods=['GET'])
def get_menu():
    items = MenuItem.query.all()
    return jsonify([{"id": i.id, "name": i.name, "price": i.price, "category": i.category} for i in items]), 200

@app.route('/menu', methods=['POST'])
@jwt_required()
def add_menu_item():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    if not current_user.has_permission('add'):
        return jsonify({"msg": "Permission denied"}), 403
    data = request.get_json()
    new_item = MenuItem(name=data['name'], price=data['price'], category=data.get('category', 'Plat Principal'))
    db.session.add(new_item)
    db.session.commit()
    return jsonify({"msg": "Menu item added successfully"}), 201

@app.route('/orders', methods=['POST'])
@jwt_required()
def add_order():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    if current_user.role not in ['serveur', 'super_admin']:
        return jsonify({"msg": "Permission denied"}), 403
    data = request.get_json()
    items = data['items']
    total_price = sum(MenuItem.query.filter_by(name=item.split(' x')[0]).first().price * int(item.split(' x')[1]) for item in items.split(', '))
    new_order = Order(table_id=data.get('table_id'), items=items, total_price=total_price)
    db.session.add(new_order)
    db.session.commit()
    return jsonify({"msg": "Order added successfully", "order_id": new_order.id}), 201

@app.route('/orders', methods=['GET'])
@jwt_required()
def get_orders():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    if not current_user.has_permission('view'):
        return jsonify({"msg": "Permission denied"}), 403
    orders = Order.query.all()
    return jsonify([{"id": o.id, "order_time": o.order_time, "table_id": o.table_id, "items": o.items, "status": o.status, "total_price": o.total_price} for o in orders]), 200

@app.route('/orders/<int:order_id>', methods=['PUT'])
@jwt_required()
def update_order(order_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    if current_user.role not in ['cuisine', 'super_admin']:
        return jsonify({"msg": "Permission denied"}), 403
    order = Order.query.get(order_id)
    if not order:
        return jsonify({"msg": "Order not found"}), 404
    data = request.get_json()
    order.status = data.get('status', order.status)
    db.session.commit()
    return jsonify({"msg": "Order updated successfully"}), 200

@app.route('/stock', methods=['GET'])
@jwt_required()
def get_stock():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    if not current_user.has_permission('view'):
        return jsonify({"msg": "Permission denied"}), 403
    stock = Stock.query.all()
    return jsonify([{"id": s.id, "ingredient": s.ingredient, "quantity": s.quantity} for s in stock]), 200

@app.route('/stock', methods=['POST'])
@jwt_required()
def add_stock():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    if not current_user.has_permission('add'):
        return jsonify({"msg": "Permission denied"}), 403
    data = request.get_json()
    new_stock = Stock(ingredient=data['ingredient'], quantity=data['quantity'])
    db.session.add(new_stock)
    db.session.commit()
    return jsonify({"msg": "Stock added successfully"}), 201

# Initialisation au démarrage
init_db()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)