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
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///restaurant.db')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'votre-secret-key-super-secret')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

logging.basicConfig(level=logging.DEBUG)

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

# Modèle Emplacement (équivalent des propriétés)
class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    availability = db.Column(db.Boolean, default=True)
    description = db.Column(db.String(200))

# Modèle Proposition (réservations ou précommandes)
class Proposal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    customer_name = db.Column(db.String(100), nullable=False)
    customer_email = db.Column(db.String(120))
    status = db.Column(db.String(20), default='pending')  # pending, confirmed, cancelled
    reservation_date = db.Column(db.String(50))

# Initialisation et migration de la base
def init_db():
    with app.app_context():
        db.create_all()
        logging.debug("Database tables created")
        try:
            db.session.execute(text("SELECT category FROM menu_item LIMIT 1"))
        except Exception as e:
            if "UndefinedColumn" in str(e):
                logging.debug("Adding category column to menu_item table")
                db.session.execute(text("ALTER TABLE menu_item ADD COLUMN category VARCHAR(50) DEFAULT 'Plat Principal'"))
                db.session.commit()
                logging.debug("Column category added successfully")

# Routes
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
        return jsonify([{"id": user.id, "username": user.username, "email": user.email, "role": user.role} for user in users if current_user.role == 'super_admin' or user.role != 'super_admin']), 200
    return jsonify({"msg": "Permission denied"}), 403

@app.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    if not current_user or current_user.role != 'super_admin':
        return jsonify({"msg": "Permission denied"}), 403
    user_to_delete = User.query.get(user_id)
    if not user_to_delete or (user_to_delete.role == 'super_admin' and user_to_delete.id == int(current_user_id)):
        return jsonify({"msg": "Cannot delete"}), 403
    db.session.delete(user_to_delete)
    db.session.commit()
    return jsonify({"msg": "User deleted successfully"}), 200

@app.route('/locations', methods=['GET'])
def get_locations():
    locations = Location.query.all()
    return jsonify([{"id": loc.id, "name": loc.name, "capacity": loc.capacity, "availability": loc.availability, "description": loc.description} for loc in locations]), 200

@app.route('/locations', methods=['POST'])
@jwt_required()
def add_location():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    if not current_user.has_permission('add'):
        return jsonify({"msg": "Permission denied"}), 403
    data = request.get_json()
    new_location = Location(name=data['name'], capacity=data['capacity'], availability=data.get('availability', True), description=data.get('description', ''))
    db.session.add(new_location)
    db.session.commit()
    return jsonify({"msg": "Location added successfully"}), 201

@app.route('/proposals', methods=['GET'])
@jwt_required()
def get_proposals():
    proposals = Proposal.query.all()
    return jsonify([{"id": prop.id, "location_id": prop.location_id, "customer_name": prop.customer_name, "customer_email": prop.customer_email, "status": prop.status, "reservation_date": prop.reservation_date} for prop in proposals]), 200

@app.route('/proposals', methods=['POST'])
@jwt_required()
def add_proposal():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    if not current_user.has_permission('add'):
        return jsonify({"msg": "Permission denied"}), 403
    data = request.get_json()
    new_proposal = Proposal(
        location_id=data['location_id'],
        customer_name=data['customer_name'],
        customer_email=data.get('customer_email', ''),
        status=data.get('status', 'pending'),
        reservation_date=data['reservation_date']
    )
    db.session.add(new_proposal)
    db.session.commit()
    return jsonify({"msg": "Proposal added successfully"}), 201

@app.route('/proposals/<int:proposal_id>', methods=['PUT'])
@jwt_required()
def update_proposal(proposal_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    if not current_user.has_permission('add'):
        return jsonify({"msg": "Permission denied"}), 403
    proposal = Proposal.query.get(proposal_id)
    if not proposal:
        return jsonify({"msg": "Proposal not found"}), 404
    data = request.get_json()
    proposal.status = data.get('status', proposal.status)
    db.session.commit()
    return jsonify({"msg": "Proposal updated successfully"}), 200

init_db()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)