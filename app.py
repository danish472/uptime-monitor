from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import os

# Initialize Flask app
app = Flask(__name__)
CORS(app, supports_credentials=True)


# Configuration
app.config['SECRET_KEY'] = 'uptime_guard_secret_key_2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///uptimeguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ================================
# DATABASE MODELS
# ================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    monitors = db.relationship('Monitor', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.email}>'


class Monitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(10), default='unknown')
    uptime_percent = db.Column(db.Float, default=0.0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Monitor {self.url}>'


# ================================
# ROUTES
# ================================

@app.route('/')
def home():
    return jsonify({'message': 'UptimeGuard API is running!'})


@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()

    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'error': 'Email already registered'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = User(name=name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Account created successfully!'}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'All fields are required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'error': 'Invalid email or password'}), 401

    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid email or password'}), 401

    session['user_id'] = user.id
    session['user_name'] = user.name

    return jsonify({
        'message': 'Login successful!',
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email
        }
    }), 200


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully!'}), 200


@app.route('/api/monitors', methods=['GET'])
def get_monitors():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Please login first'}), 401

    monitors = Monitor.query.filter_by(user_id=user_id).all()

    monitors_list = []
    for monitor in monitors:
        monitors_list.append({
            'id': monitor.id,
            'name': monitor.name,
            'url': monitor.url,
            'status': monitor.status,
            'uptime_percent': monitor.uptime_percent
        })

    return jsonify({'monitors': monitors_list}), 200


@app.route('/api/monitors', methods=['POST'])
def add_monitor():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Please login first'}), 401

    data = request.get_json()
    name = data.get('name')
    url = data.get('url')

    if not name or not url:
        return jsonify({'error': 'Name and URL are required'}), 400

    new_monitor = Monitor(name=name, url=url, user_id=user_id)
    db.session.add(new_monitor)
    db.session.commit()

    return jsonify({'message': 'Monitor added successfully!'}), 201


@app.route('/api/monitors/<int:monitor_id>', methods=['DELETE'])
def delete_monitor(monitor_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Please login first'}), 401

    monitor = Monitor.query.filter_by(id=monitor_id, user_id=user_id).first()

    if not monitor:
        return jsonify({'error': 'Monitor not found'}), 404

    db.session.delete(monitor)
    db.session.commit()

    return jsonify({'message': 'Monitor deleted successfully!'}), 200


# ================================
# RUN APP
# ================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print('Database created!')
    app.run(debug=True, port=5000)

