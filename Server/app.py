import os
import sys
import logging
from datetime import datetime
from functools import wraps

from flask import Flask, Blueprint, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, verify_jwt_in_request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_login import LoginManager, login_user, logout_user, current_user

from models import User, Product, Wishlist, Favorite, CartItem, Order, Review, SupportRequest, Category, db

app = Flask(__name__)

# Get the DATABASE_URI from the environment variable
database_uri = os.getenv('DATABASE_URI', 'postgresql://shopmate_bwbg_user:KsZRkRdSwBtbHiJ3LVSkle5v5LHA8zMg@dpg-cqoc95dsvqrc73feukd0-a.oregon-postgres.render.com/shopmate_bwbg')
print(f'DATABASE_URI: {database_uri}')  # Debugging line to print the database URI

app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')
app.config["MAIL_SERVER"] = "smtp.mailtrap.io"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USERNAME"] = os.getenv('MAIL_USERNAME', 'your_email@gmail.com')
app.config["MAIL_PASSWORD"] = os.getenv('MAIL_PASSWORD', 'your_password')
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

db.init_app(app)
mail = Mail(app)
jwt = JWTManager(app)
cors = CORS(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'

app.logger.setLevel(logging.DEBUG)

# Create a file handler
handler = logging.FileHandler('app.log')
handler.setLevel(logging.DEBUG)

# Create a formatter and attach it to the handler
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Add the handler to the logger
app.logger.addHandler(handler)

# Authentication Endpoints
@login.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def jwt_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()  # Verify the JWT
            return fn(*args, **kwargs)  # Proceed with the original function if valid
        except Exception as e:
            return jsonify(msg=str(e)), 401  # Return an error if JWT is invalid
    return wrapper

@app.route('/')
def index():
    return "Welcome to ShopMate!"

@app.route('/protected', methods=['GET'])
@jwt_required
def protected_route():
    return jsonify(msg="You have access!")

def admin_required(fn):    
    @wraps(fn)
    @jwt_required
    def wrapper(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if user and user.is_admin:
            return fn(*args, **kwargs)
        else:
            return jsonify(msg="Admins only!"), 403
    return wrapper

@app.route('/admin', methods=['GET'])
@admin_required
def admin_dashboard():
    return jsonify(msg="Welcome Admin!")

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({"msg": "Username, email, and password are required"}), 400
    
    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify({"msg": "User already exists"}), 400
    
    new_user = User(username=username, email=email)
    new_user.set_password(password)  # Set the password here
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"msg": "User registered successfully"}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if user is None or not user.check_password(password):
        return jsonify({"msg": "Invalid username or password"}), 401
    
    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token), 200

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return jsonify({"message": "Logout successful"}), 200

@app.route('/profile', methods=['GET'])
@jwt_required
def profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return jsonify(username=user.username, email=user.email, preferences=user.preferences, orders=user.orders), 200

@app.route('/profile', methods=['PUT'])
@jwt_required
def update_profile():
    user_id = get_jwt_identity()
    data = request.get_json()
    user = User.query.get(user_id)
    if not user:
        return jsonify(message="User not found"), 404
    user.username = data.get('username', user.username)
    user.email = data.get('email', user.email)
    user.preferences = data.get('preferences', user.preferences)
    db.session.commit()
    return jsonify(message="Profile updated successfully"), 200

@app.route('/wishlist', methods=['POST'])
@jwt_required
def add_to_wishlist():
    user_id = get_jwt_identity()
    product_id = request.json.get('product_id')
    wishlist_item = Wishlist(user_id=user_id, product_id=product_id)
    db.session.add(wishlist_item)
    db.session.commit()
    return jsonify(message="Product added to wishlist"), 201

@app.route('/favorites', methods=['POST'])
@jwt_required
def add_to_favorites():
    user_id = get_jwt_identity()
    product_id = request.json.get('product_id')
    favorite_item = Favorite(user_id=user_id, product_id=product_id)
    db.session.add(favorite_item)
    db.session.commit()
    return jsonify(message="Product added to favorites"), 201

# Define a logger
logger = logging.getLogger("my_logger")

# Create a Blueprint for logging and monitoring
logging_bp = Blueprint("logging_bp", __name__)

@logging_bp.route("/log", methods=["POST"])
@jwt_required
def log_event():
    # Log user actions, API requests, and errors
    event = request.json.get("event")
    logger.info(event)
    return jsonify({"message": "Event logged"})

@logging_bp.route("/monitor", methods=["GET"])
@jwt_required
def monitor_system():
    # Monitor system health and identify issues
    system_status = {"status": "healthy"}
    logger.info("System health check")
    return jsonify(system_status)

# Products Blueprint
product_bp = Blueprint('products_bp', __name__)

@app.route('/products', methods=['POST'])
@jwt_required
def create_product():
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    price = data.get('price')
    category_id = data.get('category_id')
    image_url = data.get('image_url')
    rating = data.get('rating')

    if not image_url:
        return jsonify({"error": "Image URL is required"}), 400
    
    new_product = Product(
        name=name,
        description=description,
        price=price,
        rating=rating,
        category_id=category_id,
        image_url=image_url
    )
    db.session.add(new_product)
    db.session.commit()
    
    return jsonify({"message": "Product created successfully!"}), 201

@app.route('/products', methods=['GET'])
def get_products():
    products_query = Product.query.all()
    products = [{
        'id': product.id,
        'name': product.name,
        'description': product.description,
        'price': product.price,
        'rating': product.rating,
        'image_url': product.image_url,
        'category': product.category.name if product.category else None
    } for product in products_query]
    return jsonify({
        'products': products,
        'total_products': len(products)
    })

@app.route('/products/<int:id>', methods=['GET'])
def get_product_details(id):
    product = Product.query.get_or_404(id)
    reviews = [{
        'content': review.content,
        'rating': review.rating
    } for review in product.reviews]
    return jsonify({
        'id': product.id,
        'name': product.name,
        'description': product.description,
        'price': product.price,
        'image_url': product.image_url,
        'star': product.rating,
        'reviews': reviews,
        'average_rating': sum(review['rating'] for review in reviews) / len(reviews) if reviews else None
    })

@app.route('/products/<int:id>', methods=['PUT'])
@jwt_required
def update_product(id):
    data = request.get_json()
    product = Product.query.get_or_404(id)

    product.name = data.get('name', product.name)
    product.description = data.get('description', product.description)
    product.price = data.get('price', product.price)
    product.rating = data.get('rating', product.rating)
    product.category_id = data.get('category_id', product.category_id)
    product.image_url = data.get('image_url', product.image_url)

    db.session.commit()
    return jsonify({"message": "Product updated successfully!"})

@app.route('/products/<int:id>', methods=['DELETE'])
@jwt_required
def delete_product(id):
    product = Product.query.get_or_404(id)
    db.session.delete(product)
    db.session.commit()
    return jsonify({"message": "Product deleted successfully!"})

@app.route('/checkout', methods=['POST'])
@jwt_required
def checkout():
    user_id = get_jwt_identity()
    data = request.get_json()
    cart_items = data.get('cart_items', [])
    address = data.get('address')
    payment_method = data.get('payment_method')
    order_date = datetime.utcnow()

    if not cart_items or not address or not payment_method:
        return jsonify({"msg": "Cart items, address, and payment method are required"}), 400

    order = Order(user_id=user_id, address=address, payment_method=payment_method, order_date=order_date)
    db.session.add(order)
    db.session.commit()

    for item in cart_items:
        product_id = item.get('product_id')
        quantity = item.get('quantity')
        cart_item = CartItem(order_id=order.id, product_id=product_id, quantity=quantity)
        db.session.add(cart_item)

    db.session.commit()
    return jsonify({"msg": "Order placed successfully!"}), 201

@app.route('/reviews', methods=['POST'])
@jwt_required
def create_review():
    data = request.get_json()
    product_id = data.get('product_id')
    content = data.get('content')
    rating = data.get('rating')

    if not product_id or not content or not rating:
        return jsonify({"msg": "Product ID, content, and rating are required"}), 400

    review = Review(product_id=product_id, content=content, rating=rating)
    db.session.add(review)
    db.session.commit()

    return jsonify({"msg": "Review added successfully!"}), 201

@app.route('/support', methods=['POST'])
@jwt_required
def support_request():
    data = request.get_json()
    subject = data.get('subject')
    description = data.get('description')
    
    if not subject or not description:
        return jsonify({"msg": "Subject and description are required"}), 400

    support_request = SupportRequest(user_id=get_jwt_identity(), subject=subject, description=description)
    db.session.add(support_request)
    db.session.commit()

    # Send an email notification
    msg = Message(subject='Support Request Received', recipients=[os.getenv('MAIL_USERNAME')])
    msg.body = f"Support Request\nSubject: {subject}\nDescription: {description}"
    mail.send(msg)

    return jsonify({"msg": "Support request submitted successfully!"}), 201

app.register_blueprint(logging_bp, url_prefix='/logging')
app.register_blueprint(product_bp, url_prefix='/products')

if __name__ == "__main__":
    app.run(debug=True)
