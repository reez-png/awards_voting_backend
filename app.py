# Import necessary Flask components and other libraries
from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import jwt
from functools import wraps
import datetime  # For setting JWT expiration
import uuid  # For generating UUIDs for public_id

# Load environment variables from .env file
from dotenv import load_dotenv

load_dotenv()

# Initialize the Flask application
app = Flask(__name__)

# Configure the secret key for JWT signing from environment variables
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise RuntimeError("SECRET_KEY not set in .env file. Please generate a strong secret key.")

# Configure the database URI for SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
# Disable SQLAlchemy event tracking for performance
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the SQLAlchemy instance
db = SQLAlchemy(app)


# --- Database Models ---
class User(db.Model):
    """
    Defines the User model for our database.
    Each instance of this class will correspond to a row in the 'user' table.
    """
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)
    # NEW: Add a vote balance for monetized voting
    vote_balance = db.Column(db.Integer, default=0, nullable=False)

    # Relationship to Votes. A user can cast many votes.
    votes = db.relationship('Vote', backref='voter', lazy=True)

    def __repr__(self):
        """
        Provides a string representation of the User object,
        useful for debugging.
        """
        return f'<User {self.username}>'

    def set_password(self, password):
        """
        Hashes the provided plain-text password and stores it in password_hash.
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """
        Checks if the provided plain-text password matches the stored hash.
        """
        return check_password_hash(self.password_hash, password)


class Category(db.Model):
    """
    Defines the Category model. Each instance is an awards category (e.g., 'Best Actor').
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)

    # Define a relationship to the Nominee model.
    nominees = db.relationship('Nominee', backref='category', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Category {self.name}>'


class Nominee(db.Model):
    """
    Defines the Nominee model. Each instance is an individual nominated person/item.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)  # Text for longer descriptions
    photo_url = db.Column(db.String(255), nullable=True)  # URL to a nominee's image
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

    # Vote count is kept on the Nominee model for quick aggregation,
    # but actual votes are stored in the Vote table for detailed history/auditing.
    vote_count = db.Column(db.Integer, default=0, nullable=False)

    # Relationship to Votes. A nominee can receive many votes.
    received_votes = db.relationship('Vote', backref='nominee', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Nominee {self.name} in Category {self.category.name if self.category else "N/A"}>'


# Vote Model
class Vote(db.Model):
    """
    Defines the Vote model to record each individual vote cast.
    This provides an audit trail for voting.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    nominee_id = db.Column(db.Integer, db.ForeignKey('nominee.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'),
                            nullable=False)  # Store category_id for easier querying
    category = db.relationship('Category', backref='votes', lazy=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    is_paid_vote = db.Column(db.Boolean, default=True, nullable=False)  # True for paid, False for free vote

    def __repr__(self):
        return f'<Vote from User {self.user_id} for Nominee {self.nominee_id} at {self.timestamp}>'


# --- End Database Models ---

# --- AwardSetting Model ---
class AwardSetting(db.Model):
    """
    Defines a model for general award show settings, allowing dynamic control.
    Example settings: 'voting_active', 'show_live_rankings', 'voting_start_time', 'voting_end_time'.
    """
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=True) # Stored as string, convert as needed (e.g., 'true', 'false', datetime string)
    description = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f'<AwardSetting {self.key}: {self.value}>'

# --- End Database Models ---

# ---Transaction Model----
class Transaction(db.Model):
    """
    Defines the Transaction model to record payment attempts for vote packs.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount_cedis = db.Column(db.Float, nullable=False) # Monetary amount
    votes_to_add = db.Column(db.Integer, nullable=False) # Votes associated with this transaction
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    status = db.Column(db.String(50), default='PENDING', nullable=False) # PENDING, COMPLETED, FAILED, REFUNDED
    payment_gateway_ref = db.Column(db.String(255), unique=True, nullable=True) # Reference ID from payment gateway

    def __repr__(self):
        return f'<Transaction {self.id} for User {self.user_id} - {self.amount_cedis} GHS, Status: {self.status}>'

# --- End Database Models ---

# --- Database Initialization ---
with app.app_context():
    db.create_all()
    # Initialize default settings if they don't exist
    if not AwardSetting.query.filter_by(key='voting_active').first():
        db.session.add(AwardSetting(key='voting_active', value='true', description='Is voting currently active? (true/false)'))
    if not AwardSetting.query.filter_by(key='show_live_rankings').first():
        db.session.add(AwardSetting(key='show_live_rankings', value='false', description='Should live rankings be visible to public? (true/false)'))
    if not AwardSetting.query.filter_by(key='voting_start_time').first():
        db.session.add(AwardSetting(key='voting_start_time', value=datetime.datetime.utcnow().isoformat(), description='Start time for voting (ISO format)'))
    if not AwardSetting.query.filter_by(key='voting_end_time').first():
        # Set an end time far in the future initially, or adjust for testing
        future_date = datetime.datetime.utcnow() + datetime.timedelta(days=365)
        db.session.add(AwardSetting(key='voting_end_time', value=future_date.isoformat(), description='End time for voting (ISO format)'))
    db.session.commit() # Commit these initial settings

# --- End Database Initialization ---

# --- Authentication Decorators ---
def token_required(f):
    """
    Decorator function to enforce JWT authentication on routes.
    It checks for a valid JWT in the request header.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
            if not current_user:
                return jsonify({'message': 'Token is invalid or user not found!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            print(f"Error decoding token: {e}")
            return jsonify({'message': 'An error occurred during token validation!'}), 500

        kwargs['current_user'] = current_user
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    """
    Decorator function to enforce that only users with the 'admin' role
    can access the decorated route.
    It relies on the token_required decorator to first authenticate the user.
    """

    @wraps(f)
    @token_required
    def decorated_admin(*args, **kwargs):
        current_user = kwargs.get('current_user')

        if not current_user or current_user.role != 'admin':
            return jsonify({'message': 'Admin access required!'}), 403

        return f(*args, **kwargs)

    return decorated_admin

# --- End Authentication Decorators ---


# --- API Routes ---

@app.route('/')
def home():
    """
    This function handles requests to the homepage.
    It returns a simple JSON response.
    """
    return jsonify({"message": "Welcome to the Awards Voting Backend!"})


@app.route('/api/status')
def status():
    """
    This function provides a simple status check for the API.
    It returns a JSON response indicating the API is operational.
    """
    return jsonify({"status": "API is up and running!"})


@app.route('/api/register', methods=['POST'])
def register():
    """
    Handles user registration.
    Expects JSON input with 'username', 'email', and 'password'.
    """
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"message": "Missing username, email, or password"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists"}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already exists"}), 409

    new_user = User(username=username, email=email)
    new_user.set_password(password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify(
            {"message": "User registered successfully!", "user_id": new_user.id, "public_id": new_user.public_id,
             "vote_balance": new_user.vote_balance}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error during registration: {e}")
        return jsonify({"message": "Something went wrong during registration"}), 500


@app.route('/api/login', methods=['POST'])
def login():
    """
    Handles user login.
    Expects JSON input with 'username' and 'password'.
    Returns a JWT if credentials are valid.
    """
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({"message": "Invalid credentials"}), 401

    token_payload = {
        'public_id': user.public_id,
        'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'token': token}), 200


@app.route('/api/protected', methods=['GET'])
@token_required
def protected_route(**kwargs):
    """
    An example of a protected API route that requires a valid JWT.
    Returns information about the authenticated user.
    """
    current_user = kwargs.get('current_user')
    return jsonify({
        'message': 'You accessed a protected route!',
        'user_public_id': current_user.public_id,
        'user_username': current_user.username,
        'user_role': current_user.role,
        'user_vote_balance': current_user.vote_balance
    }), 200


# --- Category Management API Endpoints (Admin Only) ---
@app.route('/api/categories', methods=['POST'])
@admin_required
def create_category(**kwargs):
    """
    Creates a new category. Admin only.
    Expects JSON input with 'name' and optionally 'description'.
    """
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()
    name = data.get('name')
    description = data.get('description')

    if not name:
        return jsonify({"message": "Category name is required"}), 400

    if Category.query.filter_by(name=name).first():
        return jsonify({"message": "Category with this name already exists"}), 409

    new_category = Category(name=name, description=description)

    try:
        db.session.add(new_category)
        db.session.commit()
        return jsonify({
            "message": "Category created successfully!",
            "category_id": new_category.id,
            "name": new_category.name
        }), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error creating category: {e}")
        return jsonify({"message": "Something went wrong creating category"}), 500


@app.route('/api/categories', methods=['GET'])
def get_all_categories():
    """
    Retrieves all categories. Accessible to all users.
    """
    categories = Category.query.all()
    output = []
    for category in categories:
        output.append({
            'id': category.id,
            'name': category.name,
            'description': category.description
        })
    return jsonify({"categories": output}), 200


@app.route('/api/categories/<int:category_id>', methods=['GET'])
def get_single_category(category_id):
    """
    Retrieves a single category by its ID. Accessible to all users.
    """
    category = Category.query.get(category_id)
    if not category:
        return jsonify({"message": "Category not found"}), 404

    return jsonify({
        'id': category.id,
        'name': category.name,
        'description': category.description
    }), 200


@app.route('/api/categories/<int:category_id>', methods=['PUT'])
@admin_required
def update_category(category_id, **kwargs):
    """
    Updates an existing category. Admin only.
    Expects JSON input with 'name' and/or 'description'.
    """
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    category = Category.query.get(category_id)
    if not category:
        return jsonify({"message": "Category not found"}), 404

    data = request.get_json()
    name = data.get('name')
    description = data.get('description')

    if name:
        existing_category = Category.query.filter_by(name=name).first()
        if existing_category and existing_category.id != category_id:
            return jsonify({"message": "Category with this name already exists"}), 409
        category.name = name
    if description is not None:
        category.description = description

    try:
        db.session.commit()
        return jsonify({"message": "Category updated successfully!", "category": {
            'id': category.id,
            'name': category.name,
            'description': category.description
        }}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error updating category: {e}")
        return jsonify({"message": "Something went wrong updating category"}), 500


@app.route('/api/categories/<int:category_id>', methods=['DELETE'])
@admin_required
def delete_category(category_id, **kwargs):
    """
    Deletes a category. Admin only.
    This will also delete associated nominees due to 'cascade="all, delete-orphan"'
    on the Category-Nominee relationship.
    """
    category = Category.query.get(category_id)
    if not category:
        return jsonify({"message": "Category not found"}), 404

    try:
        db.session.delete(category)
        db.session.commit()
        return jsonify({"message": "Category deleted successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting category: {e}")
        return jsonify({"message": "Something went wrong deleting category"}), 500


# --- Nominee Management API Endpoints (Admin Only) ---
@app.route('/api/nominees', methods=['POST'])
@admin_required
def create_nominee(**kwargs):
    """
    Creates a new nominee for a given category. Admin only.
    Expects JSON input with 'name', 'category_id', and optionally 'description', 'photo_url'.
    """
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()
    name = data.get('name')
    category_id = data.get('category_id')
    description = data.get('description')
    photo_url = data.get('photo_url')

    if not name or not category_id:
        return jsonify({"message": "Nominee name and category_id are required"}), 400

    category = Category.query.get(category_id)
    if not category:
        return jsonify({"message": "Category not found"}), 404

    if Nominee.query.filter_by(name=name, category_id=category_id).first():
        return jsonify({"message": f"Nominee '{name}' already exists in this category"}), 409

    new_nominee = Nominee(
        name=name,
        description=description,
        photo_url=photo_url,
        category_id=category_id
    )

    try:
        db.session.add(new_nominee)
        db.session.commit()
        return jsonify({
            "message": "Nominee created successfully!",
            "nominee_id": new_nominee.id,
            "name": new_nominee.name,
            "category": category.name
        }), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error creating nominee: {e}")
        return jsonify({"message": "Something went wrong creating nominee"}), 500


@app.route('/api/nominees', methods=['GET'])
def get_all_nominees():
    """
    Retrieves all nominees, optionally filtered by category_id. Accessible to all users.
    Query parameter: ?category_id=<int>
    """
    category_id = request.args.get('category_id', type=int)

    nominees_query = Nominee.query

    if category_id:
        category = Category.query.get(category_id)
        if not category:
            return jsonify({"message": "Category not found"}), 404
        nominees_query = nominees_query.filter_by(category_id=category_id)

    nominees = nominees_query.all()
    output = []
    for nominee in nominees:
        output.append({
            'id': nominee.id,
            'name': nominee.name,
            'description': nominee.description,
            'photo_url': nominee.photo_url,
            'category_id': nominee.category_id,
            'category_name': nominee.category.name if nominee.category else None,
            'vote_count': nominee.vote_count
        })
    return jsonify({"nominees": output}), 200


@app.route('/api/nominees/<int:nominee_id>', methods=['GET'])
def get_single_nominee(nominee_id):
    """
    Retrieves a single nominee by ID. Accessible to all users.
    """
    nominee = Nominee.query.get(nominee_id)
    if not nominee:
        return jsonify({"message": "Nominee not found"}), 404

    return jsonify({
        'id': nominee.id,
        'name': nominee.name,
        'description': nominee.description,
        'photo_url': nominee.photo_url,
        'category_id': nominee.category_id,
        'category_name': nominee.category.name if nominee.category else None,
        'vote_count': nominee.vote_count
    }), 200


@app.route('/api/nominees/<int:nominee_id>', methods=['PUT'])
@admin_required
def update_nominee(nominee_id, **kwargs):
    """
    Updates an existing nominee. Admin only.
    Expects JSON input with 'name', 'description', 'photo_url', 'category_id'.
    """
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    nominee = Nominee.query.get(nominee_id)
    if not nominee:
        return jsonify({"message": "Nominee not found"}), 404

    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    photo_url = data.get('photo_url')
    new_category_id = data.get('category_id')

    if new_category_id:
        new_category = Category.query.get(new_category_id)
        if not new_category:
            return jsonify({"message": "New category not found"}), 404
        nominee.category_id = new_category_id

    if name:
        existing_nominee = Nominee.query.filter_by(name=name, category_id=nominee.category_id).first()
        if existing_nominee and existing_nominee.id != nominee_id:
            return jsonify({"message": f"Nominee '{name}' already exists in this category"}), 409
        nominee.name = name

    if description is not None:
        nominee.description = description
    if photo_url is not None:
        nominee.photo_url = photo_url

    try:
        db.session.commit()
        return jsonify({"message": "Nominee updated successfully!", "nominee": {
            'id': nominee.id,
            'name': nominee.name,
            'description': nominee.description,
            'photo_url': nominee.photo_url,
            'category_id': nominee.category_id,
            'category_name': nominee.category.name if nominee.category else None,
            'vote_count': nominee.vote_count
        }}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error updating nominee: {e}")
        return jsonify({"message": "Something went wrong updating nominee"}), 500


@app.route('/api/nominees/<int:nominee_id>', methods=['DELETE'])
@admin_required
def delete_nominee(nominee_id, **kwargs):
    """
    Deletes a nominee. Admin only.
    """
    nominee = Nominee.query.get(nominee_id)
    if not nominee:
        return jsonify({"message": "Nominee not found"}), 404

    try:
        db.session.delete(nominee)
        db.session.commit()
        return jsonify({"message": "Nominee deleted successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting nominee: {e}")
        return jsonify({"message": "Something went wrong deleting nominee"}), 500


# --- Vote Casting and Monetization Endpoints ---

# Endpoint to get current user's vote balance and history
@app.route('/api/user/votes', methods=['GET'])
@token_required
def get_user_vote_info(**kwargs):
    """
    Retrieves the authenticated user's current vote balance and their voting history.
    """
    current_user = kwargs.get('current_user')

    # Fetch user's vote balance
    vote_balance = current_user.vote_balance

    # Fetch user's vote history
    # We fetch votes associated with the user and order by timestamp descending
    user_votes = Vote.query.filter_by(user_id=current_user.id).order_by(Vote.timestamp.desc()).all()

    vote_history_output = []
    for vote in user_votes:
        # To get the nominee and category names, we need to access the relationships.
        # This will trigger additional database queries if not already loaded (lazy loading).
        nominee_name = vote.nominee.name if vote.nominee else 'N/A'
        category_name = vote.category.name if vote.category else 'N/A'
        vote_history_output.append({
            'vote_id': vote.id,
            'nominee_id': vote.nominee_id,
            'nominee_name': nominee_name,
            'category_id': vote.category_id,
            'category_name': category_name,
            'timestamp': vote.timestamp.isoformat(),  # Format datetime for JSON
            'is_paid_vote': vote.is_paid_vote
        })

        # NEW: Fetch user's transaction history
    user_transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(
        Transaction.timestamp.desc()).all()
    transaction_history_output = []
    for transaction in user_transactions:
        transaction_history_output.append({
            'transaction_id': transaction.id,
            'amount_cedis': transaction.amount_cedis,
            'votes_to_add': transaction.votes_to_add,
            'timestamp': transaction.timestamp.isoformat(),
            'status': transaction.status,
            'payment_gateway_ref': transaction.payment_gateway_ref
        })

    return jsonify({
        "vote_balance": vote_balance,
        "vote_history": vote_history_output,
        "transaction_history": transaction_history_output  # Include transaction history
    }), 200

# Updated Endpoint for users to initiate vote purchase
@app.route('/api/buy-votes', methods=['POST'])
@token_required
def initiate_vote_purchase(**kwargs):
    """
    Initiates a vote purchase transaction.
    Instead of directly adding votes, it creates a PENDING transaction.
    Expects JSON input with 'amount_usd' (e.g., price paid) and 'votes_to_add'.
    """
    current_user = kwargs.get('current_user')

    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()

    # 1. Extract the raw values
    raw_amount = data.get('amount_cedis')
    raw_votes = data.get('votes_to_add')

    # 2. Convert & validate
    try:
        amount_cedis = float(raw_amount)
        votes_to_add = int(raw_votes)
    except (TypeError, ValueError):
        return jsonify({"message": "Both amount_cedis and votes_to_add must be numbers"}), 400

    if amount_cedis is None or amount_cedis <= 0 or votes_to_add is None or votes_to_add <= 0:
        return jsonify({"message": "Invalid amount_cedis or votes_to_add"}), 400

    new_transaction = Transaction(
        user_id=current_user.id,
        amount_cedis=amount_cedis,
        votes_to_add=votes_to_add,
        status='PENDING'  # Initial status is PENDING
    )

    try:
        db.session.add(new_transaction)
        db.session.commit()
        # In a real application, you would now integrate with a payment gateway here.
        # This response would typically include a payment URL or client_secret for the frontend.
        return jsonify({
            "message": "Payment initiation successful. Please complete the payment.",
            "transaction_id": new_transaction.id,
            "status": new_transaction.status,
            "amount_to_pay": new_transaction.amount_cedis,
            "votes_expected": new_transaction.votes_to_add
        }), 202  # 202 Accepted, indicating processing will continue

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Failed to initiate payment")
        raise


# NEW: Endpoint for payment gateway webhook/confirmation
@app.route('/api/payment/confirm', methods=['POST'])
def confirm_payment():
    """
    Endpoint to confirm a payment. In a real scenario, this would be a webhook
    from a payment gateway. For testing, you'll call this manually.
    Expects JSON input with 'transaction_id', 'status' (e.g., 'COMPLETED', 'FAILED'),
    and optionally 'payment_gateway_ref'.
    """
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()

    # 1) pull raw values out of the dict
    raw_txn_id  = data.get('transaction_id')
    status = data.get('status')
    payment_gateway_ref = data.get('payment_gateway_ref')

    # 2) validate / cast the transaction ID
    try:
        transaction_id = int(raw_txn_id)
    except (TypeError, ValueError):
        return jsonify({"message": "Invalid or missing transaction_id"}), 400

    if not transaction_id or not status:
        return jsonify({"message": "Transaction ID and status are required"}), 400

    transaction = Transaction.query.get(transaction_id)
    if not transaction:
        return jsonify({"message": "Transaction not found"}), 404

    # Prevent processing already completed or failed transactions
    if transaction.status == 'COMPLETED' or transaction.status == 'FAILED':
        return jsonify({"message": f"Transaction already {transaction.status}."}), 409  # Conflict

    user = User.query.get(transaction.user_id)
    if not user:
        # This case should ideally not happen if database integrity is maintained
        return jsonify({"message": "Associated user not found for transaction."}), 500

    try:
        transaction.status = status  # Update status
        if payment_gateway_ref:
            transaction.payment_gateway_ref = payment_gateway_ref

        if status == 'COMPLETED':
            # Add votes to user's balance ONLY if status is COMPLETED
            user.vote_balance += transaction.votes_to_add
            db.session.commit()
            return jsonify({
                "message": f"Transaction {transaction_id} successfully COMPLETED. Votes added to user.",
                "user_id": user.id,
                "new_vote_balance": user.vote_balance
            }), 200
        elif status == 'FAILED':
            db.session.commit()  # Just update status, no votes added
            return jsonify({"message": f"Transaction {transaction_id} updated to FAILED."}), 200
        else:
            db.session.commit()  # Update status for other cases (e.g., REFUNDED)
            return jsonify({"message": f"Transaction {transaction_id} status updated to {status}."}), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error confirming payment for transaction {transaction_id}: {e}")
        return jsonify({"message": "Something went wrong confirming payment"}), 500


# Endpoint for casting a vote
@app.route('/api/vote', methods=['POST'])
@token_required
def cast_vote(**kwargs):
    current_user = kwargs.get('current_user')

    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()
    nominee_id = data.get('nominee_id', type=int)

    if not nominee_id:
        return jsonify({"message": "Nominee ID is required"}), 400

    nominee = Nominee.query.get(nominee_id)
    if not nominee:
        return jsonify({"message": "Nominee not found"}), 404

    voting_active_setting = AwardSetting.query.filter_by(key='voting_active').first()
    if not voting_active_setting or voting_active_setting.value.lower() != 'true':
        return jsonify({"message": "Voting is currently not active."}), 403

    voting_start_time_str = AwardSetting.query.filter_by(key='voting_start_time').first()
    voting_end_time_str = AwardSetting.query.filter_by(key='voting_end_time').first()

    now = datetime.datetime.utcnow()

    if voting_start_time_str and voting_end_time_str:
        try:
            start_time = datetime.datetime.fromisoformat(voting_start_time_str.value)
            end_time = datetime.datetime.fromisoformat(voting_end_time_str.value)

            if not (start_time <= now <= end_time):
                return jsonify({"message": "Voting is outside the allowed time period."}), 403
        except ValueError:
            print("Warning: Invalid date format in voting_start_time or voting_end_time settings.")
            pass

    existing_free_vote_in_category = Vote.query.filter_by(
        user_id=current_user.id,
        category_id=nominee.category_id,
        is_paid_vote=False
    ).first()

    is_paid = False
    if existing_free_vote_in_category:
        if current_user.vote_balance > 0:
            current_user.vote_balance -= 1
            is_paid = True
        else:
            return jsonify({
                               "message": "You have already cast your free vote in this category and have no vote balance remaining. Please buy more votes."}), 403
    else:
        is_paid = False

    new_vote = Vote(
        user_id=current_user.id,
        nominee_id=nominee.id,
        category_id=nominee.category_id,
        is_paid_vote=is_paid
    )

    nominee.vote_count += 1

    try:
        db.session.add(new_vote)
        db.session.commit()
        vote_type_message = "paid vote" if is_paid else "free vote"
        return jsonify({
            "message": f"Vote cast successfully for {nominee.name}! This was a {vote_type_message}.",
            "nominee_id": nominee.id,
            "new_nominee_vote_count": nominee.vote_count,
            "user_new_vote_balance": current_user.vote_balance,
            "category_id": nominee.category_id
        }), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error casting vote: {e}")
        return jsonify({"message": "Something went wrong casting your vote"}), 500

# --- End Vote Casting and Monetization Endpoints ---


# NEW: API to get live rankings for a specific category or all categories
@app.route('/api/rankings', methods=['GET'])
def get_live_rankings():
    """
    Retrieves live nominee rankings.
    Can be filtered by category_id.
    Controlled by 'show_live_rankings' setting.
    Query parameter: ?category_id=<int>
    """
    show_rankings_setting = AwardSetting.query.filter_by(key='show_live_rankings').first()
    if not show_rankings_setting or show_rankings_setting.value.lower() != 'true':
        return jsonify({"message": "Live rankings are currently not public."}), 403

    category_id = request.args.get('category_id', type=int)

    # Start building the query
    rankings_query = db.session.query(Nominee.id, Nominee.name, Nominee.vote_count, Nominee.category_id,
                                      Category.name.label('category_name')) \
        .join(Category)  # Join with Category table to get category name

    if category_id:
        category_exists = Category.query.get(category_id)
        if not category_exists:
            return jsonify({"message": "Category not found"}), 404
        rankings_query = rankings_query.filter(Nominee.category_id == category_id)

    # Order by vote_count in descending order (highest votes first)
    rankings_query = rankings_query.order_by(Nominee.vote_count.desc())

    raw_rankings = rankings_query.all()

    output = []
    total_votes_in_category = 0
    if category_id:
        # Calculate total votes for the specific category if filtered
        total_votes_in_category = db.session.query(db.func.sum(Nominee.vote_count)).filter_by(
            category_id=category_id).scalar() or 0
    else:
        # Calculate total votes across all categories if not filtered
        total_votes_in_app = db.session.query(db.func.sum(Nominee.vote_count)).scalar() or 0

    for rank, nominee_data in enumerate(raw_rankings):
        nominee_id, name, vote_count, cat_id, category_name = nominee_data

        # Calculate percentage if in a specific category, otherwise skip
        percentage = (
                    vote_count / total_votes_in_category * 100) if category_id and total_votes_in_category > 0 else None

        output.append({
            'rank': rank + 1,  # Ranks start from 1
            'id': nominee_id,
            'name': name,
            'category_id': cat_id,
            'category_name': category_name,
            'vote_count': vote_count,
            'percentage': round(percentage, 2) if percentage is not None else None  # Round percentage
        })

    return jsonify({"rankings": output}), 200


# NEW: API for Admin to manage AwardSettings
@app.route('/api/admin/settings', methods=['GET'])
@admin_required
def get_award_settings(**kwargs):
    """
    Retrieves all award show settings. Admin only.
    """
    settings = AwardSetting.query.all()
    output = []
    for setting in settings:
        output.append({
            'id': setting.id,
            'key': setting.key,
            'value': setting.value,
            'description': setting.description
        })
    return jsonify({"settings": output}), 200


@app.route('/api/admin/settings', methods=['PUT'])
@admin_required
def update_award_setting(**kwargs):
    """
    Updates a specific award show setting by its key. Admin only.
    Expects JSON input with 'key' and 'value'.
    """
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()
    key = data.get('key')
    value = data.get('value')

    if not key or value is None:  # Value can be empty string, but not entirely missing
        return jsonify({"message": "Setting key and value are required"}), 400

    setting = AwardSetting.query.filter_by(key=key).first()
    if not setting:
        return jsonify({"message": f"Setting with key '{key}' not found"}), 404

    setting.value = str(value)  # Ensure value is stored as a string

    try:
        db.session.commit()
        return jsonify({
            "message": f"Setting '{key}' updated successfully!",
            "setting": {
                'id': setting.id,
                'key': setting.key,
                'value': setting.value,
                'description': setting.description
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error updating setting: {e}")
        return jsonify({"message": "Something went wrong updating setting"}), 500


# --- End API Routes ---


if __name__ == '__main__':
    # ensure debug=True
    app.run(debug=True)

