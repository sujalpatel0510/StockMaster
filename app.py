from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, and_, or_
from sqlalchemy.orm import relationship
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres:8511@localhost:5432/stockmaster')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# ==================== DATABASE MODELS ====================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100))
    role = db.Column(db.String(50), default='')  # admin, manager, staff
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Warehouse(db.Model):
    __tablename__ = 'warehouses'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(50), unique=True, nullable=False)
    location = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'code': self.code,
            'location': self.location,
            'is_active': self.is_active
        }

class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    parent_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'parent_id': self.parent_id
        }

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    sku = db.Column(db.String(100), unique=True, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'))
    unit_of_measure = db.Column(db.String(50), default='Units')
    reorder_level = db.Column(db.Float, default=0)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    category = relationship('Category', backref='products')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'sku': self.sku,
            'category': self.category.to_dict() if self.category else None,
            'unit_of_measure': self.unit_of_measure,
            'reorder_level': self.reorder_level,
            'description': self.description,
            'is_active': self.is_active
        }

class Stock(db.Model):
    __tablename__ = 'stock'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    warehouse_id = db.Column(db.Integer, db.ForeignKey('warehouses.id'), nullable=False)
    quantity = db.Column(db.Float, default=0)
    reserved_quantity = db.Column(db.Float, default=0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    product = relationship('Product', backref='stock_levels')
    warehouse = relationship('Warehouse', backref='stock_levels')
    
    def to_dict(self):
        return {
            'id': self.id,
            'product': self.product.to_dict() if self.product else None,
            'warehouse': self.warehouse.to_dict() if self.warehouse else None,
            'quantity': self.quantity,
            'reserved_quantity': self.reserved_quantity,
            'available_quantity': self.quantity - self.reserved_quantity,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Receipt(db.Model):
    __tablename__ = 'receipts'
    id = db.Column(db.Integer, primary_key=True)
    reference = db.Column(db.String(100), unique=True, nullable=False)
    supplier = db.Column(db.String(200))
    warehouse_id = db.Column(db.Integer, db.ForeignKey('warehouses.id'), nullable=False)
    status = db.Column(db.String(50), default='draft')  # draft, waiting, ready, done, canceled
    scheduled_date = db.Column(db.DateTime)
    received_date = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    warehouse = relationship('Warehouse', backref='receipts')
    creator = relationship('User', backref='receipts_created')
    
    def to_dict(self):
        return {
            'id': self.id,
            'reference': self.reference,
            'supplier': self.supplier,
            'warehouse': self.warehouse.to_dict() if self.warehouse else None,
            'status': self.status,
            'scheduled_date': self.scheduled_date.isoformat() if self.scheduled_date else None,
            'received_date': self.received_date.isoformat() if self.received_date else None,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class ReceiptLine(db.Model):
    __tablename__ = 'receipt_lines'
    id = db.Column(db.Integer, primary_key=True)
    receipt_id = db.Column(db.Integer, db.ForeignKey('receipts.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity_expected = db.Column(db.Float, nullable=False)
    quantity_received = db.Column(db.Float, default=0)
    
    receipt = relationship('Receipt', backref='lines')
    product = relationship('Product', backref='receipt_lines')
    
    def to_dict(self):
        return {
            'id': self.id,
            'product': self.product.to_dict() if self.product else None,
            'quantity_expected': self.quantity_expected,
            'quantity_received': self.quantity_received
        }

class Delivery(db.Model):
    __tablename__ = 'deliveries'
    id = db.Column(db.Integer, primary_key=True)
    reference = db.Column(db.String(100), unique=True, nullable=False)
    customer = db.Column(db.String(200))
    warehouse_id = db.Column(db.Integer, db.ForeignKey('warehouses.id'), nullable=False)
    status = db.Column(db.String(50), default='draft')  # draft, waiting, ready, done, canceled
    scheduled_date = db.Column(db.DateTime)
    delivery_date = db.Column(db.DateTime)
    shipping_address = db.Column(db.Text)
    notes = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    warehouse = relationship('Warehouse', backref='deliveries')
    creator = relationship('User', backref='deliveries_created')
    
    def to_dict(self):
        return {
            'id': self.id,
            'reference': self.reference,
            'customer': self.customer,
            'warehouse': self.warehouse.to_dict() if self.warehouse else None,
            'status': self.status,
            'scheduled_date': self.scheduled_date.isoformat() if self.scheduled_date else None,
            'delivery_date': self.delivery_date.isoformat() if self.delivery_date else None,
            'shipping_address': self.shipping_address,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class DeliveryLine(db.Model):
    __tablename__ = 'delivery_lines'
    id = db.Column(db.Integer, primary_key=True)
    delivery_id = db.Column(db.Integer, db.ForeignKey('deliveries.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity_ordered = db.Column(db.Float, nullable=False)
    quantity_delivered = db.Column(db.Float, default=0)
    
    delivery = relationship('Delivery', backref='lines')
    product = relationship('Product', backref='delivery_lines')
    
    def to_dict(self):
        return {
            'id': self.id,
            'product': self.product.to_dict() if self.product else None,
            'quantity_ordered': self.quantity_ordered,
            'quantity_delivered': self.quantity_delivered
        }

class InternalTransfer(db.Model):
    __tablename__ = 'internal_transfers'
    id = db.Column(db.Integer, primary_key=True)
    reference = db.Column(db.String(100), unique=True, nullable=False)
    from_warehouse_id = db.Column(db.Integer, db.ForeignKey('warehouses.id'), nullable=False)
    to_warehouse_id = db.Column(db.Integer, db.ForeignKey('warehouses.id'), nullable=False)
    status = db.Column(db.String(50), default='draft')
    scheduled_date = db.Column(db.DateTime)
    transfer_date = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    from_warehouse = relationship('Warehouse', foreign_keys=[from_warehouse_id], backref='transfers_out')
    to_warehouse = relationship('Warehouse', foreign_keys=[to_warehouse_id], backref='transfers_in')
    creator = relationship('User', backref='transfers_created')
    
    def to_dict(self):
        return {
            'id': self.id,
            'reference': self.reference,
            'from_warehouse': self.from_warehouse.to_dict() if self.from_warehouse else None,
            'to_warehouse': self.to_warehouse.to_dict() if self.to_warehouse else None,
            'status': self.status,
            'scheduled_date': self.scheduled_date.isoformat() if self.scheduled_date else None,
            'transfer_date': self.transfer_date.isoformat() if self.transfer_date else None,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class TransferLine(db.Model):
    __tablename__ = 'transfer_lines'
    id = db.Column(db.Integer, primary_key=True)
    transfer_id = db.Column(db.Integer, db.ForeignKey('internal_transfers.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    
    transfer = relationship('InternalTransfer', backref='lines')
    product = relationship('Product', backref='transfer_lines')
    
    def to_dict(self):
        return {
            'id': self.id,
            'product': self.product.to_dict() if self.product else None,
            'quantity': self.quantity
        }

class StockAdjustment(db.Model):
    __tablename__ = 'stock_adjustments'
    id = db.Column(db.Integer, primary_key=True)
    reference = db.Column(db.String(100), unique=True, nullable=False)
    warehouse_id = db.Column(db.Integer, db.ForeignKey('warehouses.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    old_quantity = db.Column(db.Float, nullable=False)
    new_quantity = db.Column(db.Float, nullable=False)
    adjustment_type = db.Column(db.String(50))  # damage, loss, found, correction
    reason = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    warehouse = relationship('Warehouse', backref='adjustments')
    product = relationship('Product', backref='adjustments')
    creator = relationship('User', backref='adjustments_created')
    
    def to_dict(self):
        return {
            'id': self.id,
            'reference': self.reference,
            'warehouse': self.warehouse.to_dict() if self.warehouse else None,
            'product': self.product.to_dict() if self.product else None,
            'old_quantity': self.old_quantity,
            'new_quantity': self.new_quantity,
            'adjustment': self.new_quantity - self.old_quantity,
            'adjustment_type': self.adjustment_type,
            'reason': self.reason,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class StockMove(db.Model):
    __tablename__ = 'stock_moves'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    warehouse_id = db.Column(db.Integer, db.ForeignKey('warehouses.id'), nullable=False)
    move_type = db.Column(db.String(50), nullable=False)  # receipt, delivery, transfer_in, transfer_out, adjustment
    reference = db.Column(db.String(100))
    quantity = db.Column(db.Float, nullable=False)
    move_date = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    product = relationship('Product', backref='moves')
    warehouse = relationship('Warehouse', backref='moves')
    creator = relationship('User', backref='moves_created')
    
    def to_dict(self):
        return {
            'id': self.id,
            'product': self.product.to_dict() if self.product else None,
            'warehouse': self.warehouse.to_dict() if self.warehouse else None,
            'move_type': self.move_type,
            'reference': self.reference,
            'quantity': self.quantity,
            'move_date': self.move_date.isoformat() if self.move_date else None
        }

# ==================== HELPER FUNCTIONS ====================

def generate_reference(prefix):
    """Generate unique reference number"""
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    return f"{prefix}-{timestamp}"

def update_stock(product_id, warehouse_id, quantity_change, move_type, reference, user_id):
    """Update stock and create stock move"""
    stock = Stock.query.filter_by(product_id=product_id, warehouse_id=warehouse_id).first()
    
    if not stock:
        stock = Stock(product_id=product_id, warehouse_id=warehouse_id, quantity=0)
        db.session.add(stock)
    
    stock.quantity += quantity_change
    
    # Create stock move record
    move = StockMove(
        product_id=product_id,
        warehouse_id=warehouse_id,
        move_type=move_type,
        reference=reference,
        quantity=quantity_change,
        created_by=user_id
    )
    db.session.add(move)

def check_low_stock():
    """Check for low stock items"""
    low_stock_items = []
    stocks = Stock.query.join(Product).filter(Product.is_active == True).all()
    
    for stock in stocks:
        available = stock.quantity - stock.reserved_quantity
        if available <= stock.product.reorder_level:
            low_stock_items.append({
                'product': stock.product.to_dict(),
                'warehouse': stock.warehouse.to_dict(),
                'available_quantity': available,
                'reorder_level': stock.product.reorder_level
            })
    
    return low_stock_items

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.get_json()
    
    # Check for duplicates
    if User.query.filter_by(username=data.get('username')).first():
        return jsonify({'error': 'Username already exists'}), 400
        
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    # Create the user
    new_user = User(
        username=data.get('username'),
        email=data.get('email'),
        full_name=data.get('full_name'),
        role='admin'  # <--- CHANGED FROM 'staff' TO 'admin'
    )
    new_user.set_password(data.get('password'))
    
    db.session.add(new_user)
    db.session.commit()
    
    # Auto-login the user
    access_token = create_access_token(identity=new_user.id)
    
    return jsonify({
        'message': 'User created successfully',
        'access_token': access_token,
        'user': new_user.to_dict()
    }), 201


# ---------------------------------------------------------
# PASTE THIS CODE INTO app.py (AFTER signup, BEFORE root)
# ---------------------------------------------------------

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        # 1. Get data from the frontend
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        # 2. Find the user in the database
        user = User.query.filter_by(username=username).first()

        # 3. Check if user exists AND password is correct
        if user and user.check_password(password):
            # 4. Create a security token (JWT)
            access_token = create_access_token(identity=user.id)
            
            # 5. Send success response
            return jsonify({
                'message': 'Login successful',
                'access_token': access_token,
                'user': user.to_dict()
            }), 200
        
        # 6. If login fails
        return jsonify({'error': 'Invalid username or password'}), 401

    except Exception as e:
        print(f"Login Error: {e}")
        return jsonify({'error': 'Server error during login'}), 500

@app.route('/api/auth/profile', methods=['GET'])
@jwt_required()
def get_profile():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(user.to_dict()), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        
        if 'full_name' in data:
            user.full_name = data['full_name']
        if 'email' in data:
            user.email = data['email']
        
        db.session.commit()
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ==================== DASHBOARD ROUTES ====================

@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard():
    try:
        # Total products
        total_products = Product.query.filter_by(is_active=True).count()
        
        # Low stock items
        low_stock = check_low_stock()
        low_stock_count = len(low_stock)
        
        # Out of stock
        out_of_stock = Stock.query.filter(Stock.quantity <= 0).count()
        
        # Pending receipts
        pending_receipts = Receipt.query.filter(
            Receipt.status.in_(['draft', 'waiting', 'ready'])
        ).count()
        
        # Pending deliveries
        pending_deliveries = Delivery.query.filter(
            Delivery.status.in_(['draft', 'waiting', 'ready'])
        ).count()
        
        # Internal transfers scheduled
        scheduled_transfers = InternalTransfer.query.filter(
            InternalTransfer.status.in_(['draft', 'waiting', 'ready'])
        ).count()
        
        # Recent moves (last 10)
        recent_moves = StockMove.query.order_by(
            StockMove.move_date.desc()
        ).limit(10).all()
        
        return jsonify({
            'kpis': {
                'total_products': total_products,
                'low_stock_items': low_stock_count,
                'out_of_stock_items': out_of_stock,
                'pending_receipts': pending_receipts,
                'pending_deliveries': pending_deliveries,
                'scheduled_transfers': scheduled_transfers
            },
            'low_stock_alerts': low_stock[:5],  # Top 5 low stock items
            'recent_moves': [move.to_dict() for move in recent_moves]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== PRODUCT ROUTES ====================

@app.route('/api/products', methods=['GET'])
@jwt_required()
def get_products():
    try:
        # Query parameters for filtering
        category_id = request.args.get('category_id', type=int)
        warehouse_id = request.args.get('warehouse_id', type=int)
        search = request.args.get('search', '')
        
        query = Product.query.filter_by(is_active=True)
        
        if category_id:
            query = query.filter_by(category_id=category_id)
        
        if search:
            query = query.filter(
                or_(
                    Product.name.ilike(f'%{search}%'),
                    Product.sku.ilike(f'%{search}%')
                )
            )
        
        products = query.all()
        
        # If warehouse filter, get stock info
        if warehouse_id:
            result = []
            for product in products:
                stock = Stock.query.filter_by(
                    product_id=product.id,
                    warehouse_id=warehouse_id
                ).first()
                
                product_data = product.to_dict()
                product_data['stock'] = stock.to_dict() if stock else None
                result.append(product_data)
            
            return jsonify(result), 200
        
        return jsonify([p.to_dict() for p in products]), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/products', methods=['POST'])
@jwt_required()
def create_product():
    try:
        data = request.get_json()
        
        if not all(k in data for k in ['name', 'sku']):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Check if SKU exists
        if Product.query.filter_by(sku=data['sku']).first():
            return jsonify({'error': 'SKU already exists'}), 400
        
        product = Product(
            name=data['name'],
            sku=data['sku'],
            category_id=data.get('category_id'),
            unit_of_measure=data.get('unit_of_measure', 'Units'),
            reorder_level=data.get('reorder_level', 0),
            description=data.get('description', '')
        )
        
        db.session.add(product)
        db.session.commit()
        
        # Initialize stock if provided
        if 'initial_stock' in data and data['initial_stock'] > 0:
            warehouse_id = data.get('warehouse_id', 1)  # Default warehouse
            stock = Stock(
                product_id=product.id,
                warehouse_id=warehouse_id,
                quantity=data['initial_stock']
            )
            db.session.add(stock)
            db.session.commit()
        
        return jsonify({
            'message': 'Product created successfully',
            'product': product.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/products/', methods=['GET'])
@jwt_required()
def get_product(product_id):
    try:
        product = Product.query.get(product_id)
        
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        # Get stock levels across all warehouses
        stocks = Stock.query.filter_by(product_id=product_id).all()
        
        product_data = product.to_dict()
        product_data['stock_levels'] = [s.to_dict() for s in stocks]
        
        return jsonify(product_data), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/products/', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    try:
        product = Product.query.get(product_id)
        
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        data = request.get_json()
        
        if 'name' in data:
            product.name = data['name']
        if 'category_id' in data:
            product.category_id = data['category_id']
        if 'unit_of_measure' in data:
            product.unit_of_measure = data['unit_of_measure']
        if 'reorder_level' in data:
            product.reorder_level = data['reorder_level']
        if 'description' in data:
            product.description = data['description']
        
        db.session.commit()
        
        return jsonify({
            'message': 'Product updated successfully',
            'product': product.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/products/', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    try:
        product = Product.query.get(product_id)
        
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        # Soft delete
        product.is_active = False
        db.session.commit()
        
        return jsonify({'message': 'Product deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ==================== CATEGORY ROUTES ====================

@app.route('/api/categories', methods=['GET'])
@jwt_required()
def get_categories():
    try:
        categories = Category.query.all()
        return jsonify([c.to_dict() for c in categories]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/categories', methods=['POST'])
@jwt_required()
def create_category():
    try:
        data = request.get_json()
        
        if 'name' not in data:
            return jsonify({'error': 'Name is required'}), 400
        
        category = Category(
            name=data['name'],
            description=data.get('description', ''),
            parent_id=data.get('parent_id')
        )
        
        db.session.add(category)
        db.session.commit()
        
        return jsonify({
            'message': 'Category created successfully',
            'category': category.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ==================== WAREHOUSE ROUTES ====================

@app.route('/api/warehouses', methods=['GET'])
@jwt_required()
def get_warehouses():
    try:
        warehouses = Warehouse.query.filter_by(is_active=True).all()
        return jsonify([w.to_dict() for w in warehouses]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/warehouses', methods=['POST'])
@jwt_required()
def create_warehouse():
    try:
        data = request.get_json()
        
        if not all(k in data for k in ['name', 'code']):
            return jsonify({'error': 'Missing required fields'}), 400
        
        if Warehouse.query.filter_by(code=data['code']).first():
            return jsonify({'error': 'Warehouse code already exists'}), 400
        
        warehouse = Warehouse(
            name=data['name'],
            code=data['code'],
            location=data.get('location', '')
        )
        
        db.session.add(warehouse)
        db.session.commit()
        
        return jsonify({
            'message': 'Warehouse created successfully',
            'warehouse': warehouse.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ==================== RECEIPT ROUTES ====================

@app.route('/api/receipts', methods=['GET'])
@jwt_required()
def get_receipts():
    try:
        status = request.args.get('status')
        warehouse_id = request.args.get('warehouse_id', type=int)
        
        query = Receipt.query
        
        if status:
            query = query.filter_by(status=status)
        if warehouse_id:
            query = query.filter_by(warehouse_id=warehouse_id)
        
        receipts = query.order_by(Receipt.created_at.desc()).all()
        
        result = []
        for receipt in receipts:
            receipt_data = receipt.to_dict()
            receipt_data['lines'] = [line.to_dict() for line in receipt.lines]
            result.append(receipt_data)
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/receipts', methods=['POST'])
@jwt_required()
def create_receipt():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not all(k in data for k in ['warehouse_id', 'lines']):
            return jsonify({'error': 'Missing required fields'}), 400
        
        receipt = Receipt(
            reference=generate_reference('RCP'),
            supplier=data.get('supplier', ''),
            warehouse_id=data['warehouse_id'],
            status='draft',
            scheduled_date=datetime.fromisoformat(data['scheduled_date']) if 'scheduled_date' in data else None,
            notes=data.get('notes', ''),
            created_by=user_id
        )
        
        db.session.add(receipt)
        db.session.flush()
        
        # Add receipt lines
        for line_data in data['lines']:
            line = ReceiptLine(
                receipt_id=receipt.id,
                product_id=line_data['product_id'],
                quantity_expected=line_data['quantity']
            )
            db.session.add(line)
        
        db.session.commit()
        
        receipt_data = receipt.to_dict()
        receipt_data['lines'] = [line.to_dict() for line in receipt.lines]
        
        return jsonify({
            'message': 'Receipt created successfully',
            'receipt': receipt_data
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/receipts//validate', methods=['POST'])
@jwt_required()
def validate_receipt(receipt_id):
    try:
        user_id = get_jwt_identity()
        receipt = Receipt.query.get(receipt_id)
        
        if not receipt:
            return jsonify({'error': 'Receipt not found'}), 404
        
        if receipt.status == 'done':
            return jsonify({'error': 'Receipt already validated'}), 400
        
        # Update stock for each line
        for line in receipt.lines:
            quantity = line.quantity_received if line.quantity_received > 0 else line.quantity_expected
            update_stock(
                line.product_id,
                receipt.warehouse_id,
                quantity,
                'receipt',
                receipt.reference,
                user_id
            )
        
        receipt.status = 'done'
        receipt.received_date = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'message': 'Receipt validated successfully',
            'receipt': receipt.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ==================== DELIVERY ROUTES ====================

@app.route('/api/deliveries', methods=['GET'])
@jwt_required()
def get_deliveries():
    try:
        status = request.args.get('status')
        warehouse_id = request.args.get('warehouse_id', type=int)
        
        query = Delivery.query
        
        if status:
            query = query.filter_by(status=status)
        if warehouse_id:
            query = query.filter_by(warehouse_id=warehouse_id)
        
        deliveries = query.order_by(Delivery.created_at.desc()).all()
        
        result = []
        for delivery in deliveries:
            delivery_data = delivery.to_dict()
            delivery_data['lines'] = [line.to_dict() for line in delivery.lines]
            result.append(delivery_data)
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deliveries', methods=['POST'])
@jwt_required()
def create_delivery():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not all(k in data for k in ['warehouse_id', 'lines']):
            return jsonify({'error': 'Missing required fields'}), 400
        
        delivery = Delivery(
            reference=generate_reference('DLV'),
            customer=data.get('customer', ''),
            warehouse_id=data['warehouse_id'],
            status='draft',
            scheduled_date=datetime.fromisoformat(data['scheduled_date']) if 'scheduled_date' in data else None,
            shipping_address=data.get('shipping_address', ''),
            notes=data.get('notes', ''),
            created_by=user_id
        )
        
        db.session.add(delivery)
        db.session.flush()
        
        # Add delivery lines
        for line_data in data['lines']:
            line = DeliveryLine(
                delivery_id=delivery.id,
                product_id=line_data['product_id'],
                quantity_ordered=line_data['quantity']
            )
            db.session.add(line)
        
        db.session.commit()
        
        delivery_data = delivery.to_dict()
        delivery_data['lines'] = [line.to_dict() for line in delivery.lines]
        
        return jsonify({
            'message': 'Delivery created successfully',
            'delivery': delivery_data
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/deliveries//validate', methods=['POST'])
@jwt_required()
def validate_delivery(delivery_id):
    try:
        user_id = get_jwt_identity()
        delivery = Delivery.query.get(delivery_id)
        
        if not delivery:
            return jsonify({'error': 'Delivery not found'}), 404
        
        if delivery.status == 'done':
            return jsonify({'error': 'Delivery already validated'}), 400
        
        # Update stock for each line
        for line in delivery.lines:
            quantity = line.quantity_delivered if line.quantity_delivered > 0 else line.quantity_ordered
            
            # Check if sufficient stock
            stock = Stock.query.filter_by(
                product_id=line.product_id,
                warehouse_id=delivery.warehouse_id
            ).first()
            
            if not stock or stock.quantity < quantity:
                return jsonify({'error': f'Insufficient stock for product {line.product.name}'}), 400
            
            update_stock(
                line.product_id,
                delivery.warehouse_id,
                -quantity,
                'delivery',
                delivery.reference,
                user_id
            )
        
        delivery.status = 'done'
        delivery.delivery_date = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'message': 'Delivery validated successfully',
            'delivery': delivery.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ==================== INTERNAL TRANSFER ROUTES ====================

@app.route('/api/transfers', methods=['GET'])
@jwt_required()
def get_transfers():
    try:
        status = request.args.get('status')
        
        query = InternalTransfer.query
        
        if status:
            query = query.filter_by(status=status)
        
        transfers = query.order_by(InternalTransfer.created_at.desc()).all()
        
        result = []
        for transfer in transfers:
            transfer_data = transfer.to_dict()
            transfer_data['lines'] = [line.to_dict() for line in transfer.lines]
            result.append(transfer_data)
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/transfers', methods=['POST'])
@jwt_required()
def create_transfer():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not all(k in data for k in ['from_warehouse_id', 'to_warehouse_id', 'lines']):
            return jsonify({'error': 'Missing required fields'}), 400
        
        if data['from_warehouse_id'] == data['to_warehouse_id']:
            return jsonify({'error': 'Source and destination warehouses must be different'}), 400
        
        transfer = InternalTransfer(
            reference=generate_reference('TRF'),
            from_warehouse_id=data['from_warehouse_id'],
            to_warehouse_id=data['to_warehouse_id'],
            status='draft',
            scheduled_date=datetime.fromisoformat(data['scheduled_date']) if 'scheduled_date' in data else None,
            notes=data.get('notes', ''),
            created_by=user_id
        )
        
        db.session.add(transfer)
        db.session.flush()
        
        # Add transfer lines
        for line_data in data['lines']:
            line = TransferLine(
                transfer_id=transfer.id,
                product_id=line_data['product_id'],
                quantity=line_data['quantity']
            )
            db.session.add(line)
        
        db.session.commit()
        
        transfer_data = transfer.to_dict()
        transfer_data['lines'] = [line.to_dict() for line in transfer.lines]
        
        return jsonify({
            'message': 'Transfer created successfully',
            'transfer': transfer_data
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/transfers//validate', methods=['POST'])
@jwt_required()
def validate_transfer(transfer_id):
    try:
        user_id = get_jwt_identity()
        transfer = InternalTransfer.query.get(transfer_id)
        
        if not transfer:
            return jsonify({'error': 'Transfer not found'}), 404
        
        if transfer.status == 'done':
            return jsonify({'error': 'Transfer already validated'}), 400
        
        # Update stock for each line
        for line in transfer.lines:
            # Check if sufficient stock in source
            stock = Stock.query.filter_by(
                product_id=line.product_id,
                warehouse_id=transfer.from_warehouse_id
            ).first()
            
            if not stock or stock.quantity < line.quantity:
                return jsonify({'error': f'Insufficient stock for product {line.product.name}'}), 400
            
            # Decrease from source
            update_stock(
                line.product_id,
                transfer.from_warehouse_id,
                -line.quantity,
                'transfer_out',
                transfer.reference,
                user_id
            )
            
            # Increase in destination
            update_stock(
                line.product_id,
                transfer.to_warehouse_id,
                line.quantity,
                'transfer_in',
                transfer.reference,
                user_id
            )
        
        transfer.status = 'done'
        transfer.transfer_date = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'message': 'Transfer validated successfully',
            'transfer': transfer.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ==================== STOCK ADJUSTMENT ROUTES ====================

@app.route('/api/adjustments', methods=['GET'])
@jwt_required()
def get_adjustments():
    try:
        warehouse_id = request.args.get('warehouse_id', type=int)
        product_id = request.args.get('product_id', type=int)
        
        query = StockAdjustment.query
        
        if warehouse_id:
            query = query.filter_by(warehouse_id=warehouse_id)
        if product_id:
            query = query.filter_by(product_id=product_id)
        
        adjustments = query.order_by(StockAdjustment.created_at.desc()).all()
        
        return jsonify([adj.to_dict() for adj in adjustments]), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/adjustments', methods=['POST'])
@jwt_required()
def create_adjustment():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not all(k in data for k in ['warehouse_id', 'product_id', 'new_quantity']):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Get current stock
        stock = Stock.query.filter_by(
            product_id=data['product_id'],
            warehouse_id=data['warehouse_id']
        ).first()
        
        old_quantity = stock.quantity if stock else 0
        new_quantity = data['new_quantity']
        
        # Create adjustment record
        adjustment = StockAdjustment(
            reference=generate_reference('ADJ'),
            warehouse_id=data['warehouse_id'],
            product_id=data['product_id'],
            old_quantity=old_quantity,
            new_quantity=new_quantity,
            adjustment_type=data.get('adjustment_type', 'correction'),
            reason=data.get('reason', ''),
            created_by=user_id
        )
        
        db.session.add(adjustment)
        
        # Update stock
        quantity_change = new_quantity - old_quantity
        update_stock(
            data['product_id'],
            data['warehouse_id'],
            quantity_change,
            'adjustment',
            adjustment.reference,
            user_id
        )
        
        db.session.commit()
        
        return jsonify({
            'message': 'Stock adjusted successfully',
            'adjustment': adjustment.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ==================== STOCK MOVE HISTORY ROUTES ====================

@app.route('/api/moves', methods=['GET'])
@jwt_required()
def get_moves():
    try:
        product_id = request.args.get('product_id', type=int)
        warehouse_id = request.args.get('warehouse_id', type=int)
        move_type = request.args.get('move_type')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        limit = request.args.get('limit', 50, type=int)
        
        query = StockMove.query
        
        if product_id:
            query = query.filter_by(product_id=product_id)
        if warehouse_id:
            query = query.filter_by(warehouse_id=warehouse_id)
        if move_type:
            query = query.filter_by(move_type=move_type)
        if start_date:
            query = query.filter(StockMove.move_date >= datetime.fromisoformat(start_date))
        if end_date:
            query = query.filter(StockMove.move_date <= datetime.fromisoformat(end_date))
        
        moves = query.order_by(StockMove.move_date.desc()).limit(limit).all()
        
        return jsonify([move.to_dict() for move in moves]), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== STOCK ROUTES ====================

@app.route('/api/stock', methods=['GET'])
@jwt_required()
def get_stock():
    try:
        warehouse_id = request.args.get('warehouse_id', type=int)
        product_id = request.args.get('product_id', type=int)
        
        query = Stock.query
        
        if warehouse_id:
            query = query.filter_by(warehouse_id=warehouse_id)
        if product_id:
            query = query.filter_by(product_id=product_id)
        
        stocks = query.all()
        
        return jsonify([stock.to_dict() for stock in stocks]), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== INITIALIZATION ROUTE ====================

@app.route('/api/init', methods=['POST'])
def initialize_database():
    """Initialize database with tables and sample data"""
    try:
        # Create all tables
        db.create_all()
        
        # Check if already initialized
        if User.query.first():
            return jsonify({'message': 'Database already initialized'}), 200
        
        # Create default admin user
        admin = User(
            username='admin',
            email='admin@stockmaster.com',
            full_name='System Administrator',
            role='admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        
        # Create default warehouse
        warehouse = Warehouse(
            name='Main Warehouse',
            code='WH001',
            location='Main Building'
        )
        db.session.add(warehouse)
        
        # Create sample categories
        categories = [
            Category(name='Raw Materials', description='Raw materials for production'),
            Category(name='Finished Goods', description='Ready to sell products'),
            Category(name='Consumables', description='Office and warehouse consumables')
        ]
        db.session.add_all(categories)
        
        db.session.commit()
        
        return jsonify({
            'message': 'Database initialized successfully',
            'admin_credentials': {
                'username': 'admin',
                'password': 'admin123'
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ==================== HEALTH CHECK ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

@app.route('/', methods=['GET'])
def root():
    """Redirect to login page"""
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET'])
def login_page():
    """Render login page"""
    return render_template('login.html')

@app.route('/signup', methods=['GET'])
def signup_page():
    """Render signup page"""
    return render_template('signup.html')

@app.route('/dashboard', methods=['GET'])
def dashboard_page():
    """Render dashboard page"""
    return render_template('dashboard.html')

@app.route('/products', methods=['GET'])
def products_page():
    """Render products page"""
    return render_template('products.html')

@app.route('/receipts', methods=['GET'])
def receipts_page():
    """Render receipts page"""
    return render_template('receipts.html')

@app.route('/deliveries', methods=['GET'])
def deliveries_page():
    """Render deliveries page (Outgoing Stock)"""
    return render_template('deliveries.html')

@app.route('/transfers', methods=['GET'])
def transfers_page():
    """Render stock transfer page"""
    return render_template('transfers.html')

@app.route('/adjustments', methods=['GET'])
def adjustments_page():
    """Render stock adjustments and corrections page"""
    return render_template('adjustments.html')

@app.route('/history', methods=['GET'])
def history_page():
    """Render stock movement history page"""
    return render_template('history.html') 

@app.route('/warehouses', methods=['GET'])
def warehouses_page():
    """Render warehouse management page"""
    return render_template('warehouses.html')

@app.route('/profile', methods=['GET'])
def profile_page():
    """Render user profile management page"""
    return render_template('profile.html')

@app.route('/api/docs', methods=['GET'])
def api_docs():
    """API Documentation endpoint"""
    return jsonify({
        'message': 'StockMaster API - Backend Only',
        'version': '1.0.0',
        'note': 'This is a REST API backend. Create your frontend templates separately.',
        'endpoints': {
            'auth': '/api/auth/*',
            'dashboard': '/api/dashboard',
            'products': '/api/products',
            'warehouses': '/api/warehouses',
            'receipts': '/api/receipts',
            'deliveries': '/api/deliveries',
            'transfers': '/api/transfers',
            'adjustments': '/api/adjustments',
            'stock': '/api/stock',
            'moves': '/api/moves'
        }
    }), 200

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'Authorization token is missing'}), 401


# ==================== RUN APP ====================

if __name__ == '__main__':
    # Auto-initialize database on startup
    with app.app_context():
        db.create_all()
        print("✅ Database tables initialized!")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
