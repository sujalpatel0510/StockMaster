from flask import Flask, request, jsonify
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
    role = db.Column(db.String(50), default='staff')  # admin, manager, staff
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



# ==================== RUN APP ====================

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)