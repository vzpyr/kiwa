from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    files = db.relationship('File', backref='owner', lazy=True, cascade='all, delete-orphan')
    password_reset_token = db.Column(db.String(120), nullable=True)
    password_reset_expires = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def __repr__(self):
        return f'<User {self.username}>'


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    file_size = db.Column(db.Integer, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime, nullable=True)
    download_limit = db.Column(db.Integer, nullable=True)
    download_count = db.Column(db.Integer, default=0)
    password_hash = db.Column(db.String(120), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    def set_password(self, password):
        if password:
            self.password_hash = generate_password_hash(password)
        else:
            self.password_hash = None
            
    def check_password(self, password):
        if not self.password_hash:
            return True
        return check_password_hash(self.password_hash, password)
        
    def is_expired(self):
        if self.download_limit and self.download_count >= self.download_limit:
            return True
        if self.expiry_date and datetime.utcnow() > self.expiry_date:
            return True
        return False
        
    def get_file_path(self):
        from flask import current_app
        return os.path.join(current_app.config['UPLOAD_FOLDER'], self.stored_filename)
        
    def __repr__(self):
        return f'<File {self.original_filename}>'