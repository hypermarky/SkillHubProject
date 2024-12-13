from utils.database import db
from datetime import datetime

class AdminLog(db.Model):
    __tablename__ = 'admin_log'
    __table_args__ = {'extend_existing': True}  # Prevent duplicate definition error

    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    admin = db.relationship('User', backref='admin_logs')