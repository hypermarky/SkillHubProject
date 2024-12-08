from utils.database import db
from datetime import datetime

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # who receives the notification
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) # who triggered the notification
    type = db.Column(db.String(50), nullable=False)  # "like", "follow", "message"
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=True)  # for "like" notifications
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=True)  # for "message" notifications
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

    recipient = db.relationship('User', foreign_keys=[user_id], backref='received_notifications')
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_notifications')
    post = db.relationship('Post', foreign_keys=[post_id], backref='like_notifications')
    message = db.relationship('Message', foreign_keys=[message_id], backref='message_notifications')
