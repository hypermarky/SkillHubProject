from utils.database import db
from datetime import datetime

class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Receiver of the notification
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Sender of the action
    type = db.Column(db.String(50), nullable=False)  # Type of notification ('like', 'follow', 'message', etc.)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=True)  # Associated post, if applicable
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=True)  # Associated message, if applicable
    read = db.Column(db.Boolean, default=False)  # Whether the notification has been read
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    receiver = db.relationship('User', foreign_keys=[user_id], backref='received_notifications')
    sender = db.relationship('User', foreign_keys=[sender_id])
    post = db.relationship('Post', foreign_keys=[post_id])
    message = db.relationship('Message', foreign_keys=[message_id])

    def mark_as_read(self):
        """Mark the notification as read."""
        self.read = True
        db.session.commit()
