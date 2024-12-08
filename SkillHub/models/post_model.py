# models/post_model.py

from utils.database import db
from datetime import datetime
from models.like_model import Like
from models.comment_model import Comment  # Import the Comment model

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content_text = db.Column(db.Text, nullable=True)
    content_image = db.Column(db.String(255), nullable=True)
    content_video = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    skill_id = db.Column(db.Integer, db.ForeignKey('skills.id'))  # New field
    user = db.relationship("User", backref="posts")
    skill = db.relationship("Skill", backref="posts") 

    def like_count(self):
        return Like.query.filter_by(post_id=self.id).count()

    def comment_count(self):
        return Comment.query.filter_by(post_id=self.id).count()  # Count comments linked to this post
