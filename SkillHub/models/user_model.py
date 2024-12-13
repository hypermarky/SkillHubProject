from utils.database import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from models.follow_model import Follow
from models.like_model import Like
from itsdangerous import URLSafeTimedSerializer
import datetime

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    profile_pic = db.Column(db.String(255), nullable=True, default='static/images/mark.jpeg')
    profile_visibility = db.Column(db.String(50), default='public')
    allow_comments = db.Column(db.Boolean, default=True)
    comment_permission = db.Column(db.String(50), default='everyone')
    post_visibility = db.Column(db.String(50), default='everyone')
    last_post_time = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<User {self.username}>"


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def has_liked(self, post):
        return Like.query.filter_by(user_id=self.id, post_id=post.id).first() is not None

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_following(self, user):
        if user is None:
            return False
        return Follow.query.filter_by(
            follower_id=self.id,
            followed_id=user.id
        ).first() is not None

    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower_id=self.id, followed_id=user.id)
            db.session.add(f)
            db.session.commit()

    def unfollow(self, user):
        f = Follow.query.filter_by(
            follower_id=self.id,
            followed_id=user.id
        ).first()
        if f:
            db.session.delete(f)
            db.session.commit()

    def get_followers(self):
        # Users who follow this user
        return [f.follower for f in self.followers]

    def get_following(self):
        # Users this user is following
        return [f.followed for f in self.following]

    def is_friends_with(self, other_user):
        if not other_user:
            return False
        # Both follow each other
        return self.is_following(other_user) and other_user.is_following(self)
    
