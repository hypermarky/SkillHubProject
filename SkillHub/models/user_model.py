from utils.database import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from models.follow_model import Follow
from models.like_model import Like

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    profile_pic = db.Column(db.String(255), nullable=True)
    # Privacy Settings
    # e.g., 'public', 'followers_only', 'friends_only'
    profile_visibility = db.Column(db.String(50), default='public')
    # Post Settings
    # Allow comments: True/False
    allow_comments = db.Column(db.Boolean, default=True)
    # Who can comment: 'everyone', 'friends'
    comment_permission = db.Column(db.String(50), default='everyone')
    # Who can see posts: 'everyone', 'followers', 'friends'
    post_visibility = db.Column(db.String(50), default='everyone')

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
