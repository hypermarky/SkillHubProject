from utils.database import db
from datetime import datetime

class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(50), nullable=False)  # 'user' or 'post'
    reason = db.Column(db.Text, nullable=False)
    reported_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    reported_post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    reported_user = db.relationship("User", foreign_keys=[reported_user_id], backref="user_reports")
    reported_post = db.relationship("Post", foreign_keys=[reported_post_id], backref="post_reports")
    reporter = db.relationship("User", foreign_keys=[reporter_id], backref="reports_sent")


