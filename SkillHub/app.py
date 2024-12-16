import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from config import Config
from utils.database import db
from models.user_model import User
from models.post_model import Post
from models.skill_model import Skill
from werkzeug.utils import secure_filename
from models.follow_model import Follow
from models.like_model import Like
from models.comment_model import Comment
from models.message_model import Message
from models.admin_log import AdminLog
from models.notification_model import Notification
from models.report_model import Report
from flask_socketio import SocketIO
from datetime import datetime, timedelta
from sqlalchemy.sql.expression import func
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_migrate import Migrate
import re



app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"


limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
Talisman(app,
    content_security_policy={
        'default-src': "'self'",
        'img-src': "'self' data: https:",
        'script-src': "'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        'style-src': "'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com",
        'font-src': "'self' https://fonts.gstatic.com",
    },
    force_https=True 
)

# Session configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60)
)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size


@app.before_first_request
def create_tables():
    db.create_all()
    
    # Create upload directory if it doesn't exist
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user:
        app.logger.info(f"User loaded: {user.username}")
    else:
        app.logger.warning(f"No user found with ID: {user_id}")
    return user


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    search = request.args.get('search', '').strip()

    sort_by = request.args.get('sort_by', 'recent')

    if sort_by == 'popularity':
        posts = Post.query.order_by(Post.likes_count.desc()).limit(10).all()
    elif sort_by == 'controversial':
        posts = Post.query.order_by(Post.id.desc()).limit(10).all()
    else:
        posts = Post.query.order_by(Post.created_at.desc()).limit(10).all()

    suggested_users = User.query.order_by(func.random()).limit(10).all()

    trending_skills = [
        {'skill_name': 'Python', 'popularity': 120},
        {'skill_name': 'Web Development', 'popularity': 100},
        {'skill_name': 'Data Science', 'popularity': 90},
        {'skill_name': 'Graphic Design', 'popularity': 80},
        {'skill_name': 'UI/UX', 'popularity': 75}
    ]

    return render_template('index.html', posts=posts, suggested_users=suggested_users, trending_skills=trending_skills)

@app.before_request
def check_ban_status():
    if current_user.is_authenticated and current_user.is_banned:
        flash("Your account has been banned. Please contact support.", "danger")
        logout_user()
        return redirect(url_for('login'))

with app.app_context():
    db.create_all()


def is_password_strong(password):
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password')
        profile_pic = request.files.get('profile_pic')

        # Validation
        if len(username) < 3 or ' ' in username:
            flash('Username must be at least 3 characters long and cannot contain spaces.', 'warning')
            return redirect(url_for('register'))

        if not email.endswith('@gmail.com'):
            flash('Only Gmail addresses are allowed.', 'warning')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'warning')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'warning')
            return redirect(url_for('register'))

        # Create a new user instance
        new_user = User(username=username, email=email)
        new_user.set_password(password)  # Ensure you have this method in your User model

        # Handle profile picture upload
        if profile_pic:
            filename = secure_filename(profile_pic.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            profile_pic.save(file_path)
            new_user.profile_pic = f'{filename}'

        # Add to database
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error saving user: {e}")
            flash('An error occurred. Please try again.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            if user.is_banned:
                flash("Your account has been banned. Please contact support.", "danger")
                return redirect(url_for('login'))

            # Log in the user
            login_user(user, remember=True)  # Set `remember=True` for persistent sessions
            app.logger.info(f"Login successful for user: {user.username}")
            flash('Login successful.', 'success')
            return redirect(url_for('index'))
        else:
            app.logger.warning(f"Login failed for email: {email}")
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')



@app.route('/debug')
def debug():
    from flask_login import current_user
    return f"Current user: {current_user}, Authenticated: {current_user.is_authenticated}"


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/profile/<int:user_id>')
def profile(user_id):
    user = User.query.get_or_404(user_id)
    posts = (
        Post.query
        .filter_by(user_id=user.id)
        .order_by(Post.created_at.desc())
    )
    skills = Skill.query.filter_by(user_id=user.id).all()
    return render_template('profile.html', user=user, posts=posts, skills=skills)

@app.route('/upload', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
@login_required
def upload():
    if request.method == 'POST':
        content_text = request.form.get('content_text', '').strip()
        file = request.files.get('file')

        if current_user.last_post_time:
            time_since_last_post = (datetime.now() - current_user.last_post_time).total_seconds()
            if time_since_last_post < 30:
                remaining_time = 30 - int(time_since_last_post)
                print("wait 30 seconds")
                flash(f'Please wait {remaining_time} seconds before posting again.', 'warning')
                return redirect(url_for('upload'))

        if not content_text:
            flash('Post content cannot be empty.', 'warning')
            return redirect(url_for('upload'))

        content_image = None
        content_video = None

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            file_extension = filename.rsplit('.', 1)[1].lower()
            if file_extension in ['png', 'jpg', 'jpeg', 'gif']:
                content_image = filename
            elif file_extension in ['mp4', 'mov']:
                content_video = filename
            else:
                flash('Unsupported file type.', 'danger')
                return redirect(url_for('upload'))

        try:
            post = Post(
                user_id=current_user.id, 
                content_text=content_text,
                content_image=content_image, 
                content_video=content_video
            )
            db.session.add(post)
            
            current_user.last_post_time = datetime.now()
            db.session.commit()
            
            flash('Post created successfully!', 'success')
            return redirect(url_for('index'))
        
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while creating the post.', 'danger')
            app.logger.error(f"Post creation error: {str(e)}")
            return redirect(url_for('upload'))

    return render_template('upload.html')

from functools import wraps
from flask import abort

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('index'))

    # Fetch data for the admin dashboard
    total_users = User.query.count()
    total_posts = Post.query.count()
    flagged_posts_count = Report.query.filter_by(report_type='post').count()
    reports = Report.query.all()
    users = User.query.all()
    logs = AdminLog.query.order_by(AdminLog.timestamp.desc()).limit(10).all()

    return render_template(
        'admin_dashboard.html',
        total_users=total_users,
        total_posts=total_posts,
        flagged_posts_count=flagged_posts_count,
        reports=reports,
        users=users,
        logs=logs,
    )


class AdminLog(db.Model):
    __tablename__ = 'admin_log'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/admin_logs')
@login_required
@admin_required
def admin_logs():
    logs = AdminLog.query.order_by(AdminLog.timestamp.desc()).all()
    return render_template('admin_logs.html', logs=logs)


@app.route('/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot modify your own admin status.", "danger")
        return redirect(url_for('admin_dashboard'))

    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f"Admin status {'granted' if user.is_admin else 'revoked'} for {user.username}.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/ban_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def ban_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_banned = not user.is_banned  # Add an `is_banned` column in the `User` model
    db.session.commit()
    flash(f"User {'banned' if user.is_banned else 'unbanned'} successfully.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/unban_user/<int:user_id>', methods=['POST'])
@login_required
def unban_user(user_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    user.is_banned = False
    db.session.commit()

    flash(f"User {user.username} has been unbanned.", "success")
    return redirect(url_for('admin_dashboard'))


@app.route('/flag_post/<int:post_id>', methods=['POST'])
@login_required
def flag_post(post_id):
    post = Post.query.get_or_404(post_id)
    post.is_flagged = True
    db.session.commit()
    flash("Post flagged for review.", "success")
    return redirect(url_for('index'))

@app.route('/admin/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post_admin(post_id):
    if not current_user.is_admin:
        flash("You are not authorized to perform this action.", "danger")
        return redirect(url_for('admin_dashboard'))

    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()

    flash("Post deleted successfully.", "success")
    return redirect(url_for('admin_dashboard'))



@app.route('/report', methods=['POST'])
@limiter.limit("10 per hour")
@login_required
def report():
    reported_user_id = request.form.get('reported_user_id')
    post_id = request.form.get('post_id')
    reason = request.form.get('reason')

    report = Report(
        reporter_id=current_user.id,
        reported_user_id=reported_user_id,
        post_id=post_id,
        reason=reason
    )
    db.session.add(report)
    db.session.commit()
    flash("Report submitted successfully.", "success")
    return redirect(request.referrer or url_for('index'))

@app.route('/admin/reports', methods=['GET'])
@login_required
def admin_reports():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template('admin_reports.html', reports=reports)

@app.route('/resolve_report/<int:report_id>', methods=['POST'])
@login_required
def resolve_report(report_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    report = Report.query.get_or_404(report_id)
    db.session.delete(report)
    db.session.commit()

    flash("Report marked as resolved.", "success")
    return redirect(url_for('admin_reports'))

@app.route('/delete_report/<int:report_id>', methods=['POST'])
@login_required
def delete_report(report_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    report = Report.query.get_or_404(report_id)
    db.session.delete(report)
    db.session.commit()

    flash("Report deleted successfully.", "success")
    return redirect(url_for('admin_reports'))


@app.route('/submit_report', methods=['POST'])
@limiter.limit("10 per hour")
@login_required
def submit_report():
    report_type = request.form.get('report_type')
    report_reason = request.form.get('report_reason')
    reported_user_id = request.form.get('reported_user_id')
    reported_post_id = request.form.get('reported_post_id')

    if not report_type or not report_reason:
        flash("Please provide all required fields.", "danger")
        return redirect(request.referrer)

    # Create a new report
    report = Report(
        report_type=report_type,
        reason=report_reason,
        reported_user_id=reported_user_id if report_type == "user" else None,
        reported_post_id=reported_post_id if report_type == "post" else None,
        reporter_id=current_user.id
    )

    # Add to database
    db.session.add(report)
    db.session.commit()

    flash("Report submitted successfully.", "success")
    return redirect(request.referrer)



@app.route('/follow/<int:user_id>', methods=['POST'])
@login_required
def follow_user(user_id):
    user_to_follow = User.query.get_or_404(user_id)
    if user_to_follow.id == current_user.id:
        flash('You cannot follow yourself.', 'warning')
        return redirect(url_for('profile', user_id=user_id))
    if current_user.is_following(user_to_follow):
        flash('You are already following this user.', 'info')
        return redirect(url_for('profile', user_id=user_id))

    current_user.follow(user_to_follow)
    flash(f'You are now following {user_to_follow.username}.', 'success')

    new_notification = Notification(
        user_id=user_to_follow.id,
        sender_id=current_user.id,
        type='follow'
    )
    db.session.add(new_notification)
    db.session.commit()

    return redirect(url_for('profile', user_id=user_id))

@app.route('/unfollow/<int:user_id>', methods=['POST'])
@login_required
def unfollow_user(user_id):
    user_to_unfollow = User.query.get_or_404(user_id)
    if user_to_unfollow.id == current_user.id:
        flash('You cannot unfollow yourself.', 'warning')
        return redirect(url_for('profile', user_id=user_id))
    if current_user.is_following(user_to_unfollow):
        current_user.unfollow(user_to_unfollow)
        flash(f'You have unfollowed {user_to_unfollow.username}.', 'info')
    else:
        flash('You are not following this user.', 'info')
    return redirect(url_for('profile', user_id=user_id))

@app.route('/profile/<int:user_id>/followers')
def profile_followers(user_id):
    user = User.query.get_or_404(user_id)
    followers = user.get_followers()
    return render_template('followers.html', user=user, followers=followers)

@app.route('/profile/<int:user_id>/following')
def profile_following(user_id):
    user = User.query.get_or_404(user_id)
    following = user.get_following()
    return render_template('following.html', user=user, following=following)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        flash("You are not authorized to delete this post.", "danger")
        return redirect(url_for('profile', user_id=current_user.id))

    Like.query.filter_by(post_id=post_id).delete()
    Notification.query.filter_by(post_id=post_id).delete()

    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully.", "success")
    return redirect(url_for('profile', user_id=current_user.id))

@app.route('/like_post/<int:post_id>', methods=['POST'])
@limiter.limit("60 per hour")
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    if current_user.has_liked(post):
        flash('You already liked this post.', 'info')
        return redirect(request.referrer or url_for('index'))

    new_like = Like(user_id=current_user.id, post_id=post_id)
    db.session.add(new_like)
    db.session.commit()

    if post.user_id != current_user.id:
        new_notification = Notification(
            user_id=post.user_id,
            sender_id=current_user.id,
            type='like',
            post_id=post.id
        )
        db.session.add(new_notification)
        db.session.commit()

    flash('Post liked!', 'success')
    return redirect(request.referrer or url_for('index'))

@app.route('/unlike_post/<int:post_id>', methods=['POST'])
@login_required
def unlike_post(post_id):
    post = Post.query.get_or_404(post_id)
    like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    if like:
        db.session.delete(like)
        db.session.commit()
        flash('Post unliked.', 'info')
    else:
        flash('You have not liked this post.', 'warning')
    return redirect(request.referrer or url_for('index'))

@app.route('/add_comment/<int:post_id>', methods=['POST'])
@limiter.limit("30 per hour")
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form.get('comment_content', '').strip()
    if not content.strip():
        flash('Comment cannot be empty.', 'warning')
        return redirect(request.referrer or url_for('index'))
    comment = Comment(user_id=current_user.id, post_id=post_id, content=content)
    db.session.add(comment)
    db.session.commit()
    flash('Comment added!', 'success')
    return redirect(request.referrer or url_for('index'))

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.user_id != current_user.id:
        flash('You are not authorized to delete this comment.', 'danger')
        return redirect(request.referrer or url_for('index'))
    db.session.delete(comment)
    db.session.commit()
    flash('Comment deleted.', 'info')
    return redirect(request.referrer or url_for('index'))

@app.route('/messages')
@login_required
def messages():
    chat_users = get_chat_users()
    first_user = chat_users[0] if chat_users else None
    conversation = []

    if first_user:
        conversation = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == first_user.id)) |
            ((Message.sender_id == first_user.id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.created_at.asc()).all()

    return render_template(
        'messages.html',
        chat_users=chat_users,
        other_user=first_user,
        conversation=conversation
    )

import logging

@app.route('/send_message/<int:user_id>', methods=['POST'])
@limiter.limit("30 per minute")
@login_required
def send_message(user_id):
    other_user = User.query.get_or_404(user_id)
    content = request.form.get('message_content', '').strip()

    if not content:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': 'Message content cannot be empty'}), 400
        flash('Message content cannot be empty.', 'danger')
        return redirect(url_for('fetch_messages', user_id=user_id))

    if not current_user.is_following(other_user):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': 'You must follow this user to message them'}), 403
        flash('You must follow this user to message them.', 'danger')
        return redirect(url_for('fetch_messages', user_id=user_id))

    friends = current_user.is_friends_with(other_user)
    message_count_from_current = Message.query.filter_by(sender_id=current_user.id, receiver_id=other_user.id).count()
    if not friends and message_count_from_current >= 3:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': 'Message limit reached. Become friends to send more messages.'}), 403
        flash('Message limit reached. Become friends to send more messages.', 'danger')
        return redirect(url_for('fetch_messages', user_id=user_id))

    new_message = Message(sender_id=current_user.id, receiver_id=other_user.id, content=content)
    db.session.add(new_message)
    db.session.commit()

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'sender_id': new_message.sender_id,
            'receiver_id': new_message.receiver_id,
            'content': new_message.content,
            'timestamp': new_message.created_at.strftime('%b %d, %Y %I:%M %p')
        })
    else:
        flash('Message sent successfully.', 'success')
        return redirect(url_for('fetch_messages', user_id=user_id))

def get_chat_users():
    all_users = User.query.join(
        Message,
        ((Message.sender_id == User.id) & (Message.receiver_id == current_user.id)) |
        ((Message.receiver_id == User.id) & (Message.sender_id == current_user.id))
    ).filter(
        User.id != current_user.id
    ).order_by(Message.created_at.desc()).all()

    from collections import OrderedDict
    unique_users = list(OrderedDict((user.id, user) for user in all_users).values())
    return unique_users

@app.route('/messages/<int:user_id>')
@login_required
def fetch_messages(user_id):
    other_user = User.query.get_or_404(user_id)
    conversation = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.created_at.asc()).all()

    return render_template(
        'partials/chat_box.html',
        other_user=other_user,
        conversation=conversation
    )

@app.route('/notifications')
@login_required
def notifications():
    user_notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=user_notifications)

@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notif = Notification.query.get_or_404(notification_id)
    if notif.user_id != current_user.id:
        flash("You are not authorized to mark this notification.", "danger")
        return redirect(url_for('notifications'))
    notif.read = True
    db.session.commit()
    return redirect(url_for('notifications'))

@app.route('/add_skill', methods=['GET', 'POST'])
@login_required
def add_skill():
    if request.method == 'POST':
        skill_name = request.form.get('skill_name')
        proficiency = request.form.get('proficiency')
        logging.debug(f"Received skill_name: {skill_name}, proficiency: {proficiency}")

        if not skill_name:
            flash('Skill name cannot be empty.', 'danger')
            return redirect(url_for('add_skill'))

        skill = Skill(user_id=current_user.id, skill_name=skill_name, proficiency=str(proficiency))
        db.session.add(skill)
        db.session.commit()
        logging.debug("Skill successfully added to the database.")
        flash('Skill added successfully!', 'success')
        return redirect(url_for('profile', user_id=current_user.id))

    return render_template('skill_form.html')
import mimetypes

def is_valid_image(file_path):
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type in ['image/png', 'image/jpeg', 'image/jpg', 'image/gif']

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        # Get form data
        bio = request.form.get('bio', '').strip()
        profile_pic = request.files.get('profile_pic')
        profile_visibility = request.form.get('profile_visibility')
        allow_comments = request.form.get('allow_comments') == 'on'
        comment_permission = request.form.get('comment_permission')
        post_visibility = request.form.get('post_visibility')

        # Update bio and visibility settings
        current_user.bio = bio
        current_user.profile_visibility = profile_visibility
        current_user.allow_comments = allow_comments
        current_user.comment_permission = comment_permission
        current_user.post_visibility = post_visibility

        # Handle profile picture upload
        if profile_pic and allowed_file(profile_pic.filename):
            try:
                # Generate secure filename and save the file
                filename = secure_filename(profile_pic.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                profile_pic.save(file_path)

                # Validate the uploaded image
                if is_valid_image(file_path):
                    current_user.profile_pic = filename
                else:
                    os.remove(file_path)  # Remove invalid file
                    flash('Invalid image type. Please upload PNG, JPG, JPEG, or GIF.', 'danger')
                    return redirect(url_for('settings'))
            except Exception as e:
                app.logger.error(f"Error saving profile picture: {e}")
                flash('An error occurred while uploading the profile picture. Please try again.', 'danger')
                return redirect(url_for('settings'))
        elif profile_pic:
            flash('Invalid file type. Only PNG, JPG, JPEG, and GIF are allowed.', 'danger')
            return redirect(url_for('settings'))

        # Commit changes to database
        try:
            db.session.commit()
            flash("Settings updated successfully!", "success")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error saving settings: {e}")
            flash("An error occurred while saving your settings. Please try again.", "danger")

        return redirect(url_for('settings'))

    return render_template('settings.html', user=current_user)



@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        bio = request.form.get('bio')
        file = request.files.get('profile_pic')
        current_user.bio = bio
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            current_user.profile_pic = filename

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile', user_id=current_user.id))

    return render_template('update_profile.html', user=current_user)

@app.errorhandler(429)  # Too Many Requests
def ratelimit_handler(e):
    return render_template('error.html', 
        error="Rate limit exceeded. Please try again later.",
        retry_after=e.description
    ), 429


if __name__ == '__main__':
    app.run(debug=True, host='localhost', port=5001)
