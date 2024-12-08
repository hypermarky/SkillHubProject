import os
from flask import Flask, render_template, request, redirect, url_for, flash
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
from models.notification_model import Notification

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        file = request.files.get('profile_pic')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'warning')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)

        # Handle profile picture
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_user.profile_pic = filename

        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/profile/<int:user_id>')
def profile(user_id):
    user = User.query.get_or_404(user_id)
    posts = Post.query.filter_by(user_id=user.id).all()
    skills = Skill.query.filter_by(user_id=user.id).all()
    return render_template('profile.html', user=user, posts=posts, skills=skills)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        content_text = request.form.get('content_text')
        file = request.files.get('file')
        
        content_image = None
        content_video = None
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            file_extension = filename.rsplit('.', 1)[1].lower()
            if file_extension in ['png', 'jpg', 'jpeg', 'gif']:
                content_image = filename
            else:
                content_video = filename

        post = Post(user_id=current_user.id, content_text=content_text,
                    content_image=content_image, content_video=content_video)
        db.session.add(post)
        db.session.commit()
        flash('Post created successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('upload.html')

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

    # Create a notification
    if user_to_follow.id != current_user.id:
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
    # Get a list of users who follow the given user
    followers = user.get_followers()  # returns a list of User objects
    return render_template('followers.html', user=user, followers=followers)

@app.route('/profile/<int:user_id>/following')
def profile_following(user_id):
    user = User.query.get_or_404(user_id)
    # Get a list of users that this user is following
    following = user.get_following()  # returns a list of User objects
    return render_template('following.html', user=user, following=following)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    # Ensure that the current user is the owner of the post
    if post.user_id != current_user.id:
        flash("You are not authorized to delete this post.", "danger")
        return redirect(url_for('profile', user_id=current_user.id))

    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully.", "success")
    return redirect(url_for('profile', user_id=current_user.id))

@app.route('/like_post/<int:post_id>', methods=['POST'])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    if current_user.has_liked(post):
        flash('You already liked this post.', 'info')
        return redirect(request.referrer or url_for('index'))
    
    new_like = Like(user_id=current_user.id, post_id=post_id)
    db.session.add(new_like)
    db.session.commit()

    # Create a notification for the post owner
    if post.user_id != current_user.id:
        new_notification = Notification(
            user_id=post.user_id,  # the owner of the post
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
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form.get('comment_content')
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

@app.route('/messages/<int:user_id>')
@login_required
def messages_with_user(user_id):
    other_user = User.query.get_or_404(user_id)

    # Check if current_user is following the other_user
    if not current_user.is_following(other_user):
        flash("You must follow this user to message them.", "warning")
        return redirect(url_for('profile', user_id=other_user.id))

    # Retrieve the conversation (both directions)
    conversation = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == other_user.id)) |
        ((Message.sender_id == other_user.id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.created_at.asc()).all()

    # Check friendship status and message limits
    friends = current_user.is_friends_with(other_user)
    message_count_from_current = Message.query.filter_by(sender_id=current_user.id, receiver_id=other_user.id).count()

    return render_template('messages.html', 
                           other_user=other_user, 
                           conversation=conversation,
                           friends=friends,
                           message_count_from_current=message_count_from_current)

@app.route('/send_message/<int:user_id>', methods=['POST'])
@login_required
def send_message(user_id):
    other_user = User.query.get_or_404(user_id)
    content = request.form.get('message_content', '').strip()

    if not content:
        flash("Message cannot be empty.", "warning")
        return redirect(url_for('messages_with_user', user_id=other_user.id))

    # Must follow the other user to send a message
    if not current_user.is_following(other_user):
        flash("You must follow this user to message them.", "warning")
        return redirect(url_for('profile', user_id=other_user.id))

    friends = current_user.is_friends_with(other_user)
    message_count_from_current = Message.query.filter_by(sender_id=current_user.id, receiver_id=other_user.id).count()

    if not friends and message_count_from_current >= 3:
        flash("You have reached the maximum of 3 messages. You must be friends (mutual following) to send more.", "danger")
        return redirect(url_for('messages_with_user', user_id=other_user.id))

    new_message = Message(sender_id=current_user.id, receiver_id=other_user.id, content=content)
    db.session.add(new_message)
    db.session.commit()

    # Create a notification for the receiver of the message
    notification = Notification(
        user_id=other_user.id,
        sender_id=current_user.id,
        type='message',
        message_id=new_message.id
    )
    db.session.add(notification)
    db.session.commit()

    flash("Message sent!", "success")
    return redirect(url_for('messages_with_user', user_id=other_user.id))

@app.route('/notifications')
@login_required
def notifications():
    # Get all notifications for current_user
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
        skill = Skill(user_id=current_user.id, skill_name=skill_name, proficiency=proficiency)
        db.session.add(skill)
        db.session.commit()
        flash('Skill added successfully!', 'success')
        return redirect(url_for('profile', user_id=current_user.id))
    return render_template('skill_form.html')

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


if __name__ == '__main__':
    app.run(debug=True, port=5001)
