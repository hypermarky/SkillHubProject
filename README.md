# Skillhub

Skillhub is a social platform built with Flask and MySQL where users can showcase their skills, follow each other, create posts with images or videos, like and comment on posts, send direct messages, and receive notifications about likes, follows, and messages. Its user-friendly interface and minimalistic design offer a seamless experience for connecting and sharing.

## Features

- **User Registration & Login:**  
  Create an account, log in, and manage your profile.

- **Profiles & Skills:**  
  Each user has a profile page displaying their profile picture, bio, skills, follower/following counts, and posts. Users can add new skills to their profile.

- **Posts (Images & Videos):**  
  Users can create posts with images or videos to show off their talents. Other users can view posts on the main feed or the profile of the user who created them.

- **Follow System:**  
  Users can follow others to see their posts in the main feed. Mutual following makes them "friends."

- **Likes & Comments:**  
  Engage with posts by liking and commenting. Post owners can delete their own posts, and comment authors can remove their comments.

- **Private Messaging:**  
  Users who follow someone can send up to 3 private messages. If the follow becomes mutual, both become "friends" and can message each other without limits.

- **Notifications:**  
  Users receive notifications when someone follows them, likes their post, or sends them a message. Unread notifications are highlighted, and users can mark them as read.

## Tech Stack

- **Backend:**  
  - [Flask](https://flask.palletsprojects.com/) (Python)
  - [Flask-Login](https://flask-login.readthedocs.io/) for authentication
  - [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/) as the ORM

- **Database:**  
  - MySQL (accessed via [PyMySQL](https://pypi.org/project/PyMySQL/))

- **Frontend:**  
  - Jinja2 templates
  - [Bootstrap 5](https://getbootstrap.com/) for styling
  - Custom CSS and JS as needed

- **File Handling:**  
  - Flask built-in functionalities for image/video uploads and serving static files

## Getting Started

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/skillhub.git
   cd skillhub

# 2. Installing Dependencies

To install all the required dependencies for the project, run the following command in your terminal:

```bash
pip install -r requirements.txt
```

# 3. Setup and Configuration

## Set Up the Database in MySQL

Run the following SQL commands in your MySQL environment:

```sql
CREATE DATABASE skillhub_db;
CREATE USER 'skillhub_user'@'localhost' IDENTIFIED BY 'password123';
GRANT ALL PRIVILEGES ON skillhub_db.* TO 'skillhub_user'@'localhost';
FLUSH PRIVILEGES;
```

# 4. Running the application 
## Run the following command in terminal
```bash
python app.py
```

# Project Structure
## This is how you want your project folder to look like
```arduino
skillhub/
    app.py
    config.py
    requirements.txt
    static/
        css/
            style.css
        js/
            script.js
        images/
            default_profile.png
        uploads/
    templates/
        base.html
        index.html
        login.html
        register.html
        profile.html
        upload.html
        skill_form.html
        followers.html
        following.html
        messages.html
        notifications.html
    models/
        __init__.py
        user_model.py
        post_model.py
        skill_model.py
        follow_model.py
        like_model.py
        comment_model.py
        message_model.py
        notification_model.py
    utils/
        __init__.py
        database.py
        helpers.py
```






