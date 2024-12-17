# Info til lærer
### Messaging system tok veldig mye tid og funker men ikke skikkelig, du kan sende meldingen til hverandre men du må refreshe, jeg prøvde å bruke socketIO men det ble alt for mye styr.
### På profilen til folk kan du se at following system har blitt ødelagt og du ikke kan trykke message fra der, for å sende melding til en person som du følger burde du gå lenger bak i repo-et og sjekke en der det ser ut som det funker. For å sende melding til folk må du gå til /messages/user_id til bruker.

## Oppsummering alt ble drit etter at jeg måtte begynne å legge til det lille ekstra og sikkerhets tiltak til websiden.

# SkillHub

**SkillHub** is a Flask-based social platform that allows users to create posts, follow others, send messages, and manage their profiles. It includes functionalities for user registration, login, profile management, posting, commenting, following, liking posts, reporting content, and real-time messaging.

## Features

- **User Registration & Authentication**: Users can register with a Gmail address, securely log in, and manage their sessions.
- **Profile Management**: Users can update their bios, profile pictures, and set privacy preferences.
- **Posts & Media**: Users can create text posts, upload images or videos, and view a feed of recent or popular posts.
- **Likes & Comments**: Users can like posts, leave comments, and interact with the community.
- **Follow & Unfollow**: Users can follow other users to see their posts and start chats.
- **Messaging**: Users can send direct messages to people they follow. A real-time chat interface allows for a live messaging experience.
- **Admin Dashboard**: An admin user can manage reports, ban/unban users, toggle admin status, and delete flagged posts.
- **Reporting**: Users can report content or other users for review by admins.
- **Notifications**: Users receive notifications for likes, follows, and more.
- **Security & Rate Limiting**: Implemented rate limits on certain actions, enforced HTTPS, and safe session handling.

## Tech Stack

- **Backend**: Flask for the web framework.
- **Database**: SQLAlchemy ORM with support for relational databases (e.g., SQLite, PostgreSQL, MySQL).
- **Real-time Messaging**: [Flask-SocketIO](https://flask-socketio.readthedocs.io/) and Socket.IO for live updates.
- **Authentication**: [Flask-Login](https://flask-login.readthedocs.io/) for user login management.
- **Migrations**: [Flask-Migrate](https://flask-migrate.readthedocs.io/) for handling database schema changes.
- **Rate Limiting**: [Flask-Limiter](https://flask-limiter.readthedocs.io/) to prevent abuse.
- **Security**: [Flask-Talisman](https://github.com/GoogleCloudPlatform/flask-talisman) to enforce HTTPS and secure headers.

## Getting Started

### Prerequisites

- Python 3.9+ recommended
- [pip](https://pip.pypa.io/en/stable/) package manager
- A supported database (SQLite, PostgreSQL, MySQL)

### Installation

1. **Clone the repository**:
    
    bash
    
    Copy code
    
    `git clone https://github.com/yourusername/SkillHub.git cd SkillHub`
    
2. **Create and activate a virtual environment**:
    
    bash
    
    Copy code
    
    `python3 -m venv venv source venv/bin/activate`
    
    _(On Windows: `venv\Scripts\activate`)_
    
3. **Install dependencies**:
    
    bash
    
    Copy code
    
    `pip install -r requirements.txt`
    
4. **Set up the database**:
    
    - Modify `config.py` to point to your chosen database.
    - Run migrations (if any):
        
        bash
        
        Copy code
        
        `flask db upgrade`
        
5. **Run the app**:
    
    bash
    
    Copy code
    
    `flask run`
    
    By default, the app runs at `http://127.0.0.1:5000`.
    

### Environment Variables

You can configure environment variables in `config.py` or via the OS environment for database URIs, secret keys, and other sensitive settings.

### File Structure

- `app.py`: The main Flask application.
- `config.py`: Configuration settings (database URL, secret keys, etc.).
- `utils/database.py`: Database initialization.
- `models/`: Contains SQLAlchemy models for Users, Posts, Comments, Likes, Follows, Messages, etc.
- `templates/`: Jinja2 templates for HTML pages.
- `static/`: CSS, JS, and image files.
- `migrations/`: Database migration scripts (if using Flask-Migrate).
- `requirements.txt`: Python dependencies.

## Usage

- **Register/Login**: Create an account, then log in to start browsing posts and interacting with other users.
- **Profile Management**: Update profile settings, upload a profile picture, add skills.
- **Create Posts**: Share text, images, or videos. Comment on and like other users’ posts.
- **Follow & Message**: Follow other users and start private conversations in real-time chat.
- **Report & Admin**: Report problematic content. Admins can review reports, ban/unban users, and manage flagged content.

## Contributing

1. Fork the repository.
2. Create a new branch for your feature or bug fix:
    
    bash
    
    Copy code
    
    `git checkout -b feature-name`
    
3. Commit your changes and push them to GitHub:
    
    bash
    
    Copy code
    
    `git commit -m "Add new feature" git push origin feature-name`
    
4. Create a Pull Request on the main repository.

## License

This project is licensed under the MIT License.