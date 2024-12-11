import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'Some_random_ahh_goofy_ahh_key')
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:markus@localhost/skillhub_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi'}
