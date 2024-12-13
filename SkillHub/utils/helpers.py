import bleach
import magic

def sanitize_input(text):
    return bleach.clean(text, strip=True)

def is_safe_file(file_stream):
    mime = magic.from_buffer(file_stream.read(1024), mime=True)
    file_stream.seek(0)  # Reset file pointer
    
    ALLOWED_MIMES = {
        'image/jpeg': ['.jpg', '.jpeg'],
        'image/png': ['.png'],
        'image/gif': ['.gif'],
        'video/mp4': ['.mp4'],
        'video/quicktime': ['.mov']
    }
    
    return mime in ALLOWED_MIMES

