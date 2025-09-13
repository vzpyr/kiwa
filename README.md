# kiwa
simple file hosting system
<img width="2327" height="1339" alt="screenshot" src="https://github.com/user-attachments/assets/1760e223-38b1-4aee-8539-2f8345ee3e6d" />

# features
- user registration and authentication
- recaptcha (can be temporarily disabled by setting `FLASK_DEBUG` to `1` or `FLASK_ENV` to `development`
- file uploads with expiry options and password protection
- file preview for images and videos
- responsive design with modern ui
- password hashing, csrf protection, file/mime type blacklist

# how to use
1. install python3
2. install requirements: `pip install -r requirements.txt`
3. add recaptcha keys and smtp credentials in .env.example
4. rename the `.env.example` to `.env`
5. start the app: `python3 app.py`

## optional environment variables
- `SECRET_KEY`: flask secret key (defaults to a random 32-byte string)
- `DATABASE_URL`: database connection url (defaults to `sqlite:///kiwa.db`)
- `UPLOAD_FOLDER`: directory for file storage (defaults to `static/uploads`)
- `MAX_FILE_SIZE`: maximum file size in bytes (defaults to 100MB)
