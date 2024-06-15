# create_db.py
from app import db, app
import os

# Check if the database file already exists
db_file_path = os.path.join(app.root_path, 'site.db')
if not os.path.isfile(db_file_path):  # Use isfile to check if file exists
    with app.app_context():
        db.create_all()
        print("Database tables created.")
else:
    print("Database tables already exist.")
