"""
Seed Admin User Script
Run this to create admin user in your local MongoDB
"""
from pymongo import MongoClient
import bcrypt
import uuid
from datetime import datetime, timezone

# MongoDB connection
client = MongoClient("mongodb://localhost:27017")
db = client["rumba_tailor"]

# Admin credentials
admin_email = "admin@rumbatailor.com"
admin_password = "admin123"

# Check if admin exists
existing_admin = db.users.find_one({"email": admin_email})

if existing_admin:
    print(f"✓ Admin user already exists: {admin_email}")
else:
    # Hash password
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(admin_password.encode("utf-8"), salt).decode("utf-8")
    
    # Create admin user
    admin_user = {
        "id": str(uuid.uuid4()),
        "email": admin_email,
        "password_hash": password_hash,
        "name": "Admin",
        "role": "admin",
        "phone": None,
        "address": None,
        "city": None,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    db.users.insert_one(admin_user)
    print(f"✅ Admin user created successfully!")
    print(f"   Email: {admin_email}")
    print(f"   Password: {admin_password}")

client.close()
