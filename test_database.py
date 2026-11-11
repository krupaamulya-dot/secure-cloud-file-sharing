
from database.db import (
    initialize_database,
    create_user,
    authenticate_user,
    get_user
)

# Initialize database
initialize_database()
print("Database initialized successfully!")

# Create administrator
admin_created = create_user(
    "admin001",
    "admin@example.com",
    "AdminPass123!",
    "admin"
)

if admin_created:
    print("Admin account created successfully!")
else:
    print("Admin account already exists.")

# Test login
user = authenticate_user(
    "admin@example.com",
    "AdminPass123!"
)

if user:
    print("Login successful!")
    print("User ID:", user["user_id"])
    print("Role:", user["role"])
else:
    print("Login failed!")

# Retrieve administrator
admin = get_user("admin001")

if admin:
    print("Admin details retrieved successfully!")
