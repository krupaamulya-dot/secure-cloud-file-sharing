
from backend.auth import generate_token, verify_token

# Generate an admin token
token = generate_token("admin001", "admin")

print("JWT token generated successfully!")

# Verify the token
payload = verify_token(token)

if payload:
    print("Token verified successfully!")
    print("User ID:", payload["user_id"])
    print("Role:", payload["role"])
else:
    print("Token verification failed!")
