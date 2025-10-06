from app import db
from app import User
from werkzeug.security import generate_password_hash

def create_admin():
    username = input("Enter admin username: ").strip()
    email = input("Enter admin email: ").strip()
    password = input("Enter admin password: ").strip()

    if not username or not email or not password:
        print("All fields are required.")
        return

    if User.query.filter_by(username=username).first():
        print("❌ Username already exists.")
        return

    admin = User(
        username=username,
        email=email,
        password=generate_password_hash(password),
        role='admin'
    )
    db.session.add(admin)
    db.session.commit()
    print("✅ Admin user created.")

if __name__ == "__main__":
    from app import app
    with app.app_context():
        create_admin()
