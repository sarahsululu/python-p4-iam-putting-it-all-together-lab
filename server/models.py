from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from config import db, bcrypt


class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # relationships
    recipes = db.relationship("Recipe", back_populates="user")

    # serialization rules (avoid leaking password hash)
    serialize_rules = ("-recipes.user", "-_password_hash",)

    # prevent direct reading of password
    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes are not viewable.")

    # setter hashes the password
    @password_hash.setter
    def password_hash(self, password):
        if not password or password.strip() == "":
            raise ValueError("Password cannot be empty.")
        self._password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    # authenticate user
    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)

    # validate username presence
    @validates("username")
    def validate_username(self, key, value):
        if not value or value.strip() == "":
            raise ValueError("Username must be present.")
        return value


class Recipe(db.Model):
    __tablename__ = "recipes"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user = db.relationship("User", back_populates="recipes")

    @validates("title")
    def validate_title(self, key, value):
        if not value or value.strip() == "":
            raise ValueError("Recipe must have a title.")
        return value

    @validates("instructions")
    def validate_instructions(self, key, value):
        if not value or value.strip() == "":
            raise ValueError("Recipe must have instructions.")
        if len(value.strip()) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return value


