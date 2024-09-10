from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship('Recipe', back_populates='user')

    serialize_rules = ('-recipes.user',)

    # Prevent direct access to _password_hash
    @hybrid_property
    def password_hash(self):
        raise AttributeError('password_hash is private')

    # # Password property to prevent direct access
    # @property
    # def password(self):
    #     raise AttributeError("password is not a readable attribute")

    # Password setter to hash the password using bcrypt
    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)

    # # Method to verify the password
    # def verify_password(self, password):
    #     return bcrypt.check_password_hash(self._password_hash, password)

    # Validate username to ensure it's not empty
    @validates('username')
    def validate_username(self, key, username):
        # if not username:
        #     raise ValueError("Username cannot be empty")
        # return username
        assert username is not None, 'Username is required'
        return username
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'image_url': self.image_url,
            'bio': self.bio
        }


class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String(50), nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    user = db.relationship('User', back_populates='recipes')

    serialize_rules = ('-user.recipes',)

    @validates('title')
    def validates_title(self, key, title):
        assert title is not None, 'Title is required'
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if instructions is None or len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters long")
        return instructions
