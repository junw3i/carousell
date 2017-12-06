import uuid
from src.common.database import Database
import src.models.users.errors as UserErrors
from src.models.alerts.alert import Alert
from src.common.utils import Utils
import src.models.users.constants as UserConstants

class User(object):
    def __init__(self, email, password, _id=None):
        self.email = email
        self.password = password
        self._id = uuid.uuid4().hex if _id is None else _id

    def __repr__(self):
        return "<User {}>".format(self.email)

    @staticmethod
    def is_login_valid(email, password):    # pbkdf2_sha512
        user_data = Database.find_one(UserConstants.COLLECTION, {"email": email})
        if user_data is None:
            raise UserErrors.UserNotExistsError("Your username does not exist.")
        if not Utils.check_hashed_password(password, user_data['password']):
            # password is wrong
            raise UserErrors.IncorrectPasswordError("Your password was wrong.")
        return True

    @staticmethod
    def register_user(email, password):
        """
        register user -- the password already comes hashed as sha-512
        :param email:
        :param password:
        :return:
        """
        user_data = Database.find_one(UserConstants.COLLECTION, {"email": email})
        if user_data is not None:
            # already registered
            raise UserErrors.UserAlreadyRegisteredError("Email already exists.")
        if not Utils.email_is_valid(email):
            # incorrect email format
            raise UserErrors.InvalidEmailError("Invalid email address.")
        User(email, Utils.hash_password(password)).save_to_db()
        return True

    def save_to_db(self):
        Database.insert("users", self.json())

    def json(self):
        return {
            "_id": self._id,
            "email": self.email,
            "password": self.password
        }

    @classmethod
    def find_by_email(cls, email):
        return cls(**Database.find_one(UserConstants.COLLECTION, {'email': email}))

    def get_alerts(self):
        return Alert.find_by_user_email(self.email)
