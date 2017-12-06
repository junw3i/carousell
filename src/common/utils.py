from passlib.hash import pbkdf2_sha512
import re

class Utils(object):

    @staticmethod
    def hash_password(password):
        """
        hashes a pw using pbkdf2_sha512
        :param password:
        :return:
        """
        return pbkdf2_sha512.encrypt(password)

    @staticmethod
    def check_hashed_password(password, hashed_password):
        """
        Database password is encrypted more than the user' password at this stage
        :param password: sha512-hased password
        :param hashed_password: pbkdf2_sha512 encrypted password
        :return:
        """
        return pbkdf2_sha512.verify(password, hashed_password)

    @staticmethod
    def email_is_valid(email):
        email_address_matcher = re.compile('^[\w-]+@([\w-]+\.)+[\w]+$')
        return True if email_address_matcher.match(email) else False
