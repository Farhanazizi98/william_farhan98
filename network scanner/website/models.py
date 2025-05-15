from flask_login import UserMixin
# from models import User
 

class User(UserMixin):
    def __init__ (self, id, email, firstName, password):
        self.id = id
        self.email = email 
        self.firstName = firstName
        self.password = password

    