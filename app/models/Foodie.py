from system.core.model import Model
import re

class Foodie(Model):
    def __init__(self):
        super(Foodie, self).__init__()

    def add_users(self, users):
        EMAIL_REGEX = re.compile(r'^[a-za-z0-9\.\+_-]+@[a-za-z0-9\._-]+\.[a-za-z]*$')
        errors =[]
        password= users['password']
        

        if not users['first_name']:
            errors.append('Name cannot be blank')   
        elif len(users['first_name'])<2:
            errors.append("Name must be atleast 2 characters")
        if not users['last_name']:
            errors.append('Name cannot be blank')
        elif len(users['last_name'])<2:
            errors.append("Name must be atleast 2 characters")
        if not users['email']:
            errors.append("Email cannot be blank")
        elif not EMAIL_REGEX.match(users['email']):
            errors.append("Email type is invalid")
        if users['password']<5:
            errors.append("Password must be atleast 5 characters long")
        if not users['password']:
            errors.append("Password cannot be blank")
        if users['password'] != users['cpw']:
            errors.append("Passwords do no match")

        if errors:
            return {"status":False, "errors":errors}
            print errors
        else:
            hashed_pw = self.bcrypt.generate_password_hash(password)
            query = "INSERT INTO users (first_name, last_name, email, password, created_at) VALUES(%s, %s, %s, %s, NOW())"
            data = [users['first_name'], users['last_name'], users['email'], hashed_pw]
                
            self.db.query_db(query, data)

            get_user_query = "SELECT * FROM users ORDER BY created_at DESC LIMIT 1"
            users=self.db.query_db(get_user_query)
            return {"status" : True, "user":users[0]}


    def log_in(self, login_data):
        password= login_data['password']
        query= "SELECT * FROM users WHERE email=%s"
        data=[login_data['email']]
        emailvalid = self.db.query_db(query, data)

        if emailvalid:
            if self.bcrypt.check_password_hash(emailvalid[0]['password'], password):
                return {"status": True, 'user_info': emailvalid[0] }
        
        return {"status" : False} 