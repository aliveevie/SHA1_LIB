import hashlib

def crack_sha1_hash(hash, use_salts=False):
    with open('top-1000-password.txt') as password_file:
        for password in password_file:
            password = password.strip()
            hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest()
            
            if hashed_password == hash:
                return password

            if use_salts:
                with open('known_salts.txt') as salts_file:
                    for salt in salts_file:
                        salt = salt.strip()
                        salted_password1 = salt + password
                        salted_password2 = password + salt
                        
                        hashed_salted_password1 = hashlib.sha1(salted_password1.encode('utf-8')).hexdigest()
                        hashed_salted_password2 = hashlib.sha1(salted_password2.encode('utf-8')).hexdigest()
                        
                              
                        if hashed_salted_password1 == hash or hashed_salted_password2 == hash:
                            return password
    return "PASSWORD NOT IN DATABASE"

hash_to_crack = 'ea3f62d498e3b98557f9f9cd0d905028b3b019e1'
print(crack_sha1_hash(hash_to_crack, use_salts=True))