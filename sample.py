import bcrypt
import hashlib
import hmac

password = "1234567890"

PEPPER = "gakdgakgqlhgqii$%^&*^*&^awilfhhfqwjwqhjk"
salt = bcrypt.gensalt()

peppered_password = hmac.new(PEPPER.encode("utf-8"), password.encode("utf-8"), hashlib.sha256).hexdigest()
salted_peppered_password = bcrypt.hashpw(peppered_password.encode("utf-8"), salt)
heashed_password = salted_peppered_password.decode("utf-8")

print(peppered_password)
print(salted_peppered_password)
print(heashed_password)

