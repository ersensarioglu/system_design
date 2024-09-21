import jwt, datetime, os
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

server = Flask(__name__)
server.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://sd_auth_user:sd_auth_user@localhost:5432/sd_auth"
db = SQLAlchemy(server)
migrate = Migrate(server, db)

class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(), unique=True)
    password = db.Column(db.String())

    def __init__(self, email, password):
        self.email = email
        self.password = password

    def __repr__(self):
        return f"<Email {self.email}>"

@server.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth:
        return "Missing credentials", 401
    
    res = User.query.filter_by(email=auth.username).first()
    
    if res:
        if auth.username != res.email or auth.password != res.password:
            return "Invalid credentials", 401
        else:
            return createJWT(auth.username, os.environ.get("MY_SECRET_KEY"), True)
    else:
        return "Invalid user", 401

@server.route("/validate", methods=["POST"])
def validate():
    encoded_jwt = request.headers["Authorization"]
    
    if not encoded_jwt:
        return "Unauthenticated", 401
    
    encoded_jwt = encoded_jwt.split(" ")[1]
    
    try:
        print(encoded_jwt)
        print(os.environ.get("MY_SECRET_KEY"))
        decoded = jwt.decode(
            encoded_jwt, os.environ.get("MY_SECRET_KEY"), algorithms=["HS256"]
        )
        print(decoded)
    except:
        return "Not authorized", 403
    
    return decoded, 200

def createJWT(username, secret, authZ):
    return jwt.encode(
        {
            "username": username,
            "exp": datetime.datetime.now(datetime.UTC)
            + datetime.timedelta(days=1),
            "iat": datetime.datetime.now(datetime.UTC),
            "admin": authZ,
        },
        secret,
        algorithm="HS256",
    )
    
if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000)
    
    