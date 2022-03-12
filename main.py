import flask
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'lBzRnQNZMDAQehF4mMvS'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)

@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET","POST"])
def register():

    if request.method == "POST":
        # Find user by email entered.
        user_to_check = User.query.filter_by(email=request.form.get("email")).first()
        if user_to_check:
           flask.flash('Sorry, This Email addrees already exist,  please try again.')
           return redirect(location=url_for('login'))
        else:
           new_user = User(email     = request.form.get("email")
                                ,password = generate_password_hash(password=request.form.get("password")
                                                                   ,method = 'pbkdf2:sha256'
                                                                   ,salt_length=8
                                                                   )
                                ,name     = request.form.get("name")
                                )
           db.session.add(new_user)
           db.session.commit()
           return render_template("secrets.html",username=request.form.get("name"))
    return render_template("register.html")



@app.route('/login',methods=['GET', 'POST'])
def login():
    if request.method == "POST":
       useremail     = request.form.get("email")
       userpassword  = request.form.get("password")

       # Find user by email entered.
       user_to_check = User.query.filter_by(email=useremail).first()
       if user_to_check:
            # Check stored password hash against entered password hashed.
            if  check_password_hash(pwhash=user_to_check.password ,password=userpassword):
                login_user(user_to_check)
                #flask.flash('Logged in successfully.')
                return redirect(location=url_for('secrets'))
            else:
                flask.flash('Sorry, incorrect password,  please try again.')
                return redirect(location=url_for('login'))
       else:
            flask.flash('Sorry, Email does not exist,  please try again.')
            return redirect(location=url_for('login'))

    return render_template("login.html")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
def logout():
    pass


@app.route('/download')
@login_required
def download():
    return send_from_directory("static"
                               ,filename="files/cheat_sheet.pdf"
                               ,as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
