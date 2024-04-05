import flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate

app = flask.Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = \
    "postgresql://echo:1234@localhost:5432/echo"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = "super secret"

with app.app_context():
    class User(db.Model):
        username = db.Column(db.String(64), unique=True, nullable=False, primary_key=True)
        password = db.Column(db.String(72), nullable=False)
        admin = db.Column(db.Boolean, nullable=False, default=False)

        def __init__(self, username, password, admin=False):
            self.username = username
            self.password = bcrypt.generate_password_hash(password).decode("utf-8")
            self.admin = admin


@app.context_processor
def default():
    return {
        "session": flask.session,
    }


@app.route("/")
def dashboard():
    return flask.render_template("dashboard.html")


@app.route("/login", methods=["GET"])
def login():
    return flask.render_template("login.html")


@app.route("/signup", methods=["GET"])
def signup():
    return flask.render_template("signup.html")


@app.route("/signup", methods=["POST"])
def signup_post():
    if flask.request.form["password"] != flask.request.form["password2"]:
        flask.flash("Passwords do not match")
        return flask.redirect("/signup", code=303)
    if db.session.get(User, flask.request.form["username"]):
        flask.flash("Username already exists")
        return flask.redirect("/signup", code=303)

    new_user = User(
        flask.request.form["username"],
        flask.request.form["password"],
    )
    db.session.add(new_user)
    db.session.commit()
    flask.session["username"] = new_user.username
    return flask.redirect("/", code=303)


@app.route("/timeline/<endpoint_id>")
def info(endpoint_id):
    return flask.render_template("timeline.html", endpoint=endpoint_id)
