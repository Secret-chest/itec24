import datetime

import flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate

from sqlalchemy.orm import declarative_base

import httpx

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

        applications = db.relationship("Application", back_populates="owner")

        def __init__(self, username, password, admin=False):
            self.username = username
            self.password = bcrypt.generate_password_hash(password).decode("utf-8")
            self.admin = admin

    class Application(db.Model):
        id = db.Column(db.Integer, primary_key=True, autoincrement=True, unique=True, default=0)
        name = db.Column(db.String(64), unique=True, nullable=False)
        owner_name = db.Column(db.String(64), db.ForeignKey("user.username"), nullable=False)

        owner = db.relationship("User", back_populates="applications")

        endpoints = db.relationship("Endpoint", back_populates="application")

        def __init__(self, name, owner):
            self.name = name
            self.owner_name = owner.username

    class Endpoint(db.Model):
        id = db.Column(db.Integer, unique=True, nullable=False, primary_key=True, autoincrement=True)
        application_id = db.Column(db.Integer, db.ForeignKey("application.id"), nullable=False)
        address = db.Column(db.String(2048), nullable=False)
        name = db.Column(db.String(64), nullable=False)
        comment = db.Column(db.String(2048), nullable=True)

        application = db.relationship("Application", back_populates="endpoints")

        def __init__(self, application, name, address, comment=""):
            self.application_id = application.id
            self.name = name
            self.address = address
            self.comment = comment

    Base = declarative_base()

    class Status(Base):
        __table_args = (
            {
                "timescaledb_hypertable": {
                    "time_column_name": "time",
                },
            }
        )
        __tablename__ = "status"
        id = db.Column(db.Integer, unique=True, nullable=False, autoincrement=True)
        endpoint_id = db.Column(db.Integer, nullable=False)
        time = db.Column(db.DateTime, index=True, default=datetime.datetime.utcnow, primary_key=True)

        status = db.Column(db.SmallInteger, nullable=False)

        endpoint = db.relationship("Endpoint", back_populates="statuses")

        def __init__(self, endpoint, status):
            self.endpoint_id = endpoint.id
            self.status = status


def ping(endpoint):
    url = endpoint.address
    response = httpx.get(url)
    return response.status_code


@app.context_processor
def default():
    return {
        "session": flask.session,
    }


@app.route("/")
def dashboard():
    return flask.render_template("dashboard.html", apps=Application.query.all())


@app.route("/login", methods=["GET"])
def login():
    return flask.render_template("login.html")


@app.route("/signup", methods=["GET"])
def signup():
    return flask.render_template("signup.html")


@app.route("/new-app", methods=["GET"])
def new_app():
    if not flask.session.get("username"):
        return flask.redirect("/login", code=303)
    return flask.render_template("new-app.html")


@app.route("/new-app", methods=["POST"])
def new_app_post():
    if not flask.session.get("username"):
        return flask.redirect("/login", code=303)
    if Application.query.filter_by(name=flask.request.form["name"]).first():
        flask.flash("Application already exists")
        return flask.redirect("/new-app", code=303)

    new_app_ = Application(
        flask.request.form["name"],
        db.session.get(User, flask.session["username"]),
    )
    db.session.add(new_app_)
    db.session.commit()
    return flask.redirect("/", code=303)


@app.route("/login", methods=["POST"])
def login_post():
    user =  db.session.get(User, flask.request.form["username"])
    if not user:
        flask.flash("Username doesn't exist")
        return flask.redirect("/signup", code=303)
    if not bcrypt.check_password_hash(user.password, flask.request.form["password"]):
        flask.flash("Wrong password")
        return flask.redirect("/signup", code=303)

    flask.session["username"] = user.username
    return flask.redirect("/", code=303)


@app.route("/logout")
def logout():
    flask.session.pop("username", None)
    return flask.redirect("/", code=303)


@app.route("/signup", methods=["POST"])
def signup_post():
    if flask.request.form["password"] != flask.request.form["password2"]:
        flask.flash("Passwords do not match")
        return flask.redirect("/signup", code=303)
    if db.session.get(User, flask.request.form["username"]):
        flask.flash("Username already exists")
        return flask.redirect("/signup", code=303)
    if len(flask.request.form["password"]) < 8:
        flask.flash("Password must be at least 8 characters")
        return flask.redirect("/signup", code=303)
    if len(flask.request.form["username"]) < 4:
        flask.flash("Username must be at least 4 characters")
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


@app.route("/app/<int:app_id>/")
def app_info(app_id):
    app_ = db.session.get(Application, app_id)
    return flask.render_template("app.html", app=app_)


@app.route("/app/<int:app_id>/edit/")
def app_editor(app_id):
    if flask.session.get("username") != db.session.get(Application, app_id).owner_name:
        flask.abort(403)
    app_ = db.session.get(Application, app_id)
    return flask.render_template("app-editor.html", app=app_)


@app.route("/app/<int:app_id>/edit/<int:endpoint_id>", methods=["POST"])
def endpoint_edit(app_id, endpoint_id):
    if flask.session.get("username") != db.session.get(Application, app_id).owner_name:
        flask.abort(403)
    endpoint = db.session.get(Endpoint, endpoint_id)
    if flask.request.form.get("delete") == "delete":
        db.session.delete(endpoint)
        db.session.commit()
    else:
        endpoint.name = flask.request.form["name"]
        endpoint.address = flask.request.form["url"]
        endpoint.comment = flask.request.form["comment"]
        db.session.commit()
    return flask.redirect(f"/app/{app_id}/edit", code=303)


@app.route("/app/<int:app_id>/add-endpoint", methods=["POST"])
def app_add_endpoint(app_id):
    if flask.session.get("username") != db.session.get(Application, app_id).owner_name:
        flask.abort(403)
    app_ = db.session.get(Application, app_id)
    endpoint = Endpoint(app_,
                        flask.request.form["name"],
                        flask.request.form["url"],
                        flask.request.form["comment"])
    db.session.add(endpoint)
    db.session.commit()
    return flask.redirect(f"/app/{app_id}/edit", code=303)
