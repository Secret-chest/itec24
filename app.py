import datetime

import celery
import flask
import sqlalchemy
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate

from sqlalchemy.orm import declarative_base
from celery import shared_task
import httpx

app = flask.Flask(__name__)
from celery import Celery, Task


def celery_init_app(app_) -> Celery:
    class FlaskTask(Task):
        def __call__(self, *args: object, **kwargs: object) -> object:
            with app_.app_context():
                return self.run(*args, **kwargs)

    celery_app = Celery(app_.name, task_cls=FlaskTask)
    celery_app.config_from_object(app_.config["CELERY"])
    celery_app.set_default()
    app_.extensions["celery"] = celery_app
    return celery_app


app.config.from_mapping(
    CELERY=dict(
        broker_url="redis://localhost:6379",
        result_backend="redis://localhost:6379"
    ),
)
celery_app = celery_init_app(app)

app.config["SQLALCHEMY_DATABASE_URI"] = \
    "postgresql://echo:1234@localhost:5432/echo"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "connect_args": {
        "options": "-c timezone=utc"
    }
}
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = "super secret"

with (app.app_context()):
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
        ping_interval = db.Column(db.Integer, default=300, nullable=False)
        buggy = db.Column(db.Boolean, default=False)
        create_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)

        application = db.relationship("Application", back_populates="endpoints")
        statuses = db.relationship("Status", back_populates="endpoint", lazy="dynamic")

        def __init__(self, application, name, address, ping_interval, comment=""):
            self.application_id = application.id
            self.name = name
            self.address = address
            self.comment = comment
            self.ping_interval = ping_interval


    class Status(db.Model):
        id = db.Column(db.Integer, nullable=False, autoincrement=True, primary_key=True)
        endpoint_id = db.Column(db.Integer, db.ForeignKey("endpoint.id"), nullable=False)
        time = db.Column(db.DateTime, default=datetime.datetime.utcnow)

        status = db.Column(db.SmallInteger, nullable=False)
        buggy = db.Column(db.Boolean, default=False)
        endpoint = db.relationship("Endpoint", back_populates="statuses")

        def __init__(self, endpoint_id, status, buggy):
            self.endpoint_id = endpoint_id
            self.status = status
            self.buggy = buggy


    @celery.shared_task(name="ping")
    def ping(id, address, next_ping):
        if not db.session.get(Endpoint, id):
            return
        elif db.session.get(Endpoint, id).buggy:
            buggy = True
        else:
            buggy = False
        url = address
        print(f"Pinging {url}")
        response = httpx.get(url, verify=False)
        reading = Status(id, response.status_code, buggy)
        last_reading = db.session.query(Status).filter_by(endpoint_id=id).order_by(Status.time.desc()).first()
        db.session.add(reading)
        db.session.commit()

        # Schedule the next ping
        ping.apply_async(args=(id, address, next_ping), countdown=next_ping)

    @celery.shared_task(name="ping_all")
    def ping_all():
        endpoints = Endpoint.query.all()
        for endpoint in endpoints:
            ping.delay(endpoint.id, endpoint.address, endpoint.ping_interval)


task = ping_all.delay()

print()
print()
print(task)
print()
print()


@app.context_processor
def default():
    return {
        "session": flask.session,
    }


@app.route("/")
def dashboard():
    return flask.render_template("dashboard.html", apps=Application.query.all())


@app.route("/my")
def my_apps():
        if not flask.session.get("username"):
                return flask.redirect("/login", code=303)
        return flask.render_template("my-apps.html", apps=db.session.query(Application).filter_by(owner_name=flask.session["username"]).all())


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


# UTC filter
@app.template_filter("utc")
def utc_filter(timestamp):
    return datetime.datetime.utcfromtimestamp(timestamp)


@app.route("/app/<int:app_id>/")
def app_info(app_id):
    app_ = db.session.get(Application, app_id)

    time_slices = [(datetime.datetime.utcnow() - datetime.timedelta(minutes=int(flask.request.args.get("bar_duration", 30)) * (i+1)),
                    datetime.datetime.utcnow() - datetime.timedelta(minutes=int(flask.request.args.get("bar_duration", 30)) * i))
                   for i in range(int(flask.request.args.get("time_period", 30)) // int(flask.request.args.get("bar_duration", 1)), 0, -1)]

    slice_results = {}
    all_results = []

    for endpoint in app_.endpoints:
        slice_results[endpoint.id] = []

        for slice_ in time_slices:
            slice_results[endpoint.id].append(
                    (
                        db.session.query(Status).filter(
                            sqlalchemy.and_(Status.endpoint_id == endpoint.id,
                                Status.time >= slice_[0],
                                Status.time < slice_[1])).all(),
                        slice_
                    )
            )

    for endpoint in app_.endpoints:
        all_results.extend(db.session.query(Status).filter(
                sqlalchemy.and_(Status.endpoint_id == endpoint.id,
                                Status.time >= datetime.datetime.utcnow() - datetime.timedelta(minutes=10),
                                Status.time < datetime.datetime.utcnow())).all())

    return flask.render_template("app.html", app=app_, sorted=sorted, list=list,
                                 sorting=lambda x: x.time, reverse=True,
                                 is_ok=lambda x: all(status.status in (200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 302, 304, 307)
                                                     for status in x), and_=sqlalchemy.and_,
                                 is_partial=lambda x: any(status.status in (200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 302, 304, 307)
                                                          for status in x),
                                 bar_duration=int(flask.request.args.get("bar_duration", 30)), int=int, Status=Status,
                                 time_period=int(flask.request.args.get("time_period", 1440)),
                                 now=round(datetime.datetime.utcnow().timestamp()), func=sqlalchemy.func,
                                 reversed=reversed, fromtimestamp=datetime.datetime.utcfromtimestamp,
                                 slices=slice_results, bugs=lambda x: any(status.buggy for status in x),
                                 all_results=all_results)


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
        statuses = db.session.query(Status).filter_by(endpoint_id=endpoint_id).all()
        for status in statuses:
            db.session.delete(status)
        db.session.delete(endpoint)
        db.session.commit()
    else:
        endpoint.name = flask.request.form["name"]
        endpoint.address = flask.request.form["url"]
        endpoint.ping_interval = max(15, int(flask.request.form["ping_interval"]))
        endpoint.comment = flask.request.form["comment"]
        db.session.commit()
    return flask.redirect(f"/app/{app_id}/edit", code=303)


@app.route("/app/<int:app_id>/report/<int:endpoint_id>")
def endpoint_report(app_id, endpoint_id):
    endpoint = db.session.get(Endpoint, endpoint_id)
    endpoint.buggy = True
    db.session.commit()
    return flask.redirect(f"/app/{app_id}", code=303)


@app.route("/app/<int:app_id>/fix/<int:endpoint_id>")
def endpoint_fix(app_id, endpoint_id):
    if flask.session.get("username") != db.session.get(Application, app_id).owner_name:
        flask.abort(403)
    endpoint = db.session.get(Endpoint, endpoint_id)
    endpoint.buggy = False
    db.session.commit()
    return flask.redirect(f"/app/{app_id}", code=303)


@app.route("/app/<int:app_id>/add-endpoint", methods=["POST"])
def app_add_endpoint(app_id):
    if flask.session.get("username") != db.session.get(Application, app_id).owner_name:
        flask.abort(403)
    app_ = db.session.get(Application, app_id)
    endpoint = Endpoint(app_,
                        flask.request.form["name"],
                        flask.request.form["url"],
                        max(15, int(flask.request.form["ping_interval"])),
                        flask.request.form["comment"])
    db.session.add(endpoint)
    db.session.commit()

    ping.delay(endpoint.id, endpoint.address, endpoint.ping_interval)

    return flask.redirect(f"/app/{app_id}/edit", code=303)

