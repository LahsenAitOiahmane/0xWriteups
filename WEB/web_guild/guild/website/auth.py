from flask import Blueprint, render_template, request, flash, url_for, redirect
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user

import re
regex = "^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$"

auth = Blueprint("auth", __name__)

@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()
        if user:
            if check_password_hash(user.password,password):
                flash("Log in Successfull!", category="success")
                login_user(user, remember=True)
                if username == "admin":
                    return redirect(url_for("views.admin"))
                return redirect(url_for("views.dashboard"))
            else:
                flash("Incorrect password or username", category="error")
        else:
            flash("Incorrect password or username", category="error")       
    
    return render_template("login.html", user=current_user)


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@auth.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        print([x for x in request.form])
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")

        if(not re.search(regex,email)):
            flash("InValid Email", category="error")
        elif(len(username)<3):
            flash("Usernmane greater than 3 characters", category="error")
        elif(len(password)<1):
            flash("Password too short", category="error")
        else:
            already_exits = User.query.filter_by(username=username).first()
            if already_exits:
                flash("Username or Email already in use!",category="error")
            else:
                new_user = User(email=email, username=username, password=generate_password_hash(password))
                db.session.add(new_user)
                db.session.commit()
                flash("Account created!", category="success")
                return redirect(url_for("views.home"))

    return render_template("signup.html", user=current_user)
