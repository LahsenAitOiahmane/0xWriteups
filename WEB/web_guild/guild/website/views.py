from flask import Blueprint, render_template, request, flash, redirect, url_for, render_template_string
from flask_login import login_required, current_user
from .models import User, Verification, Validlinks
from . import db
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
import hashlib
from PIL import Image
from PIL.ExifTags import TAGS
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

views = Blueprint("views", __name__)

@views.route("/")
def home():
    return render_template("home.html",user=current_user)
        

def allowed_file(filename):
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@views.route("/verification",methods=["GET","POST"])
@login_required
def verification():
    if request.method == "POST":
        if "file" in request.files:
            file = request.files["file"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                os.makedirs(os.path.join("/", "app", "guild", "website", "uploads", current_user.username), exist_ok=True)
                file.save(os.path.join("/", "app", "guild", "website", "uploads", current_user.username, filename))

                new_req = Verification(verified=0, doc=str(os.path.join("/", "app", "guild", "website", "uploads", current_user.username, filename)), user_id=current_user.id, bio="")
                db.session.add(new_req)
                db.session.commit()
                flash("Verification Request Sent!", category="success")

            elif file and not allowed_file(file.filename):
                flash("Only png, jpg, jpeg are allowed!", category="error")
    
    query = Verification.query.filter_by(user_id=current_user.id).first()
    if query:
        if query.verified == 0:
            flash("Your Request has been send to Guild-Master wait for approval.", category="error")
            return redirect(url_for("views.home"))
        
        elif query.verified == 1:
            flash("Already verified!", category="error")
            return redirect(url_for("views.dashboard"))

    else:
        return render_template("verification.html", user=current_user, username=current_user.username)


@views.route("/dashboard")
@login_required
def dashboard():
    query = Verification.query.filter_by(id=current_user.id).first()
    if query :
        if query.verified == 0:
            flash("Verification document has been submit! wait for approval", category="error")
            return redirect(url_for("views.home"))
        else:
            return render_template("dashboard.html", user=current_user)
    else:
        return redirect(url_for("views.verification"))


@views.route("/changepasswd/<Hash>",methods=["GET", "POST"])
def changepasswd(Hash):
    query = Validlinks.query.filter_by(validlink=Hash).first()
    if query:
        if request.method == "POST":
            email = query.email
            query1 = User.query.filter_by(email=email).first()
            new_password = request.form.get("password")
            query1.password = generate_password_hash(new_password, method="sha256")
            db.session.commit()
            db.session.delete(query)
            db.session.commit()
            flash("Password Updated!",category="success")
            redirect(url_for("views.home"))
            
        return render_template("resetpassword.html", user=current_user, email=query.email)


@views.route("/forgetpassword", methods=["GET", "POST"])
def forgetpassword():
    if request.method == "POST":
        email = request.form.get("email")
        query = User.query.filter_by(email=email).first()
        flash("If email is registered then you will get a link to reset password!", category="success")
        if query:
            # send email the below link
            reset_url = str(hashlib.sha256(email.encode()).hexdigest())
            print(reset_url)
            new_query = Validlinks(email=email, validlink=reset_url)
            db.session.add(new_query)
            db.session.commit()
        
        return redirect(url_for("views.home"))

    return render_template("forgetpassword.html", user=current_user)


@views.route("/admin",methods=["GET", "POST"])
@login_required
def admin():
    if current_user.username == "admin":
        verifications = Verification.query.all()
        return render_template("admin.html", user=current_user, Verification=verifications, User=User)
    else:
        flash("You are not admin!", category="error")
        return redirect(url_for("views.home"))


@views.route("/verify",methods=["GET", "POST"])
@login_required
def verify():
    if current_user.username == "admin":
        if request.method == "POST":
            user_id = request.form.get("user_id")
            verf_id = request.form.get("verification_id")
            query = Verification.query.filter_by(id=verf_id).first()
            
            img = Image.open(query.doc)

            exif_table={}

            for k, v in img.getexif().items():
                tag = TAGS.get(k)
                exif_table[tag]=v

            if "Artist" in exif_table.keys():
                sec_code = exif_table["Artist"]
                query.verified = 1
                db.session.commit()
                return render_template_string("Verified! {}".format(sec_code))
            else:
                return render_template_string("Not Verified! :(")
    else:
        flash("Oops", category="error")
        return redirect(url_for("views.home"))


def checkInput(bio):
    payloads = [
        "*",
        "script",
        "alert",
        "debug",
        "%",
        "include",
        "html",
        "if",
        "for",
        "config",
        "img",
        "src",
        ".py",
        "main",
        "herf",
        "pre",
        "class",
        "subclass",
        "base",
        "mro",
        "__",
        "[",
        "]",
        "def",
        "return",
        "self",
        "os",
        "popen",
        "init",
        "globals",
        "base",
        "class",
        "request",
        "attr",
        "args",
        "eval",
        "newInstance",
        "getEngineByName",
        "getClass",
        "join"
    ]
    for x in payloads:
        if x in bio:
            return True
    return False


@views.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    query = Verification.query.filter_by(user_id=current_user.id).first()
    if query:

        if request.method == "POST":
            bio = request.form.get("bio")
            if not checkInput(bio):
                query.bio = bio
                db.session.commit()
                flash("Bio updated !", category="success")
                return render_template("profile.html", user=current_user, Bio=bio, User=User)
            else:
                flash("Avoid Bad Characters!", category="error")

        return render_template("profile.html", user=current_user, Bio=query.bio, User=User)
    else:
        flash("Submit your Badge for verification!", category="error")
        return redirect(url_for("views.verification"))


@views.route("/getlink")
@login_required
def create_share():
    username = current_user.username
    query = Validlinks.query.filter_by(validlink=username).first()
    if query:
        pass 
    else:
        new_query = Validlinks(email=current_user.email, validlink=current_user.username)
        db.session.add(new_query)
        db.session.commit()
    link = "/user/" + str(current_user.username)
    return render_template("getlink.html", link=link, user=current_user)


@views.route("/user/<link>")
def share(link):
    query = Validlinks.query.filter_by(validlink=link).first()
    if query:
        email = query.email
        query1 = User.query.filter_by(email=email).first()
        bio = Verification.query.filter_by(user_id=query1.id).first().bio
        temp = open("/app/website/templates/newtemplate/shareprofile.html", "r").read()
        return render_template_string(temp % bio, User=User, Email=email, username=query1.username)