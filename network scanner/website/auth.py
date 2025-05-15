from flask import Blueprint, render_template, request, flash, redirect, url_for, make_response
from . import get_db
from .models import User
from flask_login import login_user, login_required, logout_user, current_user
auth = Blueprint ("auth", __name__) 




#sign up route
@auth.route("/sign_up", methods=["GET", "POST"])
def sign_up():
    if request.method =="POST":
        database = get_db()

        email = request.form.get("email") 
        firstName = request.form.get("firstName")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        cursor = database.cursor()
        cursor.execute("SELECT * FROM users Where email =?", (email,))
        row = cursor.fetchone()

        if row:
            flash("User already exists", category="error")
            return render_template("sign_up.html", user=current_user)

        if len(email) < 4:
           flash("Email must be greater than 3 characters", category="error")
        elif len(firstName) < 2:
            flash ("First name must be greater than 1 character", category="error")
        elif password1 != password2:
           flash("Passwords don't match", category="error")
        elif len(password1) < 7:
            flash("Password must be at least 7 characters", category="error")
        else:
            cursor.execute(
                "INSERT INTO users(email, firstName, password) VALUES(?,?,?)", 
                (email, firstName, password1)
            )
            database.commit()
            flash("Account created", category="success")
            return redirect(url_for("auth.login"))

        return render_template("sign_up.html", user=current_user)

    return render_template("sign_up.html", user=current_user)


#login route
@auth.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("views.icmp_scan"))

    if request.method == "POST":
        database = get_db()
        email = request.form.get("email")
        password = request.form.get("password")
        cursor = database.cursor()
        cursor.execute("SELECT * FROM users where email = ? AND password = ?", (email, password))
        row = cursor.fetchone() 

        if row:
            user = User(id=row[0], email=row[1], firstName=row[2], password=row[3])
            login_user(user)
            flash("Logged in successfully", category="success")
            response = make_response(redirect(url_for("views.icmp_scan")))
            response.headers["Cache-Control"] = "no-cache" # make sure the user can't cache the login page
            
            return response
        else: 
            flash("Incorrect email and password", category="error")

    response = make_response(render_template("login.html", user=current_user))
    response.headers["Cache-Control"] = "no-cache" # make sure the user can't cache the login page
    
    return response


#logout route
@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


#source --------- https://github.com/techwithtim/Flask-Web-App-Tutorial/tree/main/website ---------

#sorice ----------https://loadforge.com/guides/effective-caching-strategies-for-faster-flask-applications---------