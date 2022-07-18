import json
from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required, check


# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///database.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def home():
    """Show homepage"""
    user_id = session["user_id"]
    if request.method == "POST":
        note = request.form.get("note")
        date = datetime.now()
        note = db.execute("INSERT INTO note (data, date, user_id) VALUES (?, ?, ?)", note, date, user_id)
        flash("Note added!", category="success")

    note = db.execute("SELECT data, id FROM note WHERE user_id = ?", user_id)
    return render_template("home.html", user = user_id, note = note)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    user_id = session.clear()
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = db.execute("SELECT id, pass_word FROM users WHERE email = ?", email)
        print(user)
        # Check email
        if user:
            if check_password_hash(user[0]["pass_word"], password):
                # Remember user logged in
                session["user_id"] = user[0]["id"]

                flash("Logged in successfully!", category = "success")
                # Redirect user to homepage
                return redirect("/")
            else:
                flash("Incorrect password, try again.", category = "error")
        else:
            flash("Email does not exist.", category = "error")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("login.html", user = user_id)


@app.route("/logout")
@login_required
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    flash("You are logged out")
    # Redirect user to login form
    return redirect("/login")


@app.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    """Register user"""
    user_id = session.clear()
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        email = request.form.get("email")
        firstName = request.form.get("firstName")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        user = db.execute("SELECT id FROM users WHERE email = ?", email)

        # Ensure email is valid
        if user:
            flash("Email already exist.", category = "error")

        # Ensure firstname is valid
        elif check(email) == False:
            flash('Invalid Email!', category='error')

        # Check password
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        elif password1 != password2:
            flash("Passwords don't match", category = "error")

        # Add user to database
        else:
            db.execute("INSERT INTO users (email, pass_word, first_name) VALUES (?, ?, ?)", email, generate_password_hash(password1, method='sha256'), firstName)

            # Remember user logged in
            user_id = db.execute('SELECT id FROM users WHERE email = ?', (email))
            session['user_id'] = user_id[0]['id']

            # Flask message
            flash('Account created!', category='success')

            # Redirect to homepage
            return redirect("/")

    return render_template("sign_up.html", user = user_id,)


@app.route("/changePassword", methods=["GET", "POST"])
@login_required
def changePassword():
    user_id = session["user_id"]
    if request.method == "POST":
        old_password = request.form.get("password1")
        new_password = request.form.get("password2")
        confirm_new_password = request.form.get("password3")

        user = db.execute("SELECT pass_word FROM users WHERE id = ?", user_id)

        if not check_password_hash(user[0]["pass_word"], old_password):
            flash('Password not correct', category='error')
        elif len(new_password) < 7:
            flash('Password must be at least 7 characters.', category='error')
        elif new_password != confirm_new_password:
            flash('Password do not match', category='error')
        else:
            db.execute("UPDATE users SET pass_word = ? WHERE id = ?", generate_password_hash(new_password, method='sha256'), user_id)
            return redirect("/")
    return render_template("changePassword.html")


@app.route("/delete-note", methods=["POST"])
def deleteNote():
    note = json.loads(request.data)
    noteId = note["noteId"]
    note = db.execute("SELECT * FROM note WHERE id = ?", noteId)
    if note:
        if note[0]["user_id"] == session["user_id"]:
            db.execute("DELETE FROM note WHERE id = ?", noteId)

    return jsonify({})

if __name__ == "__main__":
    app.run(debug=True)