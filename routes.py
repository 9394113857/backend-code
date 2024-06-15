import os
import secrets
from PIL import Image
from flask import request, jsonify, make_response, abort, url_for
from __init__ import app, db, bcrypt, mail
from forms import RegistrationForm, LoginForm, UpdateAccountForm, PostForm, RequestResetForm, ResetPasswordForm
from models import User, Post
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
import jwt
from datetime import datetime, timedelta
from functools import wraps

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except Exception as e:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/test', methods=['GET'])
def test():
    return jsonify({"message": "Hello, World!"})


@app.route("/")
@app.route("/home")
def home():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return jsonify([post.to_dict() for post in posts.items])

@app.route("/about")
def about():
    return jsonify({'title': 'About'})

def send_verification_email(user):
    token = user.get_verification_token()
    msg = Message('Email Verification', sender='noreply@demo.com', recipients=[user.email])
    msg.body = f'''To verify your email, visit the following link:
{url_for('verify_email', token=token, _external=True)}
If you did not create an account, please ignore this email.
'''
    mail.send(msg)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return jsonify({'message': 'Already logged in.'}), 400
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        send_verification_email(user)
        return jsonify({'message': 'User registered. Please check your email to verify your account.'}), 201
    return jsonify(form.errors), 400

@app.route("/verify_email/<token>", methods=['GET'])
def verify_email(token):
    user = User.verify_verification_token(token)
    if user:
        user.verified = True
        db.session.commit()
        return jsonify({'message': 'Email verified. You can now log in.'}), 200
    else:
        return jsonify({'message': 'Verification link is invalid or expired.'}), 400

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return jsonify({'message': 'Already logged in.'}), 400
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if not user.verified:
                return jsonify({'message': 'Please verify your email first.'}), 400
            login_user(user, remember=form.remember.data)
            response = make_response(jsonify({'message': 'Login successful.'}))
            token = jwt.encode({'public_id': user.id, 'exp': datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
            response.set_cookie('x-access-token', token)
            return response
        else:
            return jsonify({'message': 'Login Unsuccessful. Please check email and password'}), 401
    return jsonify(form.errors), 400

@app.route("/logout")
def logout():
    logout_user()
    response = make_response(jsonify({'message': 'Logged out successfully.'}))
    response.set_cookie('x-access-token', '', expires=0)
    return response

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        db.session.commit()
        return jsonify({'message': 'Account updated.'}), 200
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return jsonify({'username': form.username.data, 'email': form.email.data}), 200

@app.route("/post/new", methods=['POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        return jsonify({'message': 'Post created.'}), 201
    return jsonify(form.errors), 400

@app.route("/post/<int:post_id>", methods=['GET'])
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return jsonify(post.to_dict())

@app.route("/post/<int:post_id>/update", methods=['POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        return jsonify({'message': 'Post updated.'}), 200
    return jsonify(form.errors), 400

@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    return jsonify({'message': 'Post deleted.'}), 200

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender='noreply@demo.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)

@app.route("/reset_password", methods=['POST'])
def reset_request():
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        return jsonify({'message': 'If an account with that email exists, a password reset email has been sent.'}), 200
    return jsonify(form.errors), 400

@app.route("/reset_password/<token>", methods=['POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    if not user:
        return jsonify({'message': 'That is an invalid or expired token'}), 400
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        return jsonify({'message': 'Your password has been updated! You are now able to log in.'}), 200
    return jsonify(form.errors), 400
