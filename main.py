from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['MAIL_SERVER'] = 'smtp-mail.outlook.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'seifeldenmohamed@hotmail.com'
app.config['MAIL_PASSWORD'] = 'mm221175'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(4), nullable=True)
    role = db.Column(db.String(10), default='user')
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(200))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True)
    likes = db.relationship('Like', backref='post', lazy=True)

    def get_like_count(self):
        return Like.query.filter_by(post_id=self.id).count()

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    likes = db.relationship('Like', backref='comment', lazy=True)

    def get_like_count(self):
        return Like.query.filter_by(comment_id=self.id).count()

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    posts = Post.query.all()
    return render_template('index.html', posts=posts)

@app.route('/like_post/<int:post_id>', methods=['POST'])
@login_required
def like_post(post_id):
    if not current_user.is_verified:
        return jsonify({'success': False}), 400

    post = Post.query.get_or_404(post_id)
    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()

    if not existing_like:
        like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(like)
        db.session.commit()
        new_like_count = post.get_like_count()
        return jsonify({'success': True, 'new_like_count': new_like_count})

    db.session.delete(existing_like)
    db.session.commit()
    new_like_count = post.get_like_count()
    return jsonify({'success': True, 'new_like_count': new_like_count})

@app.route('/like_comment/<int:comment_id>', methods=['POST'])
@login_required
def like_comment(comment_id):
    if not current_user.is_verified:
        return jsonify({'success': False}), 400

    comment = Comment.query.get_or_404(comment_id)
    existing_like = Like.query.filter_by(user_id=current_user.id, comment_id=comment_id).first()

    if not existing_like:
        like = Like(user_id=current_user.id, comment_id=comment_id)
        db.session.add(like)
        db.session.commit()
        new_like_count = comment.get_like_count()
        return jsonify({'success': True, 'new_like_count': new_like_count})

    db.session.delete(existing_like)
    db.session.commit()
    new_like_count = comment.get_like_count()
    return jsonify({'success': True, 'new_like_count': new_like_count})

@app.route('/add_comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    content = request.form.get('content', '').strip()
    if not content:
        return jsonify({'success': False}), 400

    post = Post.query.get_or_404(post_id)
    comment = Comment(content=content, author=current_user, post=post)
    db.session.add(comment)
    db.session.commit()
    return jsonify({'success': True, 'username': current_user.email, 'comment_id': comment.id})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            if not user.is_verified:
                flash('Please verify your email before logging in.')
                return redirect(url_for('login'))

            login_user(user)
            return redirect(url_for('index'))

        flash('Invalid email or password')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user:
            flash('Email already registered')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            verification_code = str(random.randint(1000, 9999))
            new_user = User(email=email, password=hashed_password, verification_code=verification_code)
            db.session.add(new_user)
            db.session.commit()

            msg = Message('Email Verification', sender='seifeldenmohamed@hotmail.com', recipients=[email])
            msg.body = f'Your verification code is: {verification_code}'
            mail.send(msg)

            return redirect(url_for('verify_email'))

    return render_template('register.html')

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'POST':
        code = request.form['code']
        user = User.query.filter_by(verification_code=code).first()

        if user:
            user.is_verified = True
            user.verification_code = None
            db.session.commit()
            flash('Email verified successfully')
            return redirect(url_for('login'))
        else:
            flash('Invalid verification code')

    return render_template('verify.html')

@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        image = request.files['image']

        if image:
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_url = url_for('static', filename='uploads/' + filename)
        else:
            image_url = None

        post = Post(title=title, content=content, image_url=image_url, author_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('create_post.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        if 'update_email' in request.form:
            new_email = request.form['new_email'].strip()
            if new_email:
                user = User.query.get(current_user.id)
                user.email = new_email
                db.session.commit()
                flash('Email updated successfully')
                return redirect(url_for('settings'))

        elif 'change_password' in request.form:
            old_password = request.form['old_password']
            new_password = request.form['new_password']
            user = User.query.get(current_user.id)
            if check_password_hash(user.password, old_password):
                if new_password:
                    user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
                    db.session.commit()
                    flash('Password changed successfully')
                    return redirect(url_for('settings'))
                else:
                    flash('New password cannot be empty')
            else:
                flash('Old password is incorrect')

    return render_template('settings.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
 