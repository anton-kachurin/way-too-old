import re

import micro_framework
from db_scheme import Account, Post, Comment, Like,\
                      PostEditor, CommentEditor, LikeEditor,\
                      NotAuthorized, NotExists, NotPermitted

# regexps to match against on the signup page
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

# initialize app
# use debug=True when running locally, otherwise https-only pages will
# be not accessible
app = micro_framework.WSGIApplication(debug=False)

# a custom Jinja filter improving date formatting
def datetimeformat(value, format='%B %d, %Y'):
    return value.strftime(format)
app.jinja_env.filters['datetimeformat'] = datetimeformat

# NotAuthorized, NotExists and NotPermitted may be thrown by db_scheme
# when peforming errornous operations on the datastore;
# define exception handlers for them here
@app.catch(NotAuthorized)
def on_not_authorized(request):
    return app.redirect(login_page, required=1)

@app.catch(NotExists)
def on_not_exists(request):
    return app.render('error_page.html',
                      error_message='This object does not exist')

@app.catch(NotPermitted)
def on_not_permitted(request):
    return app.render('error_page.html',
                      error_message='This action is not permitted for you')

# On each request check if user is authorized by reading `user` cookie;
# set request.user variable which will be `None` if the user is not logged in;
# otherwise it is a datastore entry key of the `Account` kind which could be
# used to create, delete and edit other kinds of datastore entries
@app.init
def db_user_by_cookie(request):
    cookie = request.cookie.get('user')
    if cookie:
        request.user = Account.by_safe_id(cookie)
    else:
        request.user = None

@app.route('/signup', 1, is_https_only=True)
def signup_page(request):
    if request.method == 'GET':
        return app.render('signup.html')

    username = request.params.get('username')
    password = request.params.get('password')
    verify = request.params.get('verify')
    email = request.params.get('email')

    def error(message):
        params = {
            'username': username,
            'password': password,
            'verify': verify,
            'email': email,
            'error': message
        }
        return app.render('signup.html', **params)

    # check if there any error in the filled form
    if not (username and password and verify):
        return error("Username, Password and Verify fields are necessary")

    if password != verify:
        return error("Password and Verify fields do not match")

    if not USER_RE.match(username):
        return error("Error in Username: "
                    + "must be at least 3 symbols long and "
                    + "can contain only numbers, letters or symbols _ and -")

    if not PASSWORD_RE.match(password):
        return error("Error in Password: must be at least 3 symbols long")

    if email and not EMAIL_RE.match(email):
        return error("Wrong format of the email address")

    # if there no errors, create an account
    key = Account.create(username, password, email)
    if not key:
        # internally Account.create checks if the username is unique
        return error("Such username already exists")

    # set a cookie to grant authorization for consecutive requests of the user
    request.cookie.set('user', key.urlsafe())

    return app.redirect(main_page)

@app.route('/login', 1, is_https_only=True)
def login_page(request):
    username = request.params.get('username')
    password = request.params.get('password')
    required = request.params.get('required')

    valid = Account.validate(username, password)
    if valid:
        request.cookie.set('user', valid.urlsafe())
        return app.redirect(main_page)
    else:
        # if the username or password is empty, show an error
        error = username or password
        return app.render('login.html', error=error, required=required)

@app.route('/logout', 1, is_https_only=True)
def logout_page(request):
    if request.method == 'GET':
        return app.render('logout.html')

    request.cookie.delete('user')

    return app.redirect(main_page)

@app.route('/')
@app.route('/blog', is_default=True)
def main_page():
    # get only 10 latest posts sorted from newest to oldest
    entries = Post.get_all(10)
    for entry in entries:
        # for every post get a comment count
        entry.comments = Comment.by_post(entry.key, True)

    return app.render('all_posts.html', entries=entries)

@app.route('/blog/newpost', 1)
def new_post(request):
    # a large button on the main page is a bait for the newcomers
    # forse them to login or signup before adding a snippet
    if not request.user:
        return app.redirect(login_page, required=1)

    if request.method == 'GET':
        return app.render('new_post.html', action='Create')

    old = request.params.get('old')
    new = request.params.get('new')
    description = request.params.get('description')

    # both `old` and `new` fields need to be filled to create a snippet
    if not (old and new):
        return app.render('new_post.html', action='Create',
                          old=old, new=new, description=description, error=True)

    # PostEditor is initialized with request.user (Account kind)
    editor = PostEditor(request.user)
    # a new post is created; in the future this post can be edited only by
    # the editor initialized with the same request.user,
    # otherwise NotPermitted will be raised
    entry = editor.create(old=old, new=new, description=description)

    return app.redirect(blog_post, post_id=entry.key.urlsafe())

@app.route('/blog/<post_id:[^/]+>')
def blog_post(post_id):
    # Post.get_one will search datastore for a post with an id == post_id
    # if it will fail (say URI is broken making post_id invalid, or
    # post_id is valid but is not one of a Post kind) NotExists will be raised
    post = Post.get_one(post_id)
    # get all comments for the post sorted descending
    comments = Comment.by_post(post.key)

    return app.render('post.html', entry=post, comments=comments)

@app.route('/blog/<post_id:[^/]+>/edit', 1)
def blog_post_edit(request, post_id):
    editor = PostEditor(request.user)
    # as editor is initialized with a certain Account entry
    # the `editor.get` method will return only those Post entries
    # related to that Account entry;
    # if trying to edit someone else's post, NotPermitted is raised
    entry = editor.get(post_id)

    if request.method == 'GET':
        old = entry.old
        new = entry.new
        description = entry.description
        return app.render('new_post.html', action='Edit', post_id=post_id,
                          old=old, new=new, description=description)

    old = request.params.get('old')
    new = request.params.get('new')
    description = request.params.get('description')

    # edited post will not be saved if `old` or `new` field is empty
    if not (old and new):
        return app.render('new_post.html', action='Edit', post_id=post_id,
                          old=old, new=new, description=description, error=True)

    editor.edit(entry, old=old, new=new, description=description)

    return app.redirect(blog_post, post_id=post_id)

@app.route('/blog/<post_id:[^/]+>/delete', 1)
def blog_post_delete(request, post_id):
    if request.method == 'GET':
        return app.render('delete_post.html', post_id=post_id)

    editor = PostEditor(request.user)
    entry = editor.get(post_id)
    editor.delete(entry)

    return app.redirect(main_page)

# this url is accessible only by POST requests
@app.route('/blog/<post_id:[^/]+>/comment/new', 1, 0)
def comment_save(request, post_id):
    message = request.params.get('message')

    if message:
        post_key = Post.get_one(post_id).key
        # CommentEditor is initialized with 2 parameters:
        #   - the first one is the Post entry's key
        #     to which the comment belongs
        #   - the second one is the authorization key
        # after it's been created Comment could be deleted only by an editor
        # which has been initialized by the same 2 parameters
        # so that it's impossible to delete comment without knowing both
        # post_id and `user` cookie
        editor = CommentEditor(post_key, request.user)
        editor.create(message=message)

    return app.redirect(blog_post, post_id=post_id)

@app.route('/blog/<post_id:[^/]+>/comment/delete', 1)
def comment_delete(request, post_id):
    comment_id = request.params.get('comment_id')

    if request.method == 'GET':
        return app.render('delete_comment.html', post_id=post_id)

    post_key = Post.get_one(post_id).key
    editor = CommentEditor(post_key, request.user)
    entry = editor.get(comment_id)
    editor.delete(entry)

    return app.redirect(blog_post, post_id=post_id)

# likes are displayed inside iframes which makes it possible to
# like/unlike posts without reloading the whole page
@app.route('/blog/<post_id:[^/]+>/likes')
def likes_iframe(request, post_id):
    post_key = Post.get_one(post_id).key
    same_user = post_key.parent() == request.user
    total_likes = Like.by_post(post_key)
    # if a user is logged in, the iframe will display buttons to like/unlike;
    # to know which button to show, the template needs a count of likes which
    # were already set by the user to the post
    if request.user:
        editor = LikeEditor(post_key, request.user)
        user_likes = editor.count()
    else:
        user_likes = 0

    return app.render('likes.html', post_id=post_id, user=request.user,
                      user_likes=user_likes, total_likes=total_likes,
                      same_user=same_user)

@app.route('/blog/<post_id:[^/]+>/likes/add', 1, 0)
def add_like(request, post_id):
    post_key = Post.get_one(post_id).key
    same_user = post_key.parent() == request.user
    editor = LikeEditor(post_key, request.user)
    # add a new like only if there are none from the user for the post
    if not editor.count() and not same_user:
        editor.create(plus_one=True, user=request.user)

    return app.redirect(likes_iframe, post_id=post_id)

@app.route('/blog/<post_id:[^/]+>/likes/remove', 1, 0)
def remove_like(request, post_id):
    post_key = Post.get_one(post_id).key
    same_user = post_key.parent() == request.user
    editor = LikeEditor(post_key, request.user)
    likes = editor.list()
    if len(likes) and not same_user:
        # delete a like if there were any added by the user to the post
        editor.delete(likes[0])

    return app.redirect(likes_iframe, post_id=post_id)
