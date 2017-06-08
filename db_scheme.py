# -*- coding: utf-8 -*-
# Copyright 2017, Anton Kachurin
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from google.appengine.ext import ndb

import hashlib
import random
import string

# salt for password hashing
SALT_LENGTH = 5

class NotAuthorized(Exception):
    """Datastore operation is not authorized

    It is raised when an operation is attempted, but was not enough evidence
    provided that the operation is ran by an authorized user
    """
    pass

class NotExists(Exception):
    """Datastore entry does not exist

    It is raised when trying to read an entry from the datastore by
    some sort of identifier, but the id is corrupted, or nothing is read, or
    reading is successfull but returned an entry of a wrong type
    """
    pass

class NotPermitted(Exception):
    """Datastore operation on the entry is unavailable for the user

    It is raised when the user is authorized to perform attempted operation,
    but does not have permissions to work with the entry
    """
    pass

class DummyKey(object):
    """A class emulating some of the ndb.Key methods

    Emulated methods return values which could be used to determine if
    the key is useful or not. Great for writing tests and some other cases,
    for example:

    1.  key = ndb.Key(urlsafe="ABCDEF")
        # this key is not necessarily pointing at some entry in the datastore
        # so the only way to find if there any record with such key is to
        # try to get it
        entry = key.get()
        # entry might be None
        if entry:
            # do some stuff with the record
            pass

    2.  key = ndb.Key(urlsafe="ABCDEF")
        # this key may be of any kind but the code is expecting something
        # particular; to avoid any troubles check the kind explicitly
        if key.kind() == 'ModelX':
            # do some stuff
            pass

    In both examples some stuff needs to be done only if the key is satisfying
    some conditions. It is where this class becomes handy. Using a mockup object
    helps to keep the code simple:

        if urlsafe:
            key = ndb.Key(urlsafe=urlsafe)
        else:
            key = DummyKey()

        if key.get():
            # do some stuff
            pass

    """
    def get(self):
        return None

    def kind(self):
        return ''

    def parent(self):
        return None

def urlsafe_key(safe_id):
    """Get a ndb.Key by given urlsafe-encoded id

    This function will return either a valid ndb.Key, or a DummyKey instance
    if the id passed in the function is corrupted
    """
    try:
        key = ndb.Key(urlsafe=safe_id)
    except:
        key = DummyKey()
    return key

class Account(ndb.Model):
    """A model containing user-related data

    Stores username, salt hashed password and an optional email address
    Has class methods to create, validate and retrieve entries from the
    datastore.
    """
    username = ndb.StringProperty(required = True)
    password_hash = ndb.StringProperty(required = True)
    email = ndb.StringProperty()

    @classmethod
    def create(cls, username, password, email=None):
        """Create an entry

        :param username:
            A unique username. Nothing will be stored if such username already
            exists
        :param password:
            The password is being hashed with salt and the "salt|hash" value
            is stored instead of the plaintext value
        :param email:
            An optional email address
        :returns:
            None if the username was not unique
            ndb.Key of the new entry otherwise
        """
        if not cls.unique_username(username):
            return None

        entry = cls(
            username=username,
            password_hash=cls.hash_password(password),
            email=email)
        entry.put()

        return entry.key

    @classmethod
    def validate(cls, username, password):
        """Validate a username-password pair

        Checks if the username exists in the datastore and if the stored
        password_hash equals the plaintext password hashed with the same salt

        :param username:
            A username
        :param password:
            A plaintext password to be hashed and matched against
        :returns:
            None if any the conditions isn't met
            ndb.Key otherwise
        """
        read = cls.query().filter(cls.username == username).fetch()
        if len(read) == 1:
            entry = read[0]
            if cls.validate_password(password, entry.password_hash):
                return entry.key
            else:
                return None
        else:
            return None

    @classmethod
    def by_safe_id(cls, safe_id):
        """Get an Account entry by urlsafe-encoded id

        :param safe_id:
            A urlsafe-encoded string
        :returns:
            None if the id is corrupted, entry of the wrong type found or
                 nothing found at all
            ndb.Key otherwise
        """
        key = urlsafe_key(safe_id)
        if key.get() and key.kind() == cls.__name__:
            return key
        return None

    @classmethod
    def unique_username(cls, username):
        """Check if such username doesn't exist in the datastore"""
        read = cls.query().filter(Account.username == username).fetch()
        if len(read):
            return False
        return True

    @classmethod
    def hash_password(cls, password, salt=""):
        """Get a sha256 salted hash of the password

        :param password:
            A password to be hashed
        :param salt:
            If wasn't provided, a new value will be generated
        :returns:
            A string in the format "salt|hash"
        """
        if not salt:
            source = string.ascii_letters
            letters = [random.choice(source) for x in xrange(SALT_LENGTH)]
            salt = "".join(letters)
        hash = hashlib.sha256(password + salt).hexdigest()
        return "%s|%s" % (salt, hash)

    @classmethod
    def validate_password(cls, password, hash):
        """Check if the password matches the hash"""
        salt = hash.split('|')[0]
        return hash == cls.hash_password(password, salt)

class EditorBase(object):
    """A base class for all Editor classes

    Editors have three main advantages over regular model classes:

    1) Out of the box inheritance

       Each model class which is manipulated through an editor has to
       have a parent. The parent key has to be passed to the constructor
       of the Editor class, so it's much harder to write invalid code.

    2) Update and Delete operations are guaranteed to be authorized

       The second parameters which has to be passed to the constructor
       of the Editor class is authorization key. `delete` and `modify`
       methods raise an exception on entries which's KeyProperty doesn't
       equal to the authorization key. `list`, `count` and `get` return
       only authorized entries.
       Note: is optional

    3) Code is shorter

       As parent and authorization keys are passed to the class constructor,
       the class allows to omit them in operations. `create` method doesn't
       require KeyProperty as a parameter to add an entry to the Datastore,
       `edit` method is raising an exception if such parameter was passed in.

    An extending class is supposed to overwrite only a few class variables:

    class DaddyOfKind(ndb.Model):
        # define properties
        pass

    class SomeKind(ndb.Model):
        # define properties
        pass

    class SomeKindEditor(EditorBase):
        model_class = SomeKind
        parent_class = DaddyOfKind
        auth_class = DaddyOfKind
        # auth_attr is not necessary because parent_class == auth_class
        # order_attr is optional
    """
    #: a model class the editor is manipulating
    model_class = None
    #: a model class of the parent key
    parent_class = None
    #: all entries manipulated with the editor will have this parent
    parent_key = None
    #: a model class of the authorization key
    auth_class = None
    #: all entries manipulated with the editor will have this authorization key
    auth_key = None
    #: a property name of the model_class which stores the auth_key
    auth_attr = None
    #: a property name of the model_class which is used for query ordering
    order_attr = None

    # a shortcut for model_class.order_attr
    @property
    def order_property(self):
        if self.order_attr:
            return getattr(self.model_class, self.order_attr)
        else:
            return None

    def __init__(self, parent_key, auth_key=None):
        self.parent_key = parent_key

        if self.parent_class != self.auth_class:
            self.auth_key = auth_key
        else:
            self.auth_key = parent_key

        editor_name = self.__class__.__name__
        if parent_key:
            parent_name = self.parent_class.__name__
            key_name = self.parent_key.kind()
            if not isinstance(parent_key, self.parent_class):
                TypeError("In %s: %s as parent key expected, got %s"
                          % (editor_name, parent_name, key_name))

        if auth_key:
            auth_name = self.auth_class.__name__
            key_name = self.auth_key.kind()
            if not isinstance(auth_key, self.auth_class):
                TypeError("In %s: %s as authorization key expected, got %s"
                          % (editor_name, auth_key, key_name))

        if self.parent_class != self.auth_class and not self.auth_attr:
            raise Exception("auth_attr must be set for %s" % editor_name)

        if self.auth_attr and not hasattr(self.model_class, self.auth_attr):
            raise Exception("%s used as an auth_attr but not defined in %s"
                            % (self.auth_attr, self.model_class))

    def auth(func):
        """Decorator checks if both parent_key and auth_key are set"""
        def wrapper(self, *args, **kwargs):
            if not self.parent_key or not self.auth_key:
                raise NotAuthorized()
            return func(self, *args, **kwargs)

        return wrapper

    def type_check(action):
        """Decorator checks if the entry passed to a method is of model_class"""
        def wrapper(func):
            def wrapped(self, entry, *args, **kwargs):
                if not isinstance(entry, self.model_class):
                    this = self.__class__.__name__
                    that = entry.__class__.__name__
                    raise TypeError("%s cannot %s %s entities"
                                    % (this, action, that))
                return func(self, entry, *args, **kwargs)

            return wrapped
        return wrapper

    def can_modify(func):
        """Decorator checks if the entry can be modified by the editor"""
        def wrapper(self, entry, *args, **kwargs):
            if entry.key.parent() != self.parent_key:
                raise NotPermitted()

            if self.auth_attr:
                entry_auth_prop = getattr(entry, self.auth_attr)
                if entry_auth_prop != self.auth_key:
                    raise NotPermitted()

            return func(self, entry, *args, **kwargs)

        return wrapper

    @auth
    def _prepare_query(self):
        """Prepare query for `count` and `list` methods"""
        query = self.model_class.query(ancestor=self.parent_key)
        if self.auth_attr:
            model_attr = getattr(self.model_class, self.auth_attr)
            query = query.filter(model_attr == self.auth_key)
        if self.order_property:
            return query.order(-self.order_property)
        else:
            return query

    def count(self):
        """Get count of entries of model_class modifiable by the editor"""
        return self._prepare_query().count()

    def list(self):
        """List entries of model_class modifiable by the editor"""
        return self._prepare_query().fetch()

    @auth
    def create(self, **kwargs):
        """Create a new entry of model_class

        Its parent and `auth_attr` will be set automatically
        """
        kwargs['parent'] = self.parent_key

        if self.auth_attr:
            kwargs[self.auth_attr] = self.auth_key

        entry = self.model_class(**kwargs)
        entry.put()
        return entry

    @auth
    def get(self, safe_id):
        """Get an entry modifiable by the editor by urlsafe-encoded id"""
        key = urlsafe_key(safe_id)
        if key.kind() != self.model_class.__name__:
            raise NotExists()
        if key.parent() != self.parent_key:
            raise NotPermitted()

        entry = key.get()

        if entry:
            if self.auth_attr:
                entry_auth_prop = getattr(entry, self.auth_attr)
                if entry_auth_prop != self.auth_key:
                    raise NotPermitted()

            return entry
        else:
            raise NotExists()

    @auth
    @type_check('delete')
    @can_modify
    def delete(self, entry):
        """Delete an entry if it's modifiable by the editor"""
        entry.key.delete()

    @auth
    @type_check('edit')
    @can_modify
    def edit(self, entry, **kwargs):
        """Edit an entry if it's modifiable by the editor

        model_class.auth_attr is forbidden to be modified
        """
        if self.auth_attr and self.auth_attr in kwargs:
            raise NotPermitted()
        for prop in kwargs:
            if not hasattr(entry, prop):
                entry_class = entry.__class__.__name__
                raise TypeError("%s has no %s property" % (entry_class, prop))
            setattr(entry, prop, kwargs[prop])

        entry.put()

class Post(ndb.Model):
    old = ndb.StringProperty()
    new = ndb.StringProperty()
    description = ndb.StringProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)
    modified = ndb.DateTimeProperty(auto_now=True)

    @classmethod
    def get_all(cls, count=None):
        """Get all posts written by all users

        :param count:
            optionally set how many entries returned
        :returns:
            a list of entries sorted from the newest to the oldest
        """
        return cls.query().order(-cls.created).fetch(count)

    @classmethod
    def get_one(cls, safe_id):
        """Get a post by given urlsafe-encoded id

        :param safe_id:
            urlsafe-encoded string
        :returns:
            an entry of Post kind
        :raises:
            NotExists when:
                safe_id is corrupted;
                no entry found;
                something except Post kind entry is found;
        """
        key = urlsafe_key(safe_id)
        entry = key.get()
        if not entry or not isinstance(entry, cls):
            raise NotExists()
        return entry

class Comment(ndb.Model):
    message = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    modified = ndb.DateTimeProperty(auto_now=True)
    user = ndb.KeyProperty(kind=Account)

    @classmethod
    def by_post(cls, post_key, only_count=False):
        """Get comments having the same parent

        Returns all comments made by all users for some post

        :param post_key:
            ndb.Key parent key of the comments
        :param only_count:
            whether to return entries themselves or just to count them
        :returns:
            `int` if only_count is True
            a list of entries if only_count is False
        """
        query = cls.query(ancestor=post_key).order(-cls.created)
        if only_count:
            return query.count()
        else:
            return query.fetch()

class Like(ndb.Model):
    plus_one = ndb.BooleanProperty(required=True)
    user = ndb.KeyProperty(kind=Account)

    @classmethod
    def by_post(cls, post_key):
        """Get count of likes having the same parent

        Returns all likes made by all users for the same post

        :param post_key:
            ndb.Key parent key of the likes
        :returns:
            `int` count of likes
        """
        query = cls.query(ancestor=post_key)
        return query.count()

class PostEditor(EditorBase):
    model_class = Post
    parent_class = Account
    auth_class = Account
    # auth_attr is not declared because parent_class and auth_class are the same
    order_attr = 'created'

class CommentEditor(EditorBase):
    model_class = Comment
    parent_class = Post
    auth_class = Account
    auth_attr = 'user'
    order_attr = 'created'

class LikeEditor(EditorBase):
    model_class = Like
    parent_class = Post
    auth_class = Account
    auth_attr = 'user'
    order_attr = 'user'
