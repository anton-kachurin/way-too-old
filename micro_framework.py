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

"""
micro framework
---------------

A wrapper around Google App Engine's webapp2 inspired by Flask routing and
supporting Jinja2 out of the box
"""

import os
import inspect
import hmac
import string

import webapp2
import jinja2

from logging import debug

# this key is used in Cookie class HMAC hashing function
COOKIE_SECRET = 'somestring88320'

class MicroRouter(webapp2.Router):
    """ An extension to webapp Router with a few features.

    - adds syntax sugar for adding new routes:

        @router.wrap('/<user_id:([^/]+)>/',
                    is_post=False, is_get=True, is_https_only=False,
                    is_default=False)
        def handler_name(user_id):
            pass

    - sets redirections automatically for https-only pages (login, payment):

        @router.wrap('/login', is_https_only=True)
        def login_page():
            pass

    - enables redirection by a handler function:

        @router.wrap('/blog/<id:(\d+)>')
        def standalone_post_page(id):
            pass

        @router.wrap('/latest')
        def get_latest_post():
            # get latest_id from db
            latest_id = 42
            # redirect to '/blog/42'
            return router.redirect(standalone_post_page, id=latest_id)

    - provides `uri_for` method which generates a URI by a handler function

        router.uri_for(standalone_post_page, id='123') # /blog/123

    - allows to omit the first argument in the handler function:

        @router.wrap('/login', is_post=True)
        def login_page(request):
            # request.params.get(...)
            pass

        @router.wrap('/main')
        def main_page():
            # doesn't need to access `request.params.get(...)` and so on
            return 'main_page_content'
    """

    # routes declared via decorator are stored here as
    # 'handler_name': [{'name': 'handler_name_1', 'route': route1}, ...]
    # `is_default` route is the first item in the list
    by_handler = None
    # in debug mode https-only parameters are ignored as most likely
    # http://localhost:8080/ is being used
    debug = False

    def __init__(self, debug, *args, **kwargs):
        super(MicroRouter, self).__init__(*args, **kwargs)
        self.debug = debug
        self.by_handler = {}

    def add_by_handler(self, handler_name, route, is_default):
        """Combines routes with the same handler as a list.

        Generates a unique name for the route

        self.by_handler ==
        {'handler_name': [{'name': 'handler_name_1', 'route': route_obj1},
                          {'name': 'handler_name_2', 'route': route_obj1}],
        'other_handler_name':[...]}

        :param handler_name:
            __name__ of the handler function
        :param route:
            webapp2.Route object
        :param is_default:
            if True, the name-route pair will be prepended to the list,
            so it could be found easily later as ['handler_name'][0]
        :returns:
            A unique name for the route which could be used in webapp.uri_for()
        """
        if not handler_name in self.by_handler:
            self.by_handler[handler_name] = []

        routes = self.by_handler[handler_name]
        name = handler_name + '_' + str(len(routes) + 1)
        obj = {'name': name, 'route': route}
        if is_default:
            routes = [obj] + routes
        else:
            routes.append(obj)
        self.by_handler[handler_name] = routes

        return name

    def redirect(self, handler_func, *args, **kwargs):
        """Constructs a Redirector object to be run in dispatcher later

        :param handler_func:
            This function's __name__ will be used to find the default route
            in self.by_handler dict
        :returns:
            A Redirector object which when called will return a URL matching
            the default route of that handler function
        """
        handler_name = handler_func.__name__
        route_name = self.by_handler[handler_name][0]['name']
        return Redirector(route_name, *args, **kwargs)

    def uri_for(self, handler_func, *args, **kwargs):
        """Same as `redirect` method but returns the URL directly

        Is unable to build full URLs (e.g containing protocol://domain.name).
        Is meant to be used to generate URLs for HTML output
        """
        # pops _scheme, _netloc and _full parameters from kwargs
        # as in that case Request object is required
        kwargs.pop('_scheme', None)
        kwargs.pop('_netloc', None)
        kwargs.pop('_full', None)
        handler_name = handler_func.__name__
        route = self.by_handler[handler_name][0]['route']
        # using None as `request` parameter because it's not going to
        # be used inside that function anyways
        uri = route.build(None, args, kwargs)
        return uri

    def wrap(self, url, is_post=False, is_get=True,
             is_https_only=False, is_default=False):
        """A Decorator generating routes for the decorated handler functions

        see MicroRouter docstr

        :param url:
            A webapp2.Route URL template
        :param is_post:
            If POST requests are allowed
        :param is_get:
            If GET requests are allowed
        :param is_https_only:
            Adds an additional route which will just redirect a HTTP request to
            HTTPS with the code 307 (GET -> GET, POST -> POST)
        :param is_default:
            if the route is default self.redirect and self.uri_for methods
            will form URL based on this route
        """
        def wrapper(func):
            handler_name = func.__name__

            methods = []
            if is_get:
                methods.append("GET")
            if is_post:
                methods.append("POST")

            # create a Route object
            route = webapp2.Route(url, methods=methods, schemes=["https"])
            # give it a unique name and make it seekable for the future
            route.name = self.add_by_handler(handler_name, route, is_default)
            # set a custom adapter
            route.handler_adapter = MicroHandlerAdapter(func)
            # a standard webapp2.Router method
            self.add(route)

            if self.debug or not is_https_only:
                route.schemes.append("http")
            else:
                # create a Route object
                redirect = webapp2.Route(url, methods=methods, schemes=["http"])
                # use a special Handler class
                redirect.handler = webapp2.RedirectHandler
                # make it working for both GET and POST requests
                redirect.handler_method = 'get'
                # params to be used to build a redirection URL
                redirect.defaults = {
                    '_uri': redirect_to_route,
                    '_scheme': 'https',
                    '_code': 307,
                    '_route': route.name}
                redirect.name = self.add_by_handler(handler_name, redirect,
                                                    False)
                self.add(redirect)

            return func
        return wrapper

class WSGIApplication(webapp2.WSGIApplication):
    """A WSGI-compliant application

    :param debug:
        If it's to be run in a debug mode

    Features:
        - has to be created before any routes are defined;
        - adds shortcuts for self.router.wrap and self.router.redirect:

            app = micro_framework.WSGIApplication()

            @app.route('/') # same as @app.router.wrap('/')
            def main_page():
                return app.redirect(login_page) # same as app.router.redirect

        - allows to set initializers which will be run on every single
          incoming request before the request handler has been run:

            @app.init
            def is_admin(request):
                # check if the request is sent by an admin
                request.is_admin = True

            @app.route('/')
            def main_page(request):
                if request.is_admin:
                    return 'Welcome, my lord'
                else
                    return "Don't breath on me!"

        - provides a catching mechanism for exceptions of any sort so that
          it's possible to inform the client about what sort of error happened,
          require additional actions from them or do some server-side cleanup:

            class NotAdmin(Exception):
                pass

            @app.catch(NotAdmin)
            def on_not_admin(request):
                return app.redirect(login_page, need_admin=True)

            @app.route('/')
            def main_page(request):
                if not request.is_admin:
                    raise NotAdmin()

        - has a built-in support of Jinja2 templates:

            @app.route('/')
            def main_page(request):
                return app.render('template.html', lord_name='Count Zero')

            template.html:
                {% if request.is_admin %}
                    <a href="uri_for(handlers.logout_page)">Logout</a>
                    <br>
                    <a href="uri_for(handlers.stats_page, full=True)">Stats</a>
                    <br>
                    Welcome, {{lord_name}}!
                {% endif %}
    """
    def __init__(self, debug=False, *args, **kwargs):
        # enable request initializers
        self.request_context_class = MicroRequestContext
        # initializers which will be run on every request
        self.on_request = []

        # add some properties to the request objects
        self.request_class = MicroRequest

        # use a new router with all its features
        self.router_class = MicroRouter

        super(WSGIApplication, self).__init__(*args, **kwargs)

        self.router.debug = debug
        # set a new dispatcher which will catch exceptions
        self.router.set_dispatcher(self.__class__.catching_dispatcher)
        # exception handlers
        self.catchers = []

        # configure Jinja to use templates and auto-escape html text
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        loader = jinja2.FileSystemLoader(template_dir)
        jinja_env = jinja2.Environment(loader=loader, autoescape=True)

        # enable generating URLs inside templates
        self.handler_list = ABNDict()
        jinja_env.globals['handlers'] = self.handler_list
        jinja_env.globals['uri_for'] = self.router.uri_for

        self.jinja_env = jinja_env

    @staticmethod
    def catching_dispatcher(router, request, response):
        """Dispatches a request handler

        Additionally it checks if there were any exceptions and runs appropriate
        exception handlers when necessary; also it normalizes request handler's
        return value, i.e converts it to Webapp2.Response

        New request handlers' return value types are:
            - Redirector (return app.redirect(handler_func, **params))
            - Renderer (return app.render(template_file_name, **params))
            - basestring (return '<b>this is html output</b>')
        """
        # make a list of exceptions which have a handler defined
        catchers = tuple([e for e, f in request.app.catchers])
        try:
            # try to dispatch a route as usual
            rv = router.default_dispatcher(request, response)
        except catchers as e:
            for exception, func in request.app.catchers:
                if isinstance(e, exception):
                    # if anything went wrong and a handler is found, run it
                    rv = func(request)

        if isinstance(rv, basestring):
            # request handler returned plaintext, just send it to the client
            rv = webapp2.Response(rv,
                                  headerlist=response.headerlist)
        if isinstance(rv, Renderer):
            # a Renderer type callable will render a Jinja2 template
            rv = webapp2.Response(rv(request),
                                  headerlist=response.headerlist)
        elif isinstance(rv, Redirector):
            # a Redirector type callable will be used to perform a redirect
            rv = webapp2.redirect(rv(),
                                  request=request,
                                  response=response)
        return rv

    def init(self, func):
        """Decorator, adds a new initializer function"""
        self.on_request.append(func)
        return func

    def catch(self, exception):
        """Decorator, adds a new exception handler"""
        def wrapper(func):
            self.catchers.append((exception, func))
            return func
        return wrapper

    def route(self, *args, **kwargs):
        """A shortcut to self.router.wrap decorator

        Captures all handler functions decorated with it and adds them to
        ABNDict which is passed as a global to the template renderer
        """
        def get_func(func, *args, **kwargs):
            self.handler_list(func)
            return wrapper(func, *args, **kwargs)

        wrapper = self.router.wrap(*args, **kwargs)

        return get_func

    def redirect(self, *args, **kwargs):
        """A shortcut to self.router.redirect method

        Returns a callable to be used in the dispatcher
        """
        return self.router.redirect(*args, **kwargs)

    def render(self, template, **kwargs):
        """Returns a callable to be used in the dispatcher"""
        return Renderer(self.jinja_env, template, **kwargs)

class MicroHandlerAdapter(webapp2.BaseHandlerAdapter):
    """A handler adapter to use in MicroRouter

    Allows to omit `request` argument when defining request handler function,
    see MicroRouter for details
    """
    def __init__(self, handler):
        self.original = handler

    def handler(self, request, *args, **kwargs):
        handler_args = inspect.getargspec(self.original)[0]
        if len(handler_args) - 1 == len(kwargs):
            kwargs[handler_args[0]] = request
        return self.original(**kwargs)

class MicroRequestContext(webapp2.RequestContext):
    """Context for a single request"""
    def __enter__(self, *args, **kwargs):
        """Create request and response objects

        After the request object created, it's used as a parameter for
        a number of user-defined initializer functions
        Those could be used to set session parameters for the request,
        check permissions and so on.
        """
        rv = super(MicroRequestContext, self).__enter__(*args, **kwargs)
        request, response = rv
        for initializer in self.app.on_request:
            initializer(request)

        return request, response

class MicroRequest(webapp2.Request):
    """Extends standard Request object with some new properties"""
    def __init__(self, *args, **kwargs):
        super(MicroRequest, self).__init__(*args, **kwargs)
        self.cookie = SecureCookie(self)

class SecureCookie(object):
    """Manipulates request cookies in a secure manner

    All cookies are sent as 'str_value|hmac_hash' which makes it impossible
    to edit values of those cookies anywhere except the server
    """
    def __init__(self, request):
        self.request = request
        # when a cookie is `set` it's value is cached so that
        # the following `get` will have access to that value
        self.cached = {}

    @classmethod
    def hash_str(cls, s):
        return hmac.new(COOKIE_SECRET, s).hexdigest()

    @classmethod
    def to_secure_cookie(cls, s):
        return "%s|%s" % (s, cls.hash_str(s))

    @classmethod
    def from_secure_cookie(cls, s):
        if not s:
            s = ""
        s = str(s)
        val = s.split('|')[0]
        if s == cls.to_secure_cookie(val):
            return val

    def get(self, name):
        name = str(name)
        # if the cookie was set earlier within the request, return that value
        if name in self.cached:
            return self.cached[name]

        hashed = self.request.cookies.get(name)
        if not hashed:
            return None
        # validate the cookie's value, delete if invalid, and return it
        result = self.__class__.from_secure_cookie(hashed)
        if result is None:
            self.delete(name)
        return result

    def set(self, name, value):
        name = str(name)
        value = str(value)
        self.cached[name] = value

        value = self.__class__.to_secure_cookie(value)
        headers = self.request.response.headers
        headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, value))

    def delete(self, name):
        name = str(name)
        self.cached[name] = None

        headers = self.request.response.headers
        headers.add_header('Set-Cookie', '%s=; Path=/' % name)

class Renderer(object):
    """A callable returning HTML output

    Returned from the request handlers, used in the request dispatcher
    """
    def __init__(self, jinja_env, template, **kwargs):
        self.jinja_env = jinja_env
        self.template = template
        self.kwargs = kwargs

    def __call__(self, request):
        jinja_env = self.jinja_env
        template = self.template
        kwargs = self.kwargs
        t = jinja_env.get_template(template)
        if 'request' in kwargs:
            Exception("Parameter name 'request' is not permitted")
        # pass the request object as a parameter to the template
        kwargs['request'] = request
        return t.render(kwargs)

class Redirector(object):
    """Stores parameters for `webapp2.uri_for` method as a callable

    Returned from the request handlers, used in the request dispatcher
    """
    def __init__(self, name, *args, **kwargs):
        for k in kwargs:
            #convert all optional parameters to str
            kwargs[k] = str(kwargs[k])
        self.name = name
        self.args = args
        self.kwargs = kwargs

    def __call__(self):
        uri = webapp2.uri_for(self.name, *self.args, **self.kwargs)
        return uri

class ABNDict(object):
    """Attributes By Name Dictionary

    Stores values which have __name__ attribute and allows to retrieve them
    by that __name__ in dot notation as:

    def f(par1, par2):
        pass
    abn = ABNDict()
    abn(f)
    print abn.f('par1', 'par2')
    """
    def __init__(self):
        self.dict = {}

    def __call__(self, value):
        self.dict[value.__name__] = value

    def __getattr__(self, attr):
        if not attr in self.dict:
            return None
        return self.dict[attr]

def redirect_to_route(handler, *args, **kwargs):
    """A callable for `_uri` parameter of webapp2.RedirectHandler

    Returns a URI redirect to
    """
    route_name = kwargs.pop('_route', None)
    return handler.uri_for(route_name, *args, **kwargs)
