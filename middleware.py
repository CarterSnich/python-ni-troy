import io
import re
from flask import Flask, request, session, flash, redirect, url_for
from werkzeug.wrappers import Request


class MethodRewriteMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        req = Request(environ)
        req.get_data(cache=True)
        environ["wsgi.input"] = io.BytesIO(req.get_data())

        method = environ.get("REQUEST_METHOD", "").upper()
        _method = req.form.get("_method")

        if method == "POST" and _method:
            override = _method.upper()
            if override in ["PUT", "PATCH", "DELETE"]:
                environ["REQUEST_METHOD"] = override

        return self.app(environ, start_response)


class AuthMiddleware:
    def __init__(self, app, wsgi_app, protected_prefixes=("/users",)):
        self.app = app
        self.wsgi_app = wsgi_app
        self.protected_prefixes = protected_prefixes

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")

        if path.startswith("/static/") or path == "/favicon.ico":
            return self.wsgi_app(environ, start_response)

        with self.app.request_context(environ):
            auth_user = session.get("user")

            if any(path.startswith(prefix) for prefix in self.protected_prefixes):
                if not auth_user:
                    flash("Please, sign in first.", "warning")
                    return redirect(url_for("index"))(environ, start_response)

            elif auth_user:
                return redirect(url_for("users"))(environ, start_response)

        return self.wsgi_app(environ, start_response)
