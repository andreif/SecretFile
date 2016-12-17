import cgi
import json
import os
import re
import uuid
import shutil
import urllib.parse

import time
from contextlib import contextmanager


def uuid_str():
    return str(uuid.uuid4()).replace('-', '')


class App(object):
    def __init__(self, debug=False, https_only=False):
        self.debug = debug
        self.https_only = https_only

    def __call__(self, env, response):
        self.env = env
        self._response = response
        # print('\n'.join(sorted(env)))
        return self.dispatch()

    def path(self):
        return self.env.get('SCRIPT_NAME', '') + self.env.get('PATH_INFO', '')

    def url_params(self):
        return urllib.parse.parse_qs(self.env.get('QUERY_STRING', ''))

    def method(self):
        return self.env['REQUEST_METHOD']

    def is_post(self):
        return self.method() == 'POST'

    def form(self):
        return cgi.FieldStorage(
            fp=self.env['wsgi.input'],
            environ=self.env,
            keep_blank_values=True
        )

    def redirect(self, to, permanent=False, headers=None):
        return self.response(code=301 if permanent else 302,
                             headers=dict({'Location': to}, **(headers or {})))

    def response(self, code=200, content_type=None, headers=None, content=''):
        headers = dict(DEFAULT_HEADERS, **(headers or {}))
        if content_type:
            headers['Content-Type'] = \
                CONTENT_TYPES.get(content_type, content_type)
        if self.https_only:
            headers['Strict-Transport-Security'] = 'max-age=31536000'

        self._response('%d %s' % (code, RESPONSES[code]), list(headers.items()))
        if hasattr(content, 'read'):
            block_size = 8196 * 4
            if 'wsgi.file_wrapper' in self.env:
                return self.env['wsgi.file_wrapper'](content, block_size)
            else:
                return iter(lambda: content.read(block_size), '')
        elif isinstance(content, str):
            return [content.encode()]
        elif isinstance(content, bytes):
            return [content]
        elif isinstance(content, list):
            return content
        raise NotImplementedError

    def is_https(self):
        return self.env['wsgi.url_scheme'] == 'https'

    def host(self):
        h = self.env.get('HTTP_HOST')
        if not h:
            h = self.env['SERVER_NAME']
            if self.is_https():
                if self.env['SERVER_PORT'] != '443':
                    h += ':' + self.env['SERVER_PORT']
            else:
                if self.env['SERVER_PORT'] != '80':
                    h += ':' + self.env['SERVER_PORT']
        return h

    def full_url(self, scheme=None):
        url = (scheme or self.env['wsgi.url_scheme']) + '://'
        url += self.host()
        url += urllib.parse.quote(self.path())
        qs = self.env.get('QUERY_STRING')
        if qs:
            url += '?' + qs
        return url

    def dispatch(self):
        if self.https_only and not self.is_https():
            return self.redirect(to=self.full_url(scheme='https'))

        m = re.match('/secret/([^/]+)/([^/]+)$', self.path())
        if m:
            return self.serve_file(*m.groups())

        q = self.url_params()
        if self.is_post():
            f = self.store_file(form=self.form())
            return self.redirect('/', headers={
                'Set-Cookie': 'link=' + (urllib.parse.quote(f.url) if f else ''),
            })
        elif self.path() == '/style.css':
            return self.response(content=open('templates/style.css').read(),
                                 content_type='css')
        elif self.path() == '/clean':
            return self.response(content='{total} {available} {cleaned} {gone}'.format(**File.clean()))
        elif self.path() != '/' or set(q) not in ({'link'}, set()):
            return self.redirect(to='/')
        else:
            return self.response(content=open('templates/index.html').read(),
                                 content_type='html')

    def serve_file(self, uid, name):
        f = File(name=name, uid=uid)
        pwd = self.form().getfirst('pwd')
        if f.should_ask_password(password=pwd, is_post=self.is_post()):
            return self.response(content=open('templates/password.html').read(),
                                 content_type='html')
        if f.allowed(password=pwd):
            ct = CONTENT_TYPES.get(f.ext) or 'application/octet-stream'
            with f.open() as fp:
                return self.response(content=fp, content_type=ct)
        else:
            return self.response(404, content=f.error, content_type='html')

    def store_file(self, form):
        name = os.path.basename(form['file'].filename or '')
        if name in ('', '__conf__.json'):
            return
        f = File(name=name)
        f.copy(form['file'].file)
        lt = int(form.getfirst('lifetime') or 0) or None
        if lt:
            lt = time.time() + 60 * lt
        f.save_conf({
            'password': form.getfirst('pwd') or None,
            'encrypt': form.getfirst('encrypt') or None,
            'self_destruct': bool(form.getfirst('destruct')),
            'countdown': int(form.getfirst('max') or 0) or None,
            'valid_until': lt,
            'created_at': time.time(),
            'name': name,
            'size': f.size,
        })
        return f


class File(object):
    def __init__(self, name, uid=None):
        print(name)
        self.uid = uid or uuid_str()
        self.name = name
        self.conf = self.error = None
        self.load_conf()

    def copy(self, src_fp):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, 'wb+') as dst_fp:
            shutil.copyfileobj(src_fp, dst_fp)

    @classmethod
    def clean(cls):
        c = {
            'gone': 0,
            'total': 0,
            'cleaned': 0,
            'available': 0,
        }
        if os.path.exists('files'):
            for d in os.listdir('files'):
                if len(d) == 32:
                    c['total'] += 1
                    f = File(uid=d, name='x')
                    f.name = f.conf.get('name') or f.name
                    if f.exist():
                        if not f.available():
                            f.conf['cleaned'] = True
                            f.destroy()
                            c['cleaned'] += 1
                        else:
                            c['available'] += 1
                    else:
                        c['gone'] += 1
        return c

    @property
    def path(self):
        return 'files/%s/%s' % (self.uid, os.path.basename(self.name))

    @property
    def ext(self):
        return self.path.rpartition('.')[-1].lower()

    @property
    def conf_path(self):
        return os.path.join(os.path.dirname(self.path), '__conf__.json')

    @property
    def url(self):
        return '/secret/' + self.path.partition('files/')[2]

    @property
    def size(self):
        return os.path.getsize(self.path)

    def load_conf(self):
        if os.path.exists(self.conf_path):
            with open(self.conf_path) as fp:
                self.conf = json.load(fp)

    def save_conf(self, conf=None):
        if conf:
            self.conf = conf
        with open(self.conf_path, 'w') as fp:
            json.dump(self.conf, fp, indent=2)

    def count_down(self):
        if self.conf['countdown']:
            self.conf['countdown'] -= 1
        self.conf.setdefault('accessed_times', 0)
        self.conf['accessed_times'] += 1
        self.conf['accessed_at'] = time.time()
        self.save_conf()

    def is_over(self):
        n = self.conf['countdown']
        return n is not None and n <= 0

    def is_expired(self):
        t = self.conf['valid_until']
        return t and time.time() > t

    def has_password(self):
        return self.conf and self.conf['password']

    def wrong_password(self, password):
        should = self.has_password()
        return should and should != password

    def must_destroy(self):
        return self.conf and self.conf['self_destruct']

    def available(self):
        if not self.conf:
            self.error = 'missing'
        elif self.is_expired():
            self.error = 'expired'
        elif self.is_over():
            self.error = 'over'
        elif not self.exist():
            self.error = 'gone'
        return not self.error

    def allowed(self, password=None):
        if self.available() and self.wrong_password(password):
            if self.must_destroy():
                self.error = 'destroy'
            else:
                return
        if self.error:
            self.destroy()
        else:
            self.count_down()
            return True

    @contextmanager
    def open(self):
        yield open(self.path, 'rb')

    def read(self):
        with self.open() as fp:
            return fp.read()

    def exist(self):
        return os.path.exists(self.path)

    def destroy(self):
        if self.exist():
            self.conf['removed_at'] = time.time()
            self.conf['removed_because'] = self.error
            self.save_conf()
            os.unlink(self.path)

    def should_ask_password(self, password, is_post):
        return self.available() and self.has_password() and (
            not is_post or (
                self.wrong_password(password=password) and
                not self.must_destroy()))


RESPONSES = {
    200: 'OK',
    301: 'Moved Permanently',
    302: 'Found',
    404: 'Not Found',
}

CONTENT_TYPES = {
    'txt': 'text/plain; charset=utf-8',
    'html': 'text/html; charset=utf-8',
    'css': 'text/css; charset=utf-8',
    'js': 'application/javascript; charset=utf-8',
    'png': 'image/png',
    'jpg': 'image/jpeg',
}

DEFAULT_HEADERS = {
    'Server': 'nginx',
}

debug = bool(os.environ.get('DEBUG'))
app = App(debug=debug, https_only=not debug)


if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    from wsgiref.handlers import BaseHandler
    BaseHandler.error_body = b''
    try:
        host = os.environ.get('HOST') or '127.0.0.1'
        host, _, port = host.partition(':')
        port = int(port or os.environ.get('PORT') or 8000)
        print('Starting server %s:%s...' % (host, port))
        make_server(host=host, port=port, app=app).serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')
