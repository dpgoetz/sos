# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

try:
    import simplejson as json
except ImportError:
    import json
import unittest
#from contextlib import contextmanager
#from time import time

from webob import Request, Response

from sos import origin


class FakeConf(object):

    def __init__(self, data=None):
        if data:
            self.data = data
        else:
            self.data = '''[sos]
origin_admin_key = unittest
origin_cdn_hosts = origin_cdn.com
origin_db_hosts = origin_db.com
origin_account = .origin
outgoing_cdn_uri_format = http://cdn.com:8080/h%(hash)s/r%(hash_mod)d
outgoing_ssl_cdn_uri_format = https://ssl.cdn.com/h%(hash)s'''.split('\n')

    def readline(self):
        if self.data:
            return self.data.pop(0)
        return ''


class FakeApp(object):

    def __init__(self, status_headers_body_iter=None):
        self.calls = 0
        self.status_headers_body_iter = status_headers_body_iter
        if not self.status_headers_body_iter:
            self.status_headers_body_iter = iter([('404 Not Found', {}, '')])

    def __call__(self, env, start_response):
        self.calls += 1
        self.request = Request.blank('', environ=env)
#        if 'swift.authorize' in env:
#            resp = env['swift.authorize'](self.request)
#            if resp:
#                return resp(env, start_response)
        status, headers, body = self.status_headers_body_iter.next()
        return Response(status=status, headers=headers,
                        body=body)(env, start_response)


class FakeConn(object):

    def __init__(self, status_headers_body_iter=None):
        self.calls = 0
        self.status_headers_body_iter = status_headers_body_iter
        if not self.status_headers_body_iter:
            self.status_headers_body_iter = iter([('404 Not Found', {}, '')])

    def request(self, method, path, headers):
        self.calls += 1
        self.request_path = path
        self.status, self.headers, self.body = \
            self.status_headers_body_iter.next()
        self.status, self.reason = self.status.split(' ', 1)
        self.status = int(self.status)

    def getresponse(self):
        return self

    def read(self):
        body = self.body
        self.body = ''
        return body


class TestOrigin(unittest.TestCase):

    def setUp(self):
        fake_conf = FakeConf()
        self.test_origin = origin.filter_factory(
            {'sos_conf': fake_conf})(FakeApp())

    def test_valid_setup(self):
        fake_conf = FakeConf(data=['[sos]'])
        test_origin = origin.filter_factory(
            {'sos_conf': fake_conf})(FakeApp())
        self.assertFalse(test_origin._valid_setup())

        fake_conf = FakeConf()
        test_origin = origin.filter_factory(
            {'sos_conf': fake_conf})(FakeApp())
        self.assertTrue(test_origin._valid_setup())

    def test_admin_setup_failures(self):
        resp = Request.blank('/origin/.prep',
            environ={'REQUEST_METHOD': 'PUT'}).get_response(self.test_origin)
        self.assertEquals(resp.status_int, 403)

        resp = Request.blank('/origin/.prep_not_there',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'X-Origin-Admin-User': '.origin_admin',
                     'X-Origin-Admin-Key': 'unittest'}
            ).get_response(self.test_origin)
        self.assertEquals(resp.status_int, 404)

        self.test_origin.app = FakeApp(iter([('404 Not Found', {}, '')]))
        try:
            resp = Request.blank('/origin/.prep',
                environ={'REQUEST_METHOD': 'PUT'},
                headers={'X-Origin-Admin-User': '.origin_admin',
                         'X-Origin-Admin-Key': 'unittest'}
                ).get_response(self.test_origin)
        except Exception:
            pass
        else:
            self.assertTrue(False)

    def test_admin_setup(self):
        # PUTs for account, 16 .hash's, and .hash_to_legacy
        self.test_origin.app = FakeApp(iter(
           [('204 No Content', {}, '') for i in xrange(18)]))
        resp = Request.blank('/origin/.prep',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'X-Origin-Admin-User': '.origin_admin',
                     'X-Origin-Admin-Key': 'unittest'}
            ).get_response(self.test_origin)
        self.assertEquals(resp.status_int, 204)
        self.assertEquals(self.test_origin.app.calls, 18)

    def test_origin_db_post_fail(self):
        self.test_origin.app = FakeApp(iter(
            [('204 No Content', {}, '')]))
        resp = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'POST'},
            ).get_response(self.test_origin)
        self.assertEquals(resp.status_int, 404)

        self.test_origin.app = FakeApp(iter(
            [('404 Not Found', {}, '')]))
        resp = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'POST'},
            ).get_response(self.test_origin)
        self.assertEquals(resp.status_int, 404)

    def test_origin_db_put(self):
        data = {'account': 'acc', 'container': 'cont',
                'ttl': 29500, 'logs_enabled': 'false',
                'cdn_enabled': 'true'}
        self.test_origin.app = FakeApp(iter([
            ('404 Not Found', {}, ''), # call to get current values
            ('204 Not Found', {}, ''), # call to get current values
            ]))
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'PUT'},
            )
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 204)

    def test_origin_db_put_update(self):
        data = {'account': 'acc', 'container': 'cont',
                'ttl': 29500, 'logs_enabled': 'false',
                'cdn_enabled': 'true'}
        self.test_origin.app = FakeApp(iter(
            [('200 Ok', {}, json.dumps(data)),
            ]))
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'PUT'},
            )
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 204)

if __name__ == '__main__':
    unittest.main()
