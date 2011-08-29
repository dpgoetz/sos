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
        iter_tup = self.status_headers_body_iter.next()
        if len(iter_tup) == 3:
            status, headers, body = iter_tup
        else:
            status, headers, body, tester = iter_tup
            test_res = tester(self.request.headers, self.request.body)
            if test_res:
                raise Exception(test_res)


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
        # PUTs for account and 16 .hash's
        self.test_origin.app = FakeApp(iter(
           [('204 No Content', {}, '') for i in xrange(18)]))
        resp = Request.blank('/origin/.prep',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'X-Origin-Admin-User': '.origin_admin',
                     'X-Origin-Admin-Key': 'unittest'}
            ).get_response(self.test_origin)
        self.assertEquals(resp.status_int, 204)
        self.assertEquals(self.test_origin.app.calls, 17)

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

    def test_origin_db_post_ttl(self):
        data = {'account': 'acc', 'container': 'cont',
                'ttl': 29500, 'logs_enabled': 'false',
                'cdn_enabled': 'true'}
        self.test_origin.app = FakeApp(iter(
            [('200 Ok', {}, json.dumps(data)),
            ]))
        resp = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'POST'}, headers={'X-TTL': 'foo'},
            ).get_response(self.test_origin)
        self.assertEquals(resp.status_int, 400)
        self.assertTrue('Invalid X-TTL, must be integer' in resp.body)

        self.test_origin.app = FakeApp(iter(
            [('200 Ok', {}, json.dumps(data)),
            ]))
        resp = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'POST'}, headers={'X-TTL': '1'},
            ).get_response(self.test_origin)
        self.assertEquals(resp.status_int, 400)
        self.assertTrue('Invalid X-TTL, must be between' in resp.body)

    def test_origin_db_put(self):
        data = {'account': 'acc', 'container': 'cont',
                'ttl': 29500, 'logs_enabled': 'false',
                'cdn_enabled': 'true'}
        self.test_origin.app = FakeApp(iter([
            ('404 Not Found', {}, ''), # call to _get_cdn_data
            ('204 No Content', {}, ''), # put to .hash file
            ('404 Not Found', {}, ''), # HEAD call, see if create cont
            ('204 No Content', {}, ''), # put to create container
            ('204 No Content', {}, ''), # put to add obj to listing
            ]))
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'PUT'},
            )
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 201) # put returns a 201

    def test_origin_db_post_404(self):
        data = {'account': 'acc', 'container': 'cont',
                'ttl': 29500, 'logs_enabled': 'false',
                'cdn_enabled': 'true'}
        self.test_origin.app = FakeApp(iter([
            ('404 Not Found', {}, ''), # call to _get_cdn_data
            ]))
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'POST'},
            )
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 404)

    def test_origin_db_post(self):
        prev_data = json.dumps({'account': 'acc', 'container': 'cont',
                'ttl': 1234, 'logs_enabled': 'true',
                'cdn_enabled': 'false'})
        data = {'account': 'acc', 'container': 'cont',
                'cdn_enabled': 'true'}

        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, prev_data), # call to _get_cdn_data
            ('204 No Content', {}, '',
                lambda h,b : False if json.loads(b)['ttl'] == 1234
                    else 'Defaults not kept'), # put to .hash file
            ('404 Not Found', {}, ''), # HEAD call, see if create cont
            ('204 No Content', {}, ''), # put create cont
            ('204 No Content', {}, ''), # put to add obj to listing
            ]))
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'POST'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 202)

    #TODO: some unicode tests

    def test_origin_db_get_json(self):
        listing_data = json.dumps([
            {'name': 'test1', 'content_type': 'x-cdn/true-1234-false'},
            {'name': 'test2', 'content_type': 'x-cdn/true-2234-false'}])
        self.test_origin.app = FakeApp(iter([
            ('200 Ok', {}, listing_data),
            ]))
        req = Request.blank(
            'http://origin_db.com:8080/v1/acc/cont?format=json',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        data = json.loads(resp.body)
        self.assertEquals(data[0]['ttl'], '1234')
        self.assertEquals(data[1]['ttl'], '2234')
        self.assertEquals(resp.status_int, 200)

    def test_origin_db_get_fail(self):
        # bad listing lines are ignored
        listing_data = json.dumps([
            {'name': 'test1', 'content_type': 'x-cdn/true1234-false'},
            {'name': 'test2', 'content_type': 'x-cdn/true-2234-false'}])
        self.test_origin.app = FakeApp(iter([
            ('200 Ok', {}, listing_data),
            ]))
        req = Request.blank(
            'http://origin_db.com:8080/v1/acc/cont?format=json',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        data = json.loads(resp.body)
        self.assertEquals(data[0]['ttl'], '2234')
        self.assertEquals(len(data), 1)
        self.assertEquals(resp.status_int, 200)

    def test_origin_db_get_xml(self):
        listing_data = json.dumps([
            {'name': 'test1', 'content_type': 'x-cdn/true-1234-false'},
            {'name': 'test2', 'content_type': 'x-cdn/true-2234-false'}])
        self.test_origin.app = FakeApp(iter([
            ('200 Ok', {}, listing_data),
            ]))
        req = Request.blank(
            'http://origin_db.com:8080/v1/acc/cont?format=xml',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        self.assert_('<ttl>1234</ttl>' in resp.body)
        self.assertEquals(resp.status_int, 200)

    def test_origin_db_head(self):
        prev_data = json.dumps({'account': 'acc', 'container': 'cont',
                'ttl': 1234, 'logs_enabled': 'true',
                'cdn_enabled': 'false'})

        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, prev_data), # call to _get_cdn_data
            ]))
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'HEAD'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 204)
        self.assertEquals(resp.headers['x-ttl'], 1234)

if __name__ == '__main__':
    unittest.main()
