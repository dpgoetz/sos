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
import urllib
from hashlib import md5

from swift.common.swob import Request, Response, HTTPUnauthorized

from sos import origin
from swift.common import utils


class PropertyObject(object):
    """
    Simple empty object that you set adhoc attributes on.
    """
    pass


class FakeConf(object):

    def __init__(self, data=None):
        if data:
            self.data = data
        else:
            self.data = '''[sos]
origin_admin_key = unittest
origin_db_hosts = origin_db.com
origin_cdn_host_suffixes = origin_cdn.com
origin_account = .origin
hash_path_suffix = testing
number_hash_id_containers = 100
hmac_signed_url_secret = 'asdf'
[outgoing_url_format]
# the entries in this section "key = value" determines the blah blah...
X-CDN-URI = http://%(hash)s\.r%(hash_mod)d\.origin_cdn.com:8080
X-CDN-SSL-URI = https://%(hash)s\.ssl.origin_cdn.com
X-CDN-STREAMING-URI = http://%(hash)s\.r%(hash_mod)d\.stream.origin_cdn.com:8080
[incoming_url_regex]
regex_0 = ^http://(?P<hash>\w+)\.r\d+\.origin_cdn\.com[^\/]*\/?(?P<object_name>(.+))?$
regex_1 = ^https://(?P<hash>\w+)\.ssl.origin_cdn\.com[^\/]*\/?(?P<object_name>(.+))?$
'''.split('\n')

    def readline(self):
        if self.data:
            op = self.data.pop(0)
            return op #self.data.pop(0)
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
        if 'swift.authorize' in env:
            resp = env['swift.authorize'](self.request)
            if resp:
                return resp(env, start_response)
        iter_tup = self.status_headers_body_iter.next()
        if len(iter_tup) == 3:
            status, headers, body = iter_tup
        else:
            status, headers, body, tester = iter_tup
            test_res = tester(self.request)
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

class FakeMemcache(object):

    def __init__(self, override_get='', raise_on_delete=True):
        self.store = {}
        self.timeouts = {}
        self.override_get = override_get
        self.raise_on_delete = raise_on_delete

    def get(self, key):
        if self.override_get:
            return self.override_get
        return self.store.get(key)

    def set(self, key, value, serialize=False, time=0):
        self.store[key] = value
        self.timeouts[key] = time
        return True

    def delete(self, key):
        if self.raise_on_delete:
            raise Exception('delete called')


class FakeLogger(object):

    def __init__(self):
        self.debug_calls = []

    def debug(self, *args, **kwargs):
        self.debug_calls.append((args, kwargs))


class TestHashData(unittest.TestCase):

    def test_init(self):
        h = origin.HashData('a', 'c', '123', True, False)
        self.assertEquals(h.account, 'a')
        self.assertEquals(h.container, 'c')
        self.assertEquals(h.ttl, 123)
        self.assertTrue(h.cdn_enabled)
        self.assertFalse(h.logs_enabled)

    def test_get_json_str(self):
        h = origin.HashData('a', 'c', '123', True, False)
        self.assertEquals(origin.json.loads(h.get_json_str()),
            {'account': 'a', 'container': 'c', 'ttl': 123,
             'cdn_enabled': True, 'logs_enabled': False, 'deleted': False})

    def test_str(self):
        h = origin.HashData('a', 'c', '123', True, False)
        self.assertEquals(origin.json.loads(str(h)),
            {'account': 'a', 'container': 'c', 'ttl': 123,
             'cdn_enabled': True, 'logs_enabled': False, 'deleted': False})

    def test_create_from_json(self):
        h = origin.HashData.create_from_json(
            str(origin.HashData('a', 'c', '123', True, False)))
        self.assertEquals(h.account, 'a')
        self.assertEquals(h.container, 'c')
        self.assertEquals(h.ttl, 123)
        self.assertTrue(h.cdn_enabled)
        self.assertFalse(h.logs_enabled)

    def test_equals(self):
        l = origin.HashData('a', 'c', '123', True, False)
        r = origin.HashData('a', 'c', '123', True, False)
        q = origin.HashData('a', 'c', '123', False, False)
        self.assertTrue(l == r)
        self.assertTrue(l != q)

class TestOriginBase(unittest.TestCase):

    def setUp(self):
        conf = origin.OriginServer._translate_conf({'sos_conf': FakeConf()})
        self.origin_base = origin.OriginBase(FakeApp(), conf, FakeLogger())

    def test_memcaching_not_found(self):
        memcache = FakeMemcache()
        env = {'swift.cache': memcache}
        hsh = self.origin_base.hash_path('a', 'c')
        path = self.origin_base.get_hsh_obj_path(hsh)
        key = self.origin_base.cdn_data_memcache_key(path)
        make_pre_authed_request_calls = []

        def _make_pre_authed_request(*args, **kwargs):
            make_pre_authed_request_calls.append((args, kwargs))
            resp = PropertyObject()
            resp.status_int = 404
            req = PropertyObject()
            req.get_response = lambda *a, **kwargs: resp
            return req

        make_pre_authed_request_orig = origin.make_pre_authed_request
        try:
            origin.make_pre_authed_request = _make_pre_authed_request
            self.assertEquals(self.origin_base.get_cdn_data(env, path), None)
        finally:
            origin.make_pre_authed_request = make_pre_authed_request_orig
        self.assertEquals(len(make_pre_authed_request_calls), 1)
        self.assertEquals(memcache.store, {key: '404'})
        self.assertEquals(memcache.timeouts, {key: origin.CACHE_404})

        del make_pre_authed_request_calls[:]
        self.assertEquals(self.origin_base.get_cdn_data(env, path), None)
        self.assertEquals(len(make_pre_authed_request_calls), 0)


class TestCdnHandler(unittest.TestCase):

    def setUp(self):
        conf = origin.OriginServer._translate_conf({'sos_conf': FakeConf()})
        self.cdn_handler = origin.CdnHandler(FakeApp(), conf, FakeLogger())

    def test_allowed_origin_remote_ips_conf(self):
        conf = origin.OriginServer._translate_conf({'sos_conf': FakeConf()})
        if 'allowed_origin_remote_ips' in conf:
            del conf['allowed_origin_remote_ips']
        cdn_handler = origin.CdnHandler(FakeApp(), conf, FakeLogger())
        self.assertEquals(cdn_handler.allowed_origin_remote_ips, [])

        conf = origin.OriginServer._translate_conf({'sos_conf': FakeConf()})
        conf['allowed_origin_remote_ips'] = '1.2.3.4'
        cdn_handler = origin.CdnHandler(FakeApp(), conf, FakeLogger())
        self.assertEquals(cdn_handler.allowed_origin_remote_ips, ['1.2.3.4'])

        conf = origin.OriginServer._translate_conf({'sos_conf': FakeConf()})
        conf['allowed_origin_remote_ips'] = ', , 1.2.3.4, 5.6.7.8 , ,'
        cdn_handler = origin.CdnHandler(FakeApp(), conf, FakeLogger())
        self.assertEquals(cdn_handler.allowed_origin_remote_ips,
                          ['1.2.3.4', '5.6.7.8'])

    def test_reject_non_allowed_origin_remote_ips(self):
        conf = origin.OriginServer._translate_conf({'sos_conf': FakeConf()})
        conf['allowed_origin_remote_ips'] = '1.2.3.4'
        cdn_handler = origin.CdnHandler(FakeApp(), conf, FakeLogger())
        env = {'REQUEST_METHOD': 'HEAD'}
        req = Request.blank('/test', environ=env)
        exc = None
        try:
            cdn_handler.handle_request(env, req)
        except origin.OriginRequestNotAllowed, err:
            exc = err
        self.assertEquals(str(exc), 'SOS Origin: Remote IP None not allowed')

        env = {'REQUEST_METHOD': 'HEAD', 'REMOTE_ADDR': '5.6.7.8'}
        req = Request.blank('/test', environ=env)
        exc = None
        try:
            cdn_handler.handle_request(env, req)
        except origin.OriginRequestNotAllowed, err:
            exc = err
        self.assertEquals(str(exc), 'SOS Origin: Remote IP 5.6.7.8 not allowed')

        env = {'REQUEST_METHOD': 'HEAD', 'REMOTE_ADDR': '1.2.3.4'}
        req = Request.blank('/test', environ=env)
        resp = cdn_handler.handle_request(env, req)
        self.assertEquals(resp.status_int, 404)

    def test_bad_hash(self):
        self.cdn_handler.logger = logger = FakeLogger()
        env = {'REQUEST_METHOD': 'HEAD'}
        req = Request.blank('http://one.r3.origin_cdn.com:8080/obj1.jpg',
                            environ=env)
        resp = self.cdn_handler.handle_request(env, req)
        self.assertEquals(resp.status_int, 400)
        self.assertEquals(resp.headers['Cache-Control'],
                          'max-age=86400, public')
        self.assertEquals(logger.debug_calls, [(("get_hsh_obj_path error: "
            "invalid literal for int() with base 16: 'one'",), {})])
        del logger.debug_calls[:]

        env = {'REQUEST_METHOD': 'HEAD', 'swift.cdn_hash': 'one-two',
               'swift.cdn_object_name': 'obj1.jpg'}
        req = Request.blank('http://1234.r3.origin_cdn.com:8080/obj1.jpg',
                            environ=env)
        resp = self.cdn_handler.handle_request(env, req)
        self.assertEquals(resp.status_int, 400)
        self.assertEquals(resp.headers['Cache-Control'],
                          'max-age=86400, public')
        self.assertEquals(logger.debug_calls, [(("get_hsh_obj_path error: "
            "invalid literal for int() with base 16: 'two'",), {})])
        


class TestOrigin(unittest.TestCase):

    def setUp(self):
        fake_conf = FakeConf()
        self.test_origin = origin.filter_factory(
            {'sos_conf': fake_conf})(FakeApp())

#    def test_valid_setup(self):
#        fake_conf = FakeConf(data=['[sos]'])
#        test_origin = origin.filter_factory(
#            {'sos_conf': fake_conf})(FakeApp())
#        self.assertFalse(test_origin._valid_setup())
#
#        fake_conf = FakeConf()
#        test_origin = origin.filter_factory(
#            {'sos_conf': fake_conf})(FakeApp())
#        self.assertTrue(test_origin._valid_setup())

    def test_no_handlers(self):
        self.test_origin.app = FakeApp(iter([('204 No Content', {}, '')]))
        resp = Request.blank('/tester',
            environ={'REQUEST_METHOD': 'GET'},
            ).get_response(self.test_origin)
        self.assertEquals(resp.status_int, 204)

    def test_bad_utf_8(self):
        utf_path = '/v1/AUTH_test/\xde'
        resp = Request.blank(utf_path, environ={'REQUEST_METHOD': 'PUT',
            'HTTP_HOST': 'origin_db.com'}).get_response(self.test_origin)
        self.assertEquals(resp.status_int, 412)

    def test_admin_setup_failures(self):
        resp = Request.blank('/origin/.prep',
            environ={'REQUEST_METHOD': 'PUT'}).get_response(self.test_origin)
        self.assertEquals(resp.status_int, 403)

        resp = Request.blank('/origin/.prep_not_there',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'X-Origin-Admin-User': '.origin_admin',
                     'X-Origin-Admin-Key': 'unittest'}).get_response(
                     self.test_origin)
        self.assertEquals(resp.status_int, 404)

        self.test_origin.app = FakeApp(iter([('404 Not Found', {}, '')]))
        try:
            resp = Request.blank('/origin/.prep',
                environ={'REQUEST_METHOD': 'PUT'},
                headers={'X-Origin-Admin-User': '.origin_admin',
                         'X-Origin-Admin-Key': 'unittest'}).get_response(
                         self.test_origin)
        except Exception:
            pass
        else:
            self.assertTrue(False)

    def test_admin_setup(self):
        # PUTs for account and 16 .hash's
        self.test_origin.app = FakeApp(iter(
           [('204 No Content', {}, '') for i in xrange(201)]))
        resp = Request.blank('/origin/.prep',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'X-Origin-Admin-User': '.origin_admin',
                     'X-Origin-Admin-Key': 'unittest'}).get_response(
                     self.test_origin)
        self.assertEquals(resp.status_int, 204)
        self.assertEquals(self.test_origin.app.calls, 101)

        self.test_origin.app = FakeApp(iter(
           [('404 Not Found', {}, '')]))
        req = Request.blank('/origin/.prep',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'X-Origin-Admin-User': '.origin_admin',
                     'X-Origin-Admin-Key': 'unittest'})
        self.assertRaises(Exception, req.get_response, self.test_origin)

        self.test_origin.app = FakeApp(iter(
           [('204 No Content', {}, ''), ('404 Not Found', {}, '')]))
        req = Request.blank('/origin/.prep',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'X-Origin-Admin-User': '.origin_admin',
                     'X-Origin-Admin-Key': 'unittest'})
        self.assertRaises(Exception, req.get_response, self.test_origin)

    def test_origin_db_valid_setup(self):
        fake_conf = FakeConf(data=['[sos]',
            'origin_cdn_host_suffixes = origin_cdn.com'])
        test_origin = origin.filter_factory(
            {'sos_conf': fake_conf})(FakeApp())
        resp = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'POST'}).get_response(test_origin)
        self.assertEquals(resp.status_int, 404)

        fake_conf = FakeConf(data='''[sos]
origin_admin_key = unittest
origin_cdn_host_suffixes = origin_cdn.com
origin_db_hosts = origin_db.com
origin_account = .origin
max_cdn_file_size = 0
'''.split('\n'))
        test_origin = origin.filter_factory(
            {'sos_conf': fake_conf})(FakeApp())
        resp = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'POST'}).get_response(test_origin)
        self.assertEquals(resp.status_int, 500)

        fake_conf = FakeConf(data='''[sos]
origin_admin_key = unittest
origin_db_hosts = origin_db.com
origin_account = .origin
max_cdn_file_size = 0
'''.split('\n'))
        factory = origin.filter_factory(
            {'sos_conf': fake_conf})
        self.assertRaises(origin.InvalidConfiguration, factory, FakeApp())

    def test_origin_db_post_fail(self):
        self.test_origin.app = FakeApp(iter([('204 No Content', {}, '')]))
        resp = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'POST'}).get_response(self.test_origin)
        self.assertEquals(resp.status_int, 404)

        self.test_origin.app = FakeApp(iter([('404 Not Found', {}, '')]))
        resp = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'POST'},).get_response(self.test_origin)
        self.assertEquals(resp.status_int, 404)

    def test_origin_db_post_ttl(self):
        data = {'account': 'acc', 'container': 'cont',
                'ttl': 29500, 'logs_enabled': False, 'cdn_enabled': True}
        self.test_origin.app = FakeApp(iter(
            [('200 Ok', {}, json.dumps(data))]))
        resp = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'POST'}, headers={'X-TTL': 'foo'},
            ).get_response(self.test_origin)
        self.assertEquals(resp.status_int, 400)
        self.assertTrue('Invalid X-TTL, must be integer' in resp.body)

    def test_origin_db_put(self):
        def test_put(req):
            check_hash = md5('/acc/cont/testing').hexdigest()
            if check_hash in req.path:
                return False
            return True
        self.test_origin.app = FakeApp(iter([
            ('404 Not Found', {}, ''), # call to _get_cdn_data
            ('204 No Content', {}, '', test_put), # put to .hash file
            ('404 Not Found', {}, ''), # HEAD call, see if create cont
            ('204 No Content', {}, ''), # put to create container
            ('204 No Content', {}, ''), # put to add obj to listing
            ]))
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont/',
            environ={'REQUEST_METHOD': 'PUT'},
            )
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 201) # put returns a 201

    def test_origin_db_post_404(self):
        data = {'account': 'acc', 'container': 'cont',
                'ttl': 29500, 'logs_enabled': False,
                'cdn_enabled': True}
        self.test_origin.app = FakeApp(iter([
            ('404 Not Found', {}, '')])) # call to _get_cdn_data
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'POST'},
            )
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 404)

    def test_origin_db_post(self):
        prev_data = json.dumps({'account': 'acc', 'container': 'cont',
                'ttl': 1234, 'logs_enabled': True,
                'cdn_enabled': False})
        data = {'account': 'acc', 'container': 'cont', 'cdn_enabled': 'true'}
        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, prev_data), # call to _get_cdn_data
            ('204 No Content', {}, '',
                lambda req: False if json.loads(req.body)['ttl'] == 1234
                    else 'Defaults not kept'), # put to .hash file
            ('404 Not Found', {}, ''), # HEAD call, see if create cont
            ('204 No Content', {}, ''), # put create cont
            ('204 No Content', {}, ''), # put to add obj to listing
            ]))
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'POST'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 202)

    def test_origin_db_post_min_ttl(self):
        prev_data = json.dumps({'account': 'acc', 'container': 'cont',
                'ttl': 12, 'logs_enabled': True,
                'cdn_enabled': False})
        data = {'account': 'acc', 'container': 'cont', 'cdn_enabled': 'true'}
        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, prev_data), # call to _get_cdn_data
            ('204 No Content', {}, '',
                lambda req: False if json.loads(req.body)['ttl'] == 900
                    else 'Not setting min'), # put to .hash file
            ('404 Not Found', {}, ''), # HEAD call, see if create cont
            ('204 No Content', {}, ''), # put create cont
            ('204 No Content', {}, ''), # put to add obj to listing
            ]))
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'POST'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 202)

    def test_origin_db_post_fail(self):
        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, ''), # call to _get_cdn_data
            ('404 Not Found', {}, ''), # put to .hash
            ]))
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'PUT'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 500)

        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, ''), # call to _get_cdn_data
            ('204 No Content', {}, ''), # put to .hash
            ('404 Not Found', {}, ''), # HEAD check to list container
            ('404 Not Found', {}, ''), # PUT to list container
            ]))
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'PUT'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 500)

        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, ''), # call to _get_cdn_data
            ('204 No Content', {}, ''), # put to .hash
            ('204 No Content', {}, ''), # HEAD check to list container
            ('404 Not Found', {}, ''), # PUT to list container
            ]))
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'PUT'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 500)

    def test_origin_db_get(self):
        listing_data = json.dumps([
            {'name': 'test1', 'content_type': 'x-cdn/true-1234-false'},
            {'name': 'test2', 'content_type': 'x-cdn/true-2234-false'}])
        self.test_origin.app = FakeApp(iter([('200 Ok', {}, listing_data)]))
        req = Request.blank(
            'http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        data = resp.body.split('\n')
        self.assertEquals(data[0], 'test1')
        self.assertEquals(data[1], 'test2')
        self.assertEquals(resp.status_int, 200)

    def test_origin_db_get_limit(self):
        listing_data = json.dumps([
            {'name': 'test1', 'content_type': 'x-cdn/true-1234-false'},
            {'name': 'test2', 'content_type': 'x-cdn/true-2234-false'}])
        self.test_origin.app = FakeApp(iter([('200 Ok', {}, listing_data)]))
        req = Request.blank(
            'http://origin_db.com:8080/v1/acc?limit=1',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        data = resp.body.split('\n')
        self.assertEquals(data[0], 'test1')
        self.assertEquals(len(data), 2)
        self.assertEquals(resp.status_int, 200)

    def test_origin_db_get_json(self):
        listing_data = json.dumps([
            {'name': 'test1', 'content_type': 'x-cdn/true-1234-false'},
            {'name': 'test2', 'content_type': 'x-cdn/true-2234-false'}])
        self.test_origin.app = FakeApp(iter([('200 Ok', {}, listing_data)]))
        req = Request.blank(
            'http://origin_db.com:8080/v1/acc/cont?format=json',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        data = json.loads(resp.body)
        self.assertEquals(data[0]['ttl'], 1234)
        self.assertEquals(data[1]['ttl'], 2234)
        self.assertEquals(resp.status_int, 200)

    def test_origin_db_get_json_only_enabled(self):
        listing_data = json.dumps([
            {'name': 'test1', 'content_type': 'x-cdn/false-1234-false'},
            {'name': 'test2', 'content_type': 'x-cdn/true-2234-false'}])
        self.test_origin.app = FakeApp(iter([('200 Ok', {}, listing_data)]))
        req = Request.blank(
            'http://origin_db.com:8080/v1/acc/cont?format=json&enabled=true',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        data = json.loads(resp.body)
        self.assertEquals(data[0]['ttl'], 2234)
        self.assertEquals(len(data), 1)
        self.assertEquals(resp.status_int, 200)

    def test_origin_db_delete_enabled(self):
        fake_conf = FakeConf(data='''[sos]
origin_admin_key = unittest
origin_cdn_host_suffixes = origin_cdn.com
origin_db_hosts = origin_db.com
origin_account = .origin
max_cdn_file_size = 0
hash_path_suffix = testing
'''.split('\n'))
        test_origin = origin.filter_factory(
            {'sos_conf': fake_conf})
        test_origin = test_origin(FakeApp(iter([
            ('204 No Content', {}, ''),
            ('204 No Content', {}, '')
            ])))
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'DELETE',},
            headers={'x-remove-cdn-container': 'true'})
        resp = req.get_response(test_origin)
        self.assertEquals(resp.status_int, 204)

        def mock_memcache(env):
            return FakeMemcache()
        was_memcache = utils.cache_from_env

        try:
            utils.cache_from_env = mock_memcache
            fake_conf = FakeConf(data='''[sos]
origin_admin_key = unittest
origin_cdn_host_suffixes = origin_cdn.com
origin_db_hosts = origin_db.com
origin_account = .origin
max_cdn_file_size = 0
hash_path_suffix = testing
delete_enabled = true
'''.split('\n'))
            test_origin = origin.filter_factory(
                {'sos_conf': fake_conf})
            test_origin = test_origin(FakeApp(iter([
                ('404 No Content', {}, ''),
                ('204 No Content', {}, '')
                ])))
            req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
                environ={'REQUEST_METHOD': 'DELETE',})
            try:
                resp = req.get_response(test_origin)
            except Exception, e:
                self.assertEquals(str(e), 'delete called')
        finally:
            utils.cache_from_env = was_memcache

    def test_origin_db_delete_bad_request(self):
        fake_conf = FakeConf(data='''[sos]
origin_admin_key = unittest
origin_cdn_host_suffixes = origin_cdn.com
origin_db_hosts = origin_db.com
origin_account = .origin
max_cdn_file_size = 0
hash_path_suffix = testing
delete_enabled = true
'''.split('\n'))
        test_origin = origin.filter_factory(
            {'sos_conf': fake_conf})
        test_origin = test_origin(FakeApp(iter([
            ('500 Internal Server Error', {}, '')
            ])))
        req = Request.blank('http://origin_db.com:8080/',
            environ={'REQUEST_METHOD': 'DELETE',})
        resp = req.get_response(test_origin)
        self.assertEquals(resp.status_int, 400)

        req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'DELETE',})
        resp = req.get_response(test_origin)
        self.assertEquals(resp.status_int, 405)

    def test_origin_db_delete_bad_request_second(self):
        fake_conf = FakeConf(data='''[sos]
origin_admin_key = unittest
origin_cdn_host_suffixes = origin_cdn.com
origin_db_hosts = origin_db.com
origin_account = .origin
max_cdn_file_size = 0
hash_path_suffix = testing
delete_enabled = true
'''.split('\n'))
        test_origin = origin.filter_factory(
            {'sos_conf': fake_conf})
        test_origin = test_origin(FakeApp(iter([
            ('204 No Content', {}, ''),
            ('500 Internal Server Error', {}, '')
            ])))
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'DELETE',})
        resp = req.get_response(test_origin)
        self.assertEquals(resp.status_int, 405)

    def test_origin_db_get_fail(self):
        # bad listing lines are ignored
        listing_data = json.dumps([
            {'name': 'test1', 'content_type': 'x-cdn/true1234-false'},
            {'name': 'test1', 'content_type': 'x-cd/true1234-false'},
            {'name': 'test2', 'content_type': 'x-cdn/true-2234-false'}])
        self.test_origin.app = FakeApp(iter([('200 Ok', {}, listing_data)]))
        req = Request.blank(
            'http://origin_db.com:8080/v1/acc/cont?format=json',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        data = json.loads(resp.body)
        self.assertEquals(data[0]['ttl'], 2234)
        self.assertEquals(len(data), 1)
        self.assertEquals(resp.status_int, 200)
        #bad path
        req = Request.blank(
            'http://origin_db.com:8080/v1?format=json',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 400)
        #bad path/
        req = Request.blank(
            'http://origin_db.com:8080/v1/?format=json',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 400)
        #bad limit
        req = Request.blank(
            'http://origin_db.com:8080/v1/acc?limit=hey',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 400)
        # acc not found get
        self.test_origin.app = FakeApp(iter([('404 Not Found', {}, '')]))
        req = Request.blank(
            'http://origin_db.com:8080/v1/acc/cont?format=json',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 200)
        self.assertEquals(resp.body, json.dumps([]))
        # acc not found head
        self.test_origin.app = FakeApp(iter([('404 Not Found', {}, '')]))
        req = Request.blank(
            'http://origin_db.com:8080/v1/acc/cont?format=json',
            environ={'REQUEST_METHOD': 'HEAD'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 404)
        #unauthed
        self.test_origin.app = FakeApp(iter([('404 Not Found', {}, '')]))
        req = Request.blank(
            'http://origin_db.com:8080/v1/acc/cont?format=json',
            environ={'REQUEST_METHOD': 'HEAD',
            'swift.authorize': lambda req: HTTPUnauthorized()})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 401)
        #weird method
        self.test_origin.app = FakeApp(iter([]))
        req = Request.blank(
            'http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'nowhere'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 404)

    def test_db_memcache_head(self):
        def mock_memcache(env):
            return FakeMemcache(override_get=json.dumps({'account': 'acc',
                'container': 'cont', 'ttl': 5555, 'logs_enabled': True,
                'cdn_enabled': False}), raise_on_delete=False)
        was_memcache = utils.cache_from_env
        try:
            utils.cache_from_env = mock_memcache
            self.test_origin.app = FakeApp(iter([('200 Ok', {},
                json.dumps({'account': 'acc', 'container': 'cont', 'ttl': 1234,
                            'logs_enabled': True, 'cdn_enabled': False}))]))
            req = Request.blank(
                'http://origin_db.com:8080/v1/acc/cont',
                environ={'REQUEST_METHOD': 'HEAD'})
            resp = req.get_response(self.test_origin)

            self.assertEquals(resp.status_int, 204)
            self.assertEquals(resp.headers['X-TTL'], '5555')
        finally:
            utils.cache_from_env = was_memcache

    def test_db_memcache_post(self):

        def mock_memcache(env):
            fake_mem = FakeMemcache(override_get=json.dumps({'account': 'acc',
                'container': 'cont', 'ttl': 5555, 'logs_enabled': True,
                'cdn_enabled': False}), raise_on_delete=False)
            def check_set(key, value, serialize=True, time=0):
                data = json.loads(value)
                if data['ttl'] != 5555:
                    raise Exception('Memcache not working')
                if data['cdn_enabled'] != True:
                    raise Exception('Memcache not working')
            fake_mem.set = check_set
            return fake_mem
        was_memcache = utils.cache_from_env
        utils.cache_from_env = mock_memcache
        try:
            prev_data = json.dumps({'account': 'acc', 'container': 'cont',
                    'ttl': 1234, 'logs_enabled': True,
                    'cdn_enabled': False})
            data = {'account': 'acc', 'container': 'cont', 'cdn_enabled':
                'true'}
            self.test_origin.app = FakeApp(iter([ # no cdn call- hit memcache
                ('204 No Content', {}, ''),
#                ('204 No Content', {}, ''), # put create ref cont
                ('404 Not Found', {}, ''), # HEAD call, see if create cont
                ('204 No Content', {}, ''), # put create cont
                ('204 No Content', {}, ''), # put to add obj to listing
                ]))
            req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
                environ={'REQUEST_METHOD': 'PUT'},
                headers={'x-cdn-enabled': 'True', 'x-log-retention': 'f'})
            resp = req.get_response(self.test_origin)
            self.assertEquals(resp.status_int, 201)

        finally:
            utils.cache_from_env = was_memcache

    def test_db_memcache_fail(self):
        def mock_memcache(env):
            return FakeMemcache(override_get=json.dumps({'ttl': 5555}))
        was_memcache = utils.cache_from_env
        try:
            utils.cache_from_env = mock_memcache
            self.test_origin.app = FakeApp(iter([('200 Ok', {},
                json.dumps({'account': 'acc', 'container': 'cont', 'ttl': 1234,
                            'logs_enabled': True, 'cdn_enabled': False}))]))
            req = Request.blank(
                'http://origin_db.com:8080/v1/acc/cont',
                environ={'REQUEST_METHOD': 'HEAD'})
            resp = req.get_response(self.test_origin)
            self.assertEquals(resp.status_int, 204)
            self.assertEquals(resp.headers['X-TTL'], '1234')
        finally:
            utils.cache_from_env = was_memcache

    def test_origin_db_fail_bad_config(self):
        fake_conf = FakeConf(data='''[sos]
origin_admin_key = unittest
origin_cdn_host_suffixes = origin_cdn.com
origin_db_hosts = origin_db.com
origin_account = .origin
max_cdn_file_size = 0
hash_path_suffix = testing
'''.split('\n'))
        test_origin = origin.filter_factory(
            {'sos_conf': fake_conf})
        listing_data = json.dumps([
            {'name': 'test1', 'content_type': 'x-cdn/true1234-false'},
            {'name': 'test2', 'content_type': 'x-cdn/true-2234-false'}])
        test_origin = test_origin(FakeApp(iter([('200 Ok', {}, listing_data)])))
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont?format=JSON',
            environ={'REQUEST_METHOD': 'GET',})
        resp = req.get_response(test_origin)
        self.assertEquals(resp.status_int, 500)

    def test_split_paths(self):

        def fake_split(*args, **kwargs):
            raise ValueError('Testing')
        was_split = origin.split_path
        try:
            origin.split_path = fake_split
            self.test_origin.app = FakeApp(iter([('404 Not Found', {}, '')]))
            resp = Request.blank('/origin/.prep',
                environ={'REQUEST_METHOD': 'POST'},
                headers={'X-Origin-Admin-User': '.origin_admin',
                         'X-Origin-Admin-Key': 'unittest'}).get_response(
                         self.test_origin)
            self.assertEquals(resp.status_int, 400)
            resp = Request.blank('http://origin_db.com:8080/v1/acc/cont',
                environ={'REQUEST_METHOD': 'HEAD'}).get_response(
                self.test_origin)
            self.assertEquals(resp.status_int, 400)
            resp = Request.blank('http://origin_db.com:8080/v1/acc/cont/',
                environ={'REQUEST_METHOD': 'PUT'}).get_response(
                self.test_origin)
            self.assertEquals(resp.status_int, 400)
        finally:
            origin.split_path = was_split

    def test_origin_db_get_xml(self):
        listing_data = json.dumps([
            {'name': 'test1', 'content_type': 'x-cdn/true-1234-false'},
            {'name': 'test2', 'content_type': 'x-cdn/true-2234-false'}])
        self.test_origin.app = FakeApp(iter([('200 Ok', {}, listing_data)]))
        req = Request.blank(
            'http://origin_db.com:8080/v1/acc/cont?format=xml',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        self.assert_('<ttl>1234</ttl>' in resp.body)
        self.assertEquals(resp.status_int, 200)

    def test_origin_db_get_enabled(self):
        listing_data = json.dumps([
            {'name': 'test1', 'content_type': 'x-cdn/false-1234-false'},
            {'name': 'test2', 'content_type': 'x-cdn/false-2234-false'}])
        listing_data_enabled = json.dumps([
            {'name': 'test3', 'content_type': 'x-cdn/true-1234-false'},
            {'name': 'test4', 'content_type': 'x-cdn/true-2234-false'}])
        self.test_origin.app = FakeApp(iter([('200 Ok', {}, listing_data),
            ('200 Ok', {}, listing_data_enabled)]))
        req = Request.blank(
            'http://origin_db.com:8080/v1/acc/cont?enabled=true',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        self.assert_('test1' not in resp.body)
        self.assert_('test3' in resp.body)
        self.assertEquals(resp.status_int, 200)

    def test_origin_db_get_marker(self):
        listing_data = json.dumps([
            {'name': 'test1', 'content_type': 'x-cdn/false-1234-false'},
            {'name': 'test2', 'content_type': 'x-cdn/false-2234-false'}])
        listing_data_enabled = json.dumps([
            {'name': 'test3', 'content_type': 'x-cdn/true-1234-false'},
            {'name': 'test4', 'content_type': 'x-cdn/true-2234-false'}])
        self.test_origin.app = FakeApp(iter([('200 Ok', {}, listing_data),
            ('200 Ok', {}, listing_data_enabled)]))
        unitest = urllib.quote(u'a \u2661'.encode('utf8'))
        req = Request.blank(
            'http://origin_db.com:8080/v1/acc/cont?marker=%s' % unitest,
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 200)

    def test_origin_db_head(self):
        prev_data = json.dumps({'account': 'acc', 'container': 'cont',
                'ttl': 1234, 'logs_enabled': True, 'cdn_enabled': False})
        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, prev_data)])) # call to _get_cdn_data
        req = Request.blank('http://origin_db.com:8080/v1/acc/cont',
            environ={'REQUEST_METHOD': 'HEAD'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 204)
        self.assertEquals(resp.headers['x-ttl'], '1234')

    def test_cdn_bad_req(self):
        for meth in ['PUT', 'POST', 'DELETE', 'JUNK']:
            self.test_origin.app = FakeApp(iter([]))
            resp = Request.blank('http://origin_cdn.com:8080/v1/acc/cont',
                environ={'REQUEST_METHOD': meth}).get_response(
                self.test_origin)
            self.assertEquals(resp.status_int, 405)

        prev_data = json.dumps({'account': 'acc', 'container': 'cont',
                'ttl': 1234, 'logs_enabled': True, 'cdn_enabled': True})
        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, prev_data), # call to _get_cdn_data
            ('301 Moved Permanently',
             {'Location': '/v1/acc/cont/subdir/'}, '')])) #get obj
        resp = Request.blank('http://1234.r34.origin_cdn.com:8080/subdir',
            environ={'REQUEST_METHOD': 'HEAD',
                     'swift.cdn_hash': 'abcd'}).get_response(self.test_origin)
        self.assertEquals(resp.status_int, 301)
        self.assertEquals(resp.headers['Location'], '/subdir/')

    def test_cdn_get_no_content(self):
        prev_data = json.dumps({'account': 'acc', 'container': 'cont',
                'ttl': 1234, 'logs_enabled': True, 'cdn_enabled': True})
        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, prev_data), # call to _get_cdn_data
            ('304 No Content', {}, '')])) #call to get obj
        req = Request.blank('http://1234.r34.origin_cdn.com:8080/obj1.jpg',
            environ={'REQUEST_METHOD': 'HEAD',
                     'swift.cdn_hash': 'abcd',
                     'swift.cdn_object_name': 'obj1.jpg'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 304)

        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, prev_data), # call to _get_cdn_data
            ('404 No Content', {}, '')])) #call to get obj
        req = Request.blank('http://1234.r34.origin_cdn.com:8080/obj1.jpg',
            environ={'REQUEST_METHOD': 'HEAD',
                     'swift.cdn_hash': 'abcd',
                     'swift.cdn_object_name': 'obj1.jpg'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 404)

        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, prev_data), # call to _get_cdn_data
            ('416 No Content', {}, '')])) #call to get obj
        req = Request.blank('http://1234.r34.origin_cdn.com:8080/obj1.jpg',
            environ={'REQUEST_METHOD': 'HEAD',
                     'swift.cdn_hash': 'abcd',
                     'swift.cdn_object_name': 'obj1.jpg'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 416)

    def test_cdn_get_regex(self):
        prev_data = json.dumps({'account': 'acc', 'container': 'cont',
                'ttl': 1234, 'logs_enabled': True, 'cdn_enabled': True})

        def check_urls(req):
            vrs, acc, cont, obj = utils.split_path(req.path, 1, 4)
            self.assertEquals(acc, 'acc')
            self.assertEquals(cont, 'cont')
            self.assertEquals(obj, 'obj1.jpg')

        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, prev_data), # call to _get_cdn_data
            ('304 No Content', {}, '', check_urls)])) #call to get obj
        req = Request.blank('http://1234.r3.origin_cdn.com:8080/obj1.jpg',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 304)

        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, prev_data), # call to _get_cdn_data
            ('304 No Content', {}, '', check_urls)])) #call to get obj
        req = Request.blank('http://r3.origin_cdn.com:8080/nohash/obj1.jpg',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 404)

    def test_cdn_get(self):
        prev_data = json.dumps({'account': 'acc', 'container': 'cont',
                'ttl': 1234, 'logs_enabled': True, 'cdn_enabled': True})
        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, prev_data), # call to _get_cdn_data
            ('200 Ok', {'x-object-meta-test': 'hey',
                        'Content-Length': str(len('Test obj body.'))},
             'Test obj body.',
             lambda req: False if req.headers['if-modified-since'] ==
                '2000-01-01' else 'Headers not kept')])) #call to get obj
        req = Request.blank('http://1234.r3.origin_cdn.com:8080/obj1.jpg',
            headers={'if-modified-since': '2000-01-01'},
            environ={'REQUEST_METHOD': 'GET',
                     'swift.cdn_hash': 'abcd',
                     'swift.cdn_object_name': 'obj1.jpg'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.headers.get('x-object-meta-test'), 'hey')
        self.assertEquals(resp.headers.get('Content-Length'), '14')
        self.assertEquals(resp.status_int, 200)
        self.assertEquals(resp.body, 'Test obj body.')

    def test_cdn_get_bad_auth(self):
        prev_data = json.dumps({'account': 'acc', 'container': 'cont',
                'ttl': 1234, 'logs_enabled': True, 'cdn_enabled': True})
        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, prev_data), # call to _get_cdn_data
            ('200 Ok', {'x-object-meta-test': 'hey',
                        'Content-Length': len('Test obj body.')},
             'Test obj body.',
             lambda req: False if req.headers['if-modified-since'] ==
                '2000-01-01' else 'Headers not kept')])) #call to get obj
        req = Request.blank('http://1234.r3.origin_cdn.com:8080/obj1.jpg',
            headers={'if-modified-since': '2000-01-01'},
            environ={'REQUEST_METHOD': 'GET',
                     'swift.cdn_hash': 'abcd',
                     'swift.cdn_object_name': 'obj1.jpg',
                     'swift.cdn_authorize': lambda a,b: (HTTPUnauthorized, 10)})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 401)

    def test_cdn_get_fail(self):
        prev_data = json.dumps({'account': 'acc', 'container': 'cont',
                'ttl': 1234, 'logs_enabled': True, 'cdn_enabled': True})
        self.test_origin.app = FakeApp(iter([
            ('204 No Content', {}, prev_data), # call to _get_cdn_data
            (500, {}, 'Failure.')])) #call to get obj
        req = Request.blank('http://1234.r3.origin_cdn.com:8080/obj1.jpg',
            environ={'REQUEST_METHOD': 'GET',
                     'swift.cdn_hash': 'abcd',
                     'swift.cdn_object_name': 'obj1.jpg'})
        resp = req.get_response(self.test_origin)
        self.assertEquals(resp.status_int, 404)

        fake_conf = FakeConf(data='''[sos]
origin_admin_key = unittest
origin_cdn_host_suffixes = origin_cdn.com
origin_db_hosts = origin_db.com
origin_account = .origin
max_cdn_file_size = 0
hash_path_suffix = testing
[incoming_url_regex]
regex_0 = ^http://origin_cdn\.com.*\/h(?P<cdn_hash>\w+)\/r\d+\/?(?P<object_name>(.+))?$
'''.split('\n'))
        test_origin = origin.filter_factory(
            {'sos_conf': fake_conf})
        test_origin = test_origin(FakeApp(iter([
                ('204 No Content', {}, prev_data), # call to _get_cdn_data
                ('200 Ok', {'Content-Length': 14}, 'Test obj body.')])))
        req = Request.blank('http://1234.r3.origin_cdn.com:8080/obj1.jpg',
            environ={'REQUEST_METHOD': 'GET',
                     'swift.cdn_hash': 'abcd',
                     'swift.cdn_object_name': 'obj1.jpg'})
        resp = req.get_response(test_origin)
        self.assertEquals(resp.status_int, 400)

        fake_conf = FakeConf(data='''[sos]
origin_admin_key = unittest
origin_cdn_host_suffixes = origin_cdn.com
origin_db_hosts = origin_db.com
origin_account = .origin
max_cdn_file_size = 0
hash_path_suffix = testing
'''.split('\n'))
        test_origin = origin.filter_factory(
            {'sos_conf': fake_conf})
        test_origin = test_origin(FakeApp(iter([ ])))
        req = Request.blank('http://1234.r3.origin_cdn.com:8080/obj1.jpg',
            environ={'REQUEST_METHOD': 'GET'})
        resp = req.get_response(test_origin)
        self.assertEquals(resp.status_int, 500)
        

if __name__ == '__main__':
    unittest.main()
