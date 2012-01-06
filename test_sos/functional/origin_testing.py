#!/usr/bin/python

import json
import unittest
from nose import SkipTest
from uuid import uuid4
from webob import Response
from swift.common.utils import urlparse

from sos_testing import check_response, retry, skip, swift_test_user, \
    swift_test_auth, sos_conf

class TestOrigin(unittest.TestCase):

    def _db_headers(self, cur_headers):
        cur_headers['Host'] = self.db_host
        return cur_headers

    def _origin_headers(self, cur_headers, url):
        parsed = urlparse(url)
        cur_headers['Host'] = parsed.hostname
        return cur_headers

    def setUp(self):
        if skip:
            raise SkipTest
        self.cont_name = 'cont' # uuid4().hex
        self.obj_name = 'obj' #uuid4().hex
        self.db_host = sos_conf['sos'].get('origin_db_hosts')
        self.origin_host = sos_conf['sos'].get(
                           'origin_cdn_host_suffixes').split(',')[0]
        self.assert_(self.db_host)
        self.cdn_url_dict = sos_conf['outgoing_url_format']
        self.use_ssl = swift_test_auth.startswith('https')

    def tearDown(self):
        if skip:
            raise SkipTest

        def get_sos(url, token, parsed, conn):
            conn.request('GET', parsed.path + '?format=json',
                         '', headers=self._db_headers({'X-Auth-Token': token}))
            return check_response(conn)
        def delete_sos(url, token, parsed, conn, obj):
            conn.request('DELETE',
                         '/'.join([parsed.path, self.cont_name]), '',
                         headers=self._db_headers({'X-Auth-Token': token}))
            return check_response(conn)

        while 'Delete SOS stuff':
            resp = retry(get_sos)
            body = resp.read()
            self.assert_(resp.status // 100 == 2, resp.status)
            objs = json.loads(body)
            objs = [obj['name'] for obj in objs]
            if not objs:
                break
            for obj in objs:
                resp = retry(delete_sos, obj)
                resp.read()
                self.assertEquals(resp.status, 204)
            break

    def _get_header(self, check_key, headers):
        passed = False
        for key, val in headers:
            if key.lower() == check_key.lower():
                return val
        return None

    def test_cdn_enable_container(self):
        return
        def put_sos(url, token, parsed, conn):
            conn.request('PUT',
                parsed.path + '/%s' % self.cont_name, '',
                self._db_headers({'X-Auth-Token': token, 'X-TTL': 123456}))
            return check_response(conn)
        def head_sos(url, token, parsed, conn):
            conn.request('HEAD',
                parsed.path + '/%s' % self.cont_name, '',
                self._db_headers({'X-Auth-Token': token}))
            return check_response(conn)
        resp = retry(put_sos)
        resp.read()
        self.assertEquals(resp.status, 201)
        resp = retry(head_sos)
        resp.read()
        self.assertEquals(resp.status, 204)
        self.assertEquals(self._get_header('x-ttl', resp.getheaders()),
                          '123456')
        self.assertEquals(self._get_header('x-cdn-enabled', resp.getheaders()),
                          'True')

    def test_origin_get(self):
        def put_swift(url, token, parsed, conn):
            conn.request('PUT',
                parsed.path + '/%s' % self.cont_name, '',
                {'X-Auth-Token': token})
            resp = check_response(conn)
            resp.read()
            conn.request('PUT',
                parsed.path + '/%s/%s' % (self.cont_name, self.obj_name),
                'testbody', {'X-Auth-Token': token, 'Content-Length': 8})
            return check_response(conn)
        def put_sos(url, token, parsed, conn):
            conn.request('PUT',
                parsed.path + '/' + self.cont_name, '',
                self._db_headers({'X-Auth-Token': token, 'X-TTL': 123456}))
            return check_response(conn)
        def head_swift(url, token, parsed, conn):
            conn.request('HEAD',
                parsed.path + '/%s/%s' % (self.cont_name, self.obj_name), '',
                {'X-Auth-Token': token})
            return check_response(conn)
        def head_sos(url, token, parsed, conn):
            conn.request('HEAD',
                parsed.path + '/' + self.cont_name, '',
                self._db_headers({'X-Auth-Token': token}))
            return check_response(conn)
        def origin_get(url, token, parsed, conn, cdn_url):
            cdn_parsed = urlparse(cdn_url)
            conn.request('GET',
                cdn_parsed.path + '/' + self.obj_name, '',
                self._origin_headers({}, cdn_url))
            return check_response(conn)
        resp = retry(put_sos)
        resp.read()
        resp = retry(put_swift)
        resp.read()
        head_resp = retry(head_sos)
        head_resp.read()
        self.assertEquals(head_resp.status, 204)
        sw_head_resp = retry(head_swift)
        sw_head_resp.read()
        self.assertEquals(sw_head_resp.status // 100, 2)
        for key in self.cdn_url_dict:
            if 'ssl' in key.lower() != self.use_ssl:
                continue
            cdn_url = self._get_header(key, head_resp.getheaders())
            resp = retry(origin_get, cdn_url=cdn_url)
            r = resp.read()


if __name__ == '__main__':
    unittest.main()
