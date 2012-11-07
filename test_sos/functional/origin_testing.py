#!/usr/bin/python
try:
    import simplejson as json
except ImportError:
    import json
import unittest
from nose import SkipTest
from uuid import uuid4
from urllib import quote
import datetime
from webob import Response
from swift.common.utils import urlparse, TRUE_VALUES
from xml.dom.minidom import parseString
from xml.sax import saxutils

from sos_testing import check_response, retry, skip, swift_test_user, \
    swift_test_auth, sos_conf, conf


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
        self.db_host = sos_conf['sos'].get(
            'origin_db_hosts').split(',')[0].strip()
        self.origin_host = sos_conf['sos'].get(
                           'origin_cdn_host_suffixes').split(',')[0].strip()
        self.assert_(self.db_host)
        self.cdn_url_dict = sos_conf['outgoing_url_format']
        self.use_ssl = swift_test_auth.startswith('https')
        self.conts_to_delete = []
        self.swift_objs_to_delete = []
        self.run_static_web_test_because_of_webob_hack = \
            conf.get('sos_static_web') in TRUE_VALUES

    def tearDown(self):
        if skip:
            raise SkipTest

        def delete_sos(url, token, parsed, conn, cont):
            conn.request('DELETE',
                         quote('/'.join([parsed.path, cont])), '',
                         headers=self._db_headers({'X-Auth-Token': token}))
            return check_response(conn)

        def delete_swift(url, token, parsed, conn, cont):
            conn.request('DELETE',
                quote('/'.join([parsed.path, cont])), '',
                headers={'X-Auth-Token': token})
            return check_response(conn)

        def delete_swift_obj(url, token, parsed, conn, cont, obj):
            conn.request('DELETE',
                quote('/'.join([parsed.path, cont, obj])), '',
                headers={'X-Auth-Token': token})
            return check_response(conn)

        for cont, obj in self.swift_objs_to_delete:
            resp = retry(delete_swift_obj, cont, obj)
            resp.read()
            self.assertEquals(resp.status, 204)
        if self.swift_objs_to_delete:
            for cont in self.conts_to_delete:
                resp = retry(delete_swift, cont)
                resp.read()
                self.assertEquals(resp.status, 204)
        for cont in self.conts_to_delete:
            resp = retry(delete_sos, cont)
            resp.read()
            self.assertEquals(resp.status, 204)

    def _get_header(self, check_key, headers):
        passed = False
        for key, val in headers:
            if key.lower() == check_key.lower():
                return val
        return None

    def test_cdn_enable_container(self):

        def put_sos(url, token, parsed, conn, cont):
            conn.request('PUT',
                parsed.path + '/%s' % cont, '',
                self._db_headers({'X-Auth-Token': token, 'X-TTL': 123456}))
            return check_response(conn)

        def head_sos(url, token, parsed, conn, cont):
            conn.request('HEAD',
                parsed.path + '/%s' % cont, '',
                self._db_headers({'X-Auth-Token': token}))
            return check_response(conn)

        cont = uuid4().hex
        self.conts_to_delete.append(cont)
        resp = retry(put_sos, cont)
        resp.read()
        self.assertEquals(resp.status, 201)
        resp = retry(head_sos, cont)
        resp.read()
        self.assertEquals(resp.status, 204)
        self.assertEquals(self._get_header('x-ttl', resp.getheaders()),
                          '123456')
        self.assertEquals(self._get_header('x-cdn-enabled', resp.getheaders()),
                          'True')

    def test_origin_get(self):

        def put_swift(url, token, parsed, conn, cont, obj):
            conn.request('PUT',
                quote(parsed.path + '/%s' % cont), '',
                {'X-Auth-Token': token})
            resp = check_response(conn)
            resp.read()
            conn.request('PUT',
                quote(parsed.path + '/%s/%s' % (cont, obj)),
                'testbody', {'X-Auth-Token': token, 'Content-Length': 8})
            return check_response(conn)

        def put_sos(url, token, parsed, conn, cont):
            conn.request('PUT',
                quote(parsed.path + '/' + cont), '',
                self._db_headers({'X-Auth-Token': token,
                                  'X-TTL': 60 * 60 * 24}))
            return check_response(conn)

        def head_swift(url, token, parsed, conn, cont, obj):
            conn.request('HEAD',
                quote(parsed.path + '/%s/%s' % (cont, obj)), '',
                {'X-Auth-Token': token})
            return check_response(conn)

        def head_sos(url, token, parsed, conn, cont):
            conn.request('HEAD',
                quote(parsed.path + '/' + cont), '',
                self._db_headers({'X-Auth-Token': token}))
            return check_response(conn)

        def origin_get(url, token, parsed, conn, cdn_url, obj, headers={}):
            cdn_parsed = urlparse(cdn_url)
            conn.request('GET',
                quote(cdn_parsed.path + '/' + obj), '',
                self._origin_headers(headers, cdn_url))
            return check_response(conn)

        cont_objs = [(uuid4().hex, uuid4().hex),
                     (u'test cont \u2661', u'test obj \u2661')]
        for cont, obj in cont_objs:
            if isinstance(cont, unicode):
                cont = cont.encode('utf-8')
            if isinstance(obj, unicode):
                obj = obj.encode('utf-8')
            self.conts_to_delete.append(cont)
            self.swift_objs_to_delete.append((cont, obj))
            resp = retry(put_sos, cont)
            resp.read()
            resp = retry(put_swift, cont, obj)
            resp.read()
            head_resp = retry(head_sos, cont)
            head_resp.read()
            self.assertEquals(head_resp.status, 204)
            sw_head_resp = retry(head_swift, cont, obj)
            sw_head_resp.read()
            self.assertEquals(sw_head_resp.status // 100, 2)
            for key in self.cdn_url_dict:
                if 'ssl' in key.lower() != self.use_ssl:
                    continue
                cdn_url = self._get_header(key, head_resp.getheaders())
                resp = retry(origin_get, cdn_url=cdn_url, obj=obj)
                body = resp.read()
                self.assertEquals(resp.status // 100, 2)
                self.assertEquals('testbody', body)
                date_str_added = self._get_header('date', resp.getheaders())
                date_added = datetime.datetime.strptime(date_str_added,
                    "%a, %d %b %Y %H:%M:%S GMT")
                exp_expires = date_added + datetime.timedelta(1)
                self.assertEquals(
                    self._get_header('Expires', resp.getheaders()),
                    datetime.datetime.strftime(exp_expires,
                                               "%a, %d %b %Y %H:%M:%S GMT"))
                resp = retry(origin_get, cdn_url=cdn_url, obj=obj,
                             headers={'Range': 'bytes=2-4'})
                body = resp.read()
                self.assertEquals(resp.status // 100, 2)
                self.assertEquals('stb', body)

    def test_db_listing(self):

        unitest = u'test \u2661'
        xml_test = 'xte<st \u2661'

        def put_sos(url, token, parsed, conn, cont, headers={}):
            headers.update({'X-Auth-Token': token, 'X-TTL': 60 * 60 * 24})
            conn.request('PUT', parsed.path + '/' + cont, '',
                self._db_headers(headers))
            return check_response(conn)

        def get_sos(url, token, parsed, conn, output_format, cdn_enabled=''):
            conn.request('GET', parsed.path + '?format=%s&enabled=%s' %
                (output_format, cdn_enabled), '',
                self._db_headers({'X-Auth-Token': token}))
            return check_response(conn)

        def get_sos_marker(url, token, parsed, conn, output_format,
                           cdn_enabled=''):
            conn.request('GET',
                parsed.path + '?marker=%s' % quote(unitest.encode('utf8')), '',
                self._db_headers({'X-Auth-Token': token}))
            return check_response(conn)

        def head_sos(url, token, parsed, conn, cont):
            conn.request('HEAD',
                parsed.path + '/' + cont, '',
                self._db_headers({'X-Auth-Token': token}))
            return check_response(conn)

        conts = [uuid4().hex for i in xrange(5)]
        conts.extend(['x' + uuid4().hex for i in xrange(5)])

        conts.append(unitest)
        conts.append(xml_test)
        for cont in conts:
            if isinstance(cont, unicode):
                cont = cont.encode('utf-8')
            self.conts_to_delete.append(cont)
            cont = quote(cont)
            if cont.startswith('x'):
                resp = retry(put_sos, cont, {'x-cdn-enabled': 'false'})
            else:
                resp = retry(put_sos, cont)
            resp.read()
            self.assertEquals(resp.status, 201)

        head_resp = retry(head_sos, quote(unitest.encode('utf8')))
        head_resp.read()
        unitest_cdn_url = head_resp.getheader('x-cdn-uri')

        resp = retry(get_sos, '')
        body = resp.read()
        for cont in conts:
            self.assert_(cont.encode('utf8') in body)
        resp = retry(get_sos, '', 'true')
        body = resp.read()
        for cont in conts[:-2]:
            self.assertEquals(not cont.startswith('x'), cont in body)
        resp = retry(get_sos, '', 'false')
        body = resp.read()
        for cont in conts:
            self.assertEquals(cont.startswith('x'), cont in body)

        resp = retry(get_sos, 'json')
        body = resp.read()
        data = json.loads(body)
        resp_conts = [d['name'] for d in data]
        self.assertEquals(set(resp_conts), set(conts))
        found_it = False
        for data_dict in data:
            if data_dict['name'] == unitest:
                self.assertEquals(data_dict['x-cdn-uri'], unitest_cdn_url)
                found_it = True
        self.assert_(found_it)

        resp = retry(get_sos, 'xml')
        body = resp.read()
        parseString(body)
        for cont in conts:
            self.assert_('<name>%s</name>' %
                         saxutils.escape(cont.encode('utf8')) in body)

        resp = retry(get_sos_marker, '')
        resp.read()
        self.assertEquals(resp.status, 200)

    def test_origin_301(self):

        if not self.run_static_web_test_because_of_webob_hack:
            raise SkipTest

        def put_swift(url, token, parsed, conn, cont):
            conn.request('PUT',
                quote(parsed.path + '/%s' % cont), '',
                {'X-Auth-Token': token,
                 'x-container-read': '.r:*',
                 'x-container-meta-web-index': 'index.html'})
            resp = check_response(conn)
            resp.read()
            conn.request('PUT',
                quote(parsed.path + '/%s/hat/index.html' % (cont)),
                'testbody', {'X-Auth-Token': token, 'Content-Length': 8})
            resp = check_response(conn)
            resp.read()

        def put_sos(url, token, parsed, conn, cont):
            conn.request('PUT',
                quote(parsed.path + '/' + cont), '',
                self._db_headers({'X-Auth-Token': token,
                                  'X-TTL': 60 * 60 * 24}))
            resp = check_response(conn)
            resp.read()

        def head_sos(url, token, parsed, conn, cont):
            conn.request('HEAD',
                quote(parsed.path + '/' + cont), '',
                self._db_headers({'X-Auth-Token': token}))
            return check_response(conn)

        def origin_get(url, token, parsed, conn, cdn_url, obj, headers={}):
            cdn_parsed = urlparse(cdn_url)
            conn.request('GET',
                quote(cdn_parsed.path + '/' + obj), '',
                self._origin_headers(headers, cdn_url))
            return check_response(conn)

        cont = uuid4().hex
        self.conts_to_delete.append(cont)
        self.swift_objs_to_delete.append((cont, 'hat/index.html'))
        retry(put_sos, cont)
        retry(put_swift, cont)
        head_resp = retry(head_sos, cont)
        head_resp.read()
        self.assertEquals(head_resp.status, 204)
        for key in self.cdn_url_dict:
            if 'ssl' in key.lower() != self.use_ssl:
                continue
            cdn_url = self._get_header(key, head_resp.getheaders())
            resp = retry(origin_get, cdn_url=cdn_url, obj='hat/')
            body = resp.read()
            self.assertEquals(resp.status // 100, 2)
            self.assertEquals('testbody', body)

            resp = retry(origin_get, cdn_url=cdn_url, obj='hat')
            body = resp.read()
            self.assertEquals(resp.status, 301)
            self.assertEquals(self._get_header('Location', resp.getheaders()),
                              '/hat/')

if __name__ == '__main__':
    unittest.main()
