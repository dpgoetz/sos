# Copyright (c) 2010 OpenStack, LLC.
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
from time import time, gmtime, strftime
from webob import Response, Request
from webob.exc import HTTPBadRequest, HTTPForbidden, HTTPNotFound, \
    HTTPUnauthorized, HTTPNoContent, HTTPAccepted, HTTPCreated, \
    HTTPMethodNotAllowed, HTTPRequestRangeNotSatisfiable, \
    HTTPInternalServerError, HTTPPreconditionFailed
from hashlib import md5
import re
from swift.common import utils
from swift.common.utils import get_logger, get_param, TRUE_VALUES, readconf
from swift.common.constraints import check_utf8
from swift.common.wsgi import make_pre_authed_request
try:
    import simplejson as json
except ImportError:
    import json

CACHE_BAD_URL = 86400
CACHE_404 = 30
SWIFT_FETCH_SIZE = 100 * 1024
MEMCACHE_TIMEOUT = 3600

class InvalidContentType(Exception):
    pass


class OriginDbFailure(Exception):
    pass

class InvalidConfiguration(Exception):
    pass

class HashData(object):
    '''
    object to keep track on json data files
    '''

    def __init__(self, account, container, ttl, cdn_enabled, logs_enabled):
        self.account = account
        self.container = container
        self.ttl = ttl
        self.logs_enabled = logs_enabled
        self.cdn_enabled = cdn_enabled

    def get_json_str(self):
        data = {'account': self.account, 'container': self.container,
                'ttl': self.ttl, 'logs_enabled': self.logs_enabled,
                'cdn_enabled': self.cdn_enabled}
        return json.dumps(data)

    @classmethod
    def create_from_json(cls, json_str):
        '''
        :returns HashData object init from str passed in
        :raises ValueError if there's a problem with json
        '''
        try:
            data = json.loads(json_str)
            return HashData(data['account'], data['container'], data['ttl'],
                            data['cdn_enabled'], data['logs_enabled'])
        except (KeyError, ValueError), e:
            raise ValueError("Problem loading json: %s" % e)


class OriginBase(object):
    '''
    Base class for Origin Server
    '''

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.hash_suffix = conf.get('hash_path_suffix')
        self.origin_account = conf.get('origin_account', '.origin')
        if not self.hash_suffix:
            raise InvalidConfiguration('Please provide a hash_path_suffix')

#    def _valid_setup(self):
#        #TODO: this later

    def _hash_path(self, account, container):
        return md5('/%s/%s/%s' % (account, container.encode('utf-8'),
                                  self.hash_suffix)).hexdigest()

    def _get_hsh_obj_path(self, hsh):
        hsh_num = int(hsh[-1], 16)
        return '/v1/%s/.hash_%d/%s' % (self.origin_account, hsh_num, hsh)

    def _get_cdn_data(self, env, cdn_obj_path):
        '''
        Returns HashData object by doing a GET to the obj in the .hash
        container.
        '''
        # get defaults
        #TODO: I think I should cache this in memcache later
        # if i do this then i'll have to clear it on PUTs / POSTs
        memcache_client = utils.cache_from_env(env)
        memcache_key = '%s/%s' % (self.origin_account, cdn_obj_path)
        if memcache_client:
            cached_cdn_data = memcache_client.get(memcache_key)
            if cached_cdn_data:
                try:
                    return HashData.create_from_json(cached_cdn_data)
                except ValueError:
                    pass

        resp = make_pre_authed_request(env, 'GET',
            cdn_obj_path, agent='SwiftOrigin').get_response(self.app)
        if resp.status_int // 100 == 2:
            try:
                if memcache_client:
                    memcache_client.set(memcache_key, resp.body,
                        serialize=False, timeout=MEMCACHE_TIMEOUT)

                return HashData.create_from_json(resp.body)
            except ValueError:
                pass # TODO: ignore json errors in the data files, ok right?
        return None


class AdminHandler(OriginBase):

    def __init__(self, app, conf):
        OriginBase.__init__(self, app, conf)
        self.admin_key = conf.get('origin_admin_key')

    def is_origin_admin(self, req):
        """
        Returns True if the admin specified in the request represents the
        .origin_admin.

        :param req: The webob.Request to check.
        :param returns: True if .origin_admin.
        """
        return self.admin_key and \
           req.headers.get('x-origin-admin-user') == '.origin_admin' and \
           req.headers.get('x-origin-admin-key') == self.admin_key

    def handle_request(self, env, req):
        """
        Handles the POST /origin/.prep call for preparing the backing store
        Swift cluster for use with the origin subsystem. Can only be called by
        .origin_admin

        :param req: The webob.Request to process.
        :returns: webob.Response, 204 on success
        """
        if not self.is_origin_admin(req):
            return HTTPForbidden(request=req)
        try:
            vsn, account, container = utils.split_path(req.path, 1, 3, True)
        except ValueError:
            return HTTPNotFound(request=req)
        if account == '.prep':
            path = '/v1/%s' % self.origin_account
            resp = make_pre_authed_request(req.environ, 'PUT',
                path, agent='SwiftOrigin').get_response(self.app)
            if resp.status_int // 100 != 2:
                raise Exception(
                    'Could not create the main origin account: %s %s' %
                    (path, resp.status))
            hash_conts = ['.hash_%d' % i for i in xrange(16)]
            for cont_name in hash_conts:
                path = '/v1/%s/%s' % (self.origin_account, cont_name)
                resp = make_pre_authed_request(req.environ, 'PUT',
                    path, agent='SwiftOrigin').get_response(self.app)
                if resp.status_int // 100 != 2:
                    raise Exception('Could not create %s container: %s %s' %
                                    (cont_name, path, resp.status))
            return HTTPNoContent(request=req)
        return HTTPNotFound(request=req)


class CdnHandler(OriginBase):

    def __init__(self, app, conf):
        OriginBase.__init__(self, app, conf)
        self.logger = get_logger(conf, log_route='origin_cdn')
        self.max_cdn_file_size = int(conf.get('max_cdn_file_size',
                                              10 * 1024 ** 3))
        if not self._valid_setup(conf):
            raise InvalidConfiguration('Invalid config for CdnHandler')
        self.cdn_regexes = []
        for key, val in conf['incoming_url_regex'].items():
            regex = re.compile(val)
            self.cdn_regexes.append(regex)

    def _valid_setup(self, conf):
        return bool(conf.get('incoming_url_regex'))

    def _getCacheHeaders(self, ttl):
        return {'Expires': strftime("%a, %d %b %Y %H:%M:%S GMT",
                                    gmtime(time() + ttl)),
                'Cache-Control': 'max-age:%d, public' % ttl}

    def _getCdnHeaders(self, req):
        headers = {}
        for header in ['If-Modified-Since', 'If-Match', 'Range', 'If-Range']:
            if header in req.headers:
                headers[header] = req.headers[header]
        return headers

    def handle_request(self, env, req):
        if req.method not in ('GET', 'HEAD'):
            headers = self._getCacheHeaders(CACHE_BAD_URL)
            return HTTPMethodNotAllowed(request=req, headers=headers)
        # allow earlier middleware to override hash and obj_name
        hsh = env.get('swift.cdn_hash')
        object_name = env.get('swift.cdn_object_name')
        if not (hsh and object_name):
            for regex in self.cdn_regexes:
                match_obj = regex.match(req.url)
                if match_obj:
                    match_dict = match_obj.groupdict()
                    hsh = match_dict.get('cdn_hash')
                    object_name = match_dict.get('object_name')
                    break

        if not (hsh and object_name):
            headers = self._getCacheHeaders(CACHE_BAD_URL)
            return HTTPNotFound(request=req, headers=headers)
        cdn_obj_path = self._get_hsh_obj_path(hsh)
        hash_data = self._get_cdn_data(env, cdn_obj_path)
        if hash_data and hash_data.cdn_enabled:
            # this is a cdn enabled container, proxy req to swift
            swift_path = '/v1/%s/%s/%s' % (hash_data.account,
                                           hash_data.container, object_name)
            headers = self._getCdnHeaders(req)
            resp = make_pre_authed_request(env, req.method, swift_path,
                headers=headers, agent='SwiftOrigin').get_response(self.app)
            if resp.status_int == 304:
                return resp
            # we don't have to worry about the 401 case
            if resp.status_int == 404:
                return HTTPNotFound(request=req,
                    headers=self._getCacheHeaders(CACHE_404))
            if resp.status_int == 416:
                return HTTPRequestRangeNotSatisfiable(request=req,
                    headers=self._getCacheHeaders(CACHE_404))
            if resp.status_int in (200, 206):
                #TODO: not doing the check for content-length == None ok?
                if resp.content_length > self.max_cdn_file_size:
                    return HTTPBadRequest(request=req,
                        headers=self._getCacheHeaders(CACHE_404))
                cdn_resp = Response(request=req, app_iter=resp.app_iter)
                cdn_resp.status = resp.status_int
                cdn_resp.last_modified = resp.last_modified
                cdn_resp.etag = resp.etag
                cdn_resp.content_length = resp.content_length
                for header in ('Content-Range', 'Content-Encoding',
                               'Content-Disposition', 'Accept-Ranges',
                               'Content-Type'):
                    header_val = resp.headers.get(header)
                    if header_val:
                        cdn_resp.headers[header] = header_val

                cdn_resp.headers.update(self._getCacheHeaders(hash_data.ttl))

                return cdn_resp
            self.logger.exception('Unexpected response from Swift: %s, %s' %
                                  (resp.status, cdn_obj_path))
        return HTTPNotFound(request=req,
                            headers=self._getCacheHeaders(CACHE_404))


class OriginDbHandler(OriginBase):
    '''
    Origin server for public containers
    '''

    def __init__(self, app, conf):
        OriginBase.__init__(self, app, conf)
        self.conf = conf
        self.logger = get_logger(conf, log_route='origin_db')
        self.min_ttl = int(conf.get('min_ttl', '900'))
        self.max_ttl = int(conf.get('max_ttl', '3155692600'))

    def _gen_listing_content_type(self, cdn_enabled, ttl, logs_enabled):
        return 'x-cdn/%(cdn_enabled)s-%(ttl)d-%(log_ret)s' % {
            'cdn_enabled': cdn_enabled, 'ttl': ttl, 'log_ret': logs_enabled}

    def _parse_container_listing(self, account, listing_data, output_format,
                                 only_cdn_enabled=False):
        '''
        :returns: For xml format: an XML str, json: a dict, otherwise container
                  name. Returns None if only_cdn_enabled is specified and
                  listing_data is false.
        :raises: InvalidContentType
        '''
        listing_dict = listing_data
        container = listing_dict['name']
        cdn_data = listing_dict['content_type']
        hsh = self._hash_path(account, container)
        if output_format not in ('json', 'xml'):
            return container
        if cdn_data.startswith('x-cdn/'):
            try:
                cdn_enabled, ttl, log_ret = cdn_data[len('x-cdn/'):].split('-')
                cdn_enabled = cdn_enabled.lower() in TRUE_VALUES
                log_ret = log_ret.lower() in TRUE_VALUES
                ttl = int(ttl)
            except ValueError:
                raise InvalidContentType('Invalid Content-Type: %s/%s: %s' %
                    (account, container, cdn_data))
            cdn_url_dict = self._get_cdn_urls(hsh, 'GET',
                                              request_format_tag=output_format)
        else:
            raise InvalidContentType('Invalid Content-Type: %s/%s: %s' %
                                     (account, container, cdn_data))
        if only_cdn_enabled and not cdn_enabled:
            return None
        output_dict = {'name': container, 'cdn_enabled': cdn_enabled,
                       'ttl': ttl, 'log_retention': log_ret}
        output_dict.update(cdn_url_dict)
        if output_format == 'xml':
            xml_data = '\n'.join(['<%s>%s</%s>' % (tag, val, tag) 
                                  for tag, val in output_dict.items()])
            return '''  <container>
            %s
  </container>''' % xml_data
        return output_dict

    def origin_db_get(self, env, req):
        '''
        Handles GETs to the Origin database
        The only part of the path this pays attention to is the account.
        '''
        #TODO: this does not return transfer-encoding: chunked
        try:
            account = req.path.split('/')[2]
        except IndexError:
            return HTTPBadRequest('Invalid request. '
                                  'URL format: /<api version>/<account>')
        #TODO: make sure to test with unicode container names
        marker = get_param(req, 'marker', default='')
        list_format = get_param(req, 'format')
        if list_format:
            list_format = list_format.lower()
        enabled_only = get_param(req, 'enabled',
                                 default='false').lower() in TRUE_VALUES
        limit = get_param(req, 'limit')
        if limit:
            try:
                limit = int(limit)
            except ValueError:
                return HTTPBadRequest('Invalid limit, must be an integer')
        listing_path = '/v1/%s/%s?format=json&marker=%s' % \
                       (self.origin_account, account, marker)
        # no limit in request because may have to filter on cdn_enabled
        resp = make_pre_authed_request(env, 'GET',
            listing_path, agent='SwiftOrigin').get_response(self.app)
        resp_headers = {}
        # {'Transfer-Encoding': 'chunked'}
        #TODO is this right? was chunked in old one
        if resp.status_int // 100 == 2:
            cont_listing = json.loads(resp.body)
            # TODO: is it ok to load the whole thing? do i have a choice?
            listing_formatted = []
            for listing_dict in cont_listing:
                if limit is None or len(listing_formatted) < limit:
                    try:
                        formatted_data = self._parse_container_listing(
                            account, listing_dict, list_format,
                            only_cdn_enabled=enabled_only)
                        if formatted_data:
                            listing_formatted.append(formatted_data)
                    except InvalidContentType, e:
                        self.logger.exception(e)
                        continue
                else:
                    break
            if list_format == 'xml':
                resp_headers['Content-Type'] = 'application/xml'
                response_body = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                    '<account name="%s">\n%s\n</account>') % (account,
                        '\n'.join(listing_formatted))

            elif list_format == 'json':
                resp_headers['Content-Type'] = 'application/json'
                response_body = json.dumps(listing_formatted)
            else:
                resp_headers['Content-Type'] = 'text/plain; charset=UTF-8'
                response_body = '\n'.join(listing_formatted)
            return Response(body=response_body, headers=resp_headers)
        else:
            return HTTPNotFound(request=req)

    def _get_cdn_urls(self, hsh, request_type, request_format_tag=''):
        '''
        Returns a dict of the outgoing urls for a HEAD or GET req.
        :param request_format_tag: the tag matching the section in the conf
            file that will be used to format the request
        '''
        format_section = None
        #TODO: add tests for each of these cases
        #TODO: functional tests for all the different requests :(
        section_names = ['outgoing_url_format_%s_%s' % (request_type.lower(),
                                                        request_format_tag),
                         'outgoing_url_format_%s' % request_type.lower(),
                         'outgoing_url_format']
        for section_name in section_names:
            format_section = self.conf.get(section_name)
            if format_section:
                break
        else:
            raise InvalidConfiguration('Could not find format for: %s, %s: %s' %
                (request_type, request_format_tag, self.conf))

        url_vars = {'hash': hsh, 'hash_mod': int(hsh[-2:], 16) % 100}
        cdn_urls = {}
        for key, url in format_section.items():
            cdn_urls[key] = (url % url_vars).rstrip('/')
        return cdn_urls

    def origin_db_head(self, env, req):
        '''
        Handles HEAD requests into Origin database
        '''
        try:
            vsn, account, container = utils.split_path(req.path, 1, 3, True)
        except ValueError:
            return HTTPNotFound()
        hsh = self._hash_path(account, container)
        cdn_obj_path = self._get_hsh_obj_path(hsh)
        hash_data = self._get_cdn_data(env, cdn_obj_path)
        if hash_data:
            headers = self._get_cdn_urls(hsh, 'HEAD')
            headers.update({'X-TTL': hash_data.ttl,
                'X-Log-Retention': hash_data.logs_enabled.title(),
                'X-CDN-Enabled': hash_data.cdn_enabled.title()})
            return HTTPNoContent(headers=headers)
        return HTTPNotFound(request=req)

    def origin_db_puts_posts(self, env, req):
        '''
        Handles PUTs and POSTs into Origin database
        '''
        try:
            vsn, account, container = utils.split_path(req.path, 1, 3, True)
        except ValueError:
            return HTTPNotFound()
        hsh = self._hash_path(account, container)
        cdn_obj_path = self._get_hsh_obj_path(hsh)
        ttl, cdn_enabled, logs_enabled = '295200', 'true', 'false'
        hash_data = self._get_cdn_data(env, cdn_obj_path)
        if hash_data:
            ttl = hash_data.ttl
            cdn_enabled = hash_data.cdn_enabled
            logs_enabled = hash_data.logs_enabled
        else:
            if req.method == 'POST':
                return HTTPNotFound(request=req)
        try:
            ttl = int(req.headers.get('X-TTL', ttl))
        except ValueError:
            return HTTPBadRequest(_('Invalid X-TTL, must be integer'))
        if ttl < self.min_ttl or ttl > self.max_ttl:
            # TODO: this isn't exactly whats currently there. It only errors on
            # invalid TTLs if the enabled is true or being set to true
            return HTTPBadRequest(_('Invalid X-TTL, must be between %(min)s '
                'and %(max)s') % {'min': self.min_ttl, 'max': self.max_ttl})
        logs_enabled = req.headers.get('X-Log-Retention',
            logs_enabled).lower() in TRUE_VALUES and 'true' or 'false'
        cdn_enabled = req.headers.get('X-CDN-Enabled',
            cdn_enabled).lower() in TRUE_VALUES and 'true' or 'false'

        new_hash_data = HashData(account, container, ttl, cdn_enabled,
                                 logs_enabled)
        cdn_obj_data = new_hash_data.get_json_str()
        cdn_obj_etag = md5(cdn_obj_data).hexdigest()
        # this is always a PUT because a POST needs to update the file
        cdn_obj_resp = make_pre_authed_request(env, 'PUT', cdn_obj_path,
            body=cdn_obj_data, headers={'Etag': cdn_obj_etag},
            agent='SwiftOrigin').get_response(self.app)

        if cdn_obj_resp.status_int // 100 != 2:
            raise OriginDbFailure('Could not PUT .hash obj in origin '
                'db: %s %s' % (cdn_obj_path, cdn_obj_resp.status_int))

        #TODO: when DELETE gets added- need to clear out the memcache data
        memcache_client = utils.cache_from_env(env)
        if memcache_client:
            memcache_key = '%s/%s' % (self.origin_account, cdn_obj_path)
            memcache_client.set(memcache_key, cdn_obj_data,
                serialize=False, timeout=MEMCACHE_TIMEOUT)

        listing_cont_path = '/v1/%s/%s' % (self.origin_account, account)
        resp = make_pre_authed_request(env, 'HEAD',
            listing_cont_path, agent='SwiftOrigin').get_response(self.app)
        if resp.status_int == 404:
            # create new container for listings
            resp = make_pre_authed_request(req.environ, 'PUT',
                listing_cont_path, agent='SwiftOrigin').get_response(self.app)
            if resp.status_int // 100 != 2:
                raise OriginDbFailure('Could not create listing container '
                    'in origin db: %s %s' % (listing_cont_path, resp.status))

        cdn_list_path = '/v1/%s/%s/%s' % (self.origin_account,
                                          account, container)

        cdn_list_resp = make_pre_authed_request(env, req.method, cdn_list_path,
            headers={'Content-Type':
                self._gen_listing_content_type(cdn_enabled, ttl, logs_enabled),
                'Content-Length': 0},
                 agent='SwiftOrigin').get_response(self.app)

        if cdn_list_resp.status_int // 100 != 2:
            raise OriginDbFailure('Could not PUT/POST to cdn listing in '
                'origin db: %s %s' % (cdn_obj_path, cdn_obj_resp.status_int))
        cdn_success = True
        # PUTs and POSTs have the headers as HEAD
        cdn_url_headers = self._get_cdn_urls(hsh, 'HEAD')
        if req.method == 'POST':
            return HTTPAccepted(request=req,
                                headers=cdn_url_headers)
        else:
            return HTTPCreated(request=req,
                               headers=cdn_url_headers)

    def handle_request(self, env, req):
        '''
        This handles requests from a user to activate cdn access for their
        containers, list them, etc.
        '''
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp
        if req.method in ('PUT', 'POST'):
            try:
                return self.origin_db_puts_posts(env, req)
            except OriginDbFailure, e:
                self.logger.exception(e)
                #TODO: get better error message
                return HTTPInternalServerError('Problem saving CDN data')
        if req.method == 'GET':
            return self.origin_db_get(env, req)
        if req.method == 'HEAD':
            return self.origin_db_head(env, req)
        if req.method == 'DELETE':
            return HTTPMethodNotAllowed()
        return HTTPNotFound()


class OriginServer(object):

    def __init__(self, app, conf):
        self.app = app
        #self.conf = conf
        origin_conf = conf['sos_conf']
        conf = readconf(origin_conf, raw=True)
        self.conf = conf['sos']
        for format_section in ['outgoing_url_format',
                'outgoing_url_format_head','outgoing_url_format_get',
                'outgoing_url_format_get_xml', 'outgoing_url_format_get_json',
                'incoming_url_regex']:
            if conf.get(format_section, None):
                self.conf[format_section] = conf[format_section]
        self.origin_prefix = self.conf.get('origin_prefix', '/origin/')
        self.origin_db_hosts = [host for host in
            self.conf.get('origin_db_hosts', '').split(',') if host]
        self.origin_cdn_hosts = [host for host in
            self.conf.get('origin_cdn_hosts', '').split(',') if host]

#    def _valid_setup(self):
#        return True
#        if not valid_setup:
#            try:
#                self.logger.critical(_('Invalid origin conf file!'))
#            except Exception:
#                pass
#        return valid_setup

    def __call__(self, env, start_response):
        '''
        Accepts a standard WSGI application call.
        There are 2 types of requests that this middleware will affect.
        1. Requests to CDN 'database' that will enable, list, etc. containers
           for the CDN.
        2. Requests (GETs, HEADs) from CDN provider to publicly available
           containers.
        The types of requests can be determined by looking at the hostname of
        the incoming call.
        Wraps env in webob.Request object and passes it down.

        :param env: WSGI environment dictionary
        :param start_response: WSGI callable
        '''
        #TODO: need to look at how the logs_enabled thing works :(
#        if not self._valid_setup():
#            return self.app(env, start_response)
        host = env['HTTP_HOST'].split(':')[0]
        #TODO: is there something that I ned to do about the environ when
        #I re route this request?
        try:
            handler = None
            if host in self.origin_db_hosts:
                handler = OriginDbHandler(self.app, self.conf)
            if host in self.origin_cdn_hosts:
                handler = CdnHandler(self.app, self.conf)
            if env['PATH_INFO'].startswith(self.origin_prefix):
                handler = AdminHandler(self.app, self.conf)
            if handler:
                req = Request(env)
                if not check_utf8(req.path_info):
                    #TODO: the current origin server accepts ISO-8859-1 object
                    # names and encodes it into unicode.  do I have to do this?
                    return HTTPPreconditionFailed(
                        request=req, body='Invalid UTF8')(env, start_response)

                return handler.handle_request(env, req)(env, start_response)
        except InvalidConfiguration, e:
            logger = get_logger(self.conf, log_route='origin_server')
            logger.exception(e)
            #TODO: get better error message
            return HTTPInternalServerError(e)(env, start_response)
                
        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def origin(app):
        return OriginServer(app, conf)
    return origin
