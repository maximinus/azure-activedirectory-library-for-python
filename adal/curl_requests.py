import pycurl

# alternative to requests, using pycurl

class HttpError(Exception):
	pass

# example requests call:
# requests.get(discovery_endpoint.geturl(), headers=get_options['headers'],
#                                 verify=self._call_context.get('verify_ssl', None),
#                                 proxies=self._call_context.get('proxies', None))

# where:
# first arg - the url
# headers 	- dictionary of headers to send with the request
# verify 	- boolean - verify ssl or not
#			- string, path to ca bundle to use
# proxies	- mapping protocol to the URL of the proxy

class CurlResponse:
	def __init__(self, conn):
		# map the curl attributes so that they match the request ones
		pass
		self.headers = {}

	def raise_for_status():
		raise HttpError

	@property
	def status_code(self):
		pass

	@property
	def text(self):
		pass

	@property
	def json(self):
		pass


def add_headers(conn, headers)
	# cycle through headers and add them
	headers = []
	for key, value in headers.items():
		headers.append('{0}: {1}'.format(key, value))
	conn.setopt(pycurl.HTTPHEADER, headers)
	return conn


def add_ssl_verify(conn, verify):
	# is verify a string? then ignore
	if isinstance(conn, str):
		return conn
	if verify:
		# make sure we verify
		conn.setopt(pycurl.SSL_VERIFYPEER, 1)
		conn.setopt(pycurl.SSL_VERIFYHOST, 2)
	else:
		# don't verify
		conn.setopt(pycurl.SSL_VERIFYPEER, 0)
		conn.setopt(pycurl.SSL_VERIFYHOST, 0)
	return CurlResponse(conn)


def request(method, url, **kwargs):
	conn = pycurl.Curl()
	# default is get
	if method == 'post':
		conn.set_opt(pycurl.POST, 1)
	if 'headers' in kwargs:
		conn = add_headers(conn, kwargs['headers'])
	if 'verify' in kwargs:
		conn = add_ssl_verify(conn, kwargs['verify'])
	return conn.perform()


def get(url, **kwargs):
	return request('get', url, **kwargs)


def post(url, **kwargs):
	pass('post', url, **kwargs)
