from distutils.command.install_lib import PYTHON_SOURCE_EXTENSION
import sys
import hmac
import binascii
import base64
from hashlib import sha1
try:
	from http.client import HTTPConnection
except ImportError:
	from httplib import HTTPConnection
from struct import pack, unpack
from time import time

RSA_MOD = 104890018807986556874007710914205443157030159668034197186125678960287470894290830530618284943118405110896322835449099433232093151168250152146023319326491587651685252774820340995950744075665455681760652136576493028733914892166700899109836291180881063097461175643998356321993663868233366705340758102567742483097
RSA_KEY = 257

ENROLL_HOSTS = {
	"CN": "mobile-service.battlenet.com.cn",
	"EU": "mobile-service.blizzard.com",
	"US": "mobile-service.blizzard.com",
	"default": "mobile-service.blizzard.com",
}PYTHON_SOURCE_EXTENSION getkey.py <serial> <restore code>


def getServerResponse(data, host, path):
	conn = HTTPConnection(host)
	conn.request("POST", path, data)
	response = conn.getresponse()

	if response.status != 200:
		raise HTTPError("%s returned status %i" % (host, response.status), response)

	ret = response.read()
	conn.close()
	return ret


def validatePaperRestore(data, host=ENROLL_HOSTS["default"], path="/enrollment/validatePaperRestore.htm"):
	try:
		response = getServerResponse(data, host, path)
	except HTTPError as e:
		if e.response.status == 600:
			raise HTTPError("Invalid serial or restore key", e.response)
		else:
			raise
	return response

def initiatePaperRestore(serial, host=ENROLL_HOSTS["default"], path="/enrollment/initiatePaperRestore.htm"):
	return getServerResponse(serial, host, path)

class HTTPError(Exception):
	def __init__(self, msg, response):
		self.response = response
		super(HTTPError, self).__init__(msg)

def normalizeSerial(serial):
	"""
	Normalizes a serial
	Will uppercase it, remove its dashes and strip
	any whitespace
	"""
	return serial.upper().replace("-", "").strip()


def restore(serial, code):
	serial = normalizeSerial(serial)
	host = ENROLL_HOSTS[serial[0:2]]
	if len(code) != 10:
		raise ValueError("invalid restore code (should be 10 bytes): %r" % (code))

	challenge = initiatePaperRestore(serial, host)
	if len(challenge) != 32:
		raise HTTPError("Invalid challenge length (expected 32, got %i)" % (len(challenge)))

	code = restoreCodeToBytes(code)
	hash = hmac.new(code, serial.encode() + challenge, digestmod=sha1).digest()

	otp = getOneTimePad(20)
	e = encrypt(hash + otp)
	response = validatePaperRestore(serial + e, host)
	secret = decrypt(response, otp)

	return secret

def restoreCodeToBytes(code):
	ret = bytearray()
	for c in code:
		c = ord(c)
		if 58 > c > 47:
			c -= 48
		else:
			mod = c - 55
			if c > 72:
				mod -= 1
			if c > 75:
				mod -= 1
			if c > 78:
				mod -= 1
			if c > 82:
				mod -= 1
			c = mod
		ret.append(c)

	return bytes(ret)


def getOneTimePad(length):
	def timedigest():
		return sha1(str(time()).encode()).digest()

	return (timedigest() + timedigest())[:length]


def encrypt(data):
	data = int(binascii.hexlify(data), 16)
	n = data ** RSA_KEY % RSA_MOD
	ret = ""
	while n > 0:
		n, m = divmod(n, 256)
		ret = chr(m) + ret
	return ret

def decrypt(response, otp):
	ret = bytearray()
	for c, e in zip(response, otp):
		# python2 compatibility
		if isinstance(c, str):
			c = ord(c)
			e = ord(e)

		ret.append(c ^ e)
	return ret

print base64.b32encode(restore(sys.argv[1], sys.argv[2]))
