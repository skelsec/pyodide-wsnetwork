
import ipaddress
import io
from pyodidewsnet.protocol.cmdtypes import CMDType
from pyodidewsnet.protocol import CMD
from pyodidewsnet.protocol.utils import *

class WSNKerberosAuthReply(CMD):
	def __init__(self, token, status, ctxattr, authdata):
		self.type = CMDType.KERBEROSREPLY
		self.token = token
		self.status = status
		self.ctxattr = ctxattr
		self.authdata = authdata

	@staticmethod
	def from_bytes(data):
		return WSNKerberosAuthReply.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		token = buff.read(16)
		status = readStr(buff)
		ctxattr = int(readStr(buff))
		authdata = readBytes(buff)
		return WSNKerberosAuthReply(token, status, ctxattr, authdata)

	def to_data(self):
		buff = io.BytesIO()
		t = self.type.value.to_bytes(2, byteorder = 'big', signed = False)
		if isinstance(self.token, str):
			t += self.token.encode()
		else:
			t += self.token
		buff.write(t)
		writeStr(buff, self.status)
		writeStr(buff, self.ctxattr)
		writeBytes(buff, self.authdata)
		buff.seek(0,0)
		return buff.read()