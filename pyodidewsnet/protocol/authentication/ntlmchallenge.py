
import ipaddress
import io
from pyodidewsnet.protocol.cmdtypes import CMDType
from pyodidewsnet.protocol import CMD
from pyodidewsnet.protocol.utils import *

class WSNNTLMChallenge(CMD):
	def __init__(self, token, authdata, ctxattr = 0, targetname = ""):
		self.type = CMDType.NTLMCHALL
		self.token = token
		self.authdata = authdata
		self.ctxattr = ctxattr
		self.targetname = targetname

	@staticmethod
	def from_bytes(data):
		return WSNNTLMChallenge.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		token = buff.read(16)
		authdata = readBytes(buff)
		ctxattr = int(readStr(buff))
		targetname = readStr(buff)
		return WSNNTLMChallenge(token, authdata, ctxattr, targetname)

	def to_data(self):
		buff = io.BytesIO()
		t = self.type.value.to_bytes(2, byteorder = 'big', signed = False)
		if isinstance(self.token, str):
			t += self.token.encode()
		else:
			t += self.token
		buff.write(t)
		writeBytes(buff, self.authdata)
		writeStr(buff, self.ctxattr)
		writeStr(buff, self.targetname)
		buff.seek(0,0)		
		return buff.read()