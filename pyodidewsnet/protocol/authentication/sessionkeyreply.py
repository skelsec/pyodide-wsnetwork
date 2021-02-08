
import ipaddress
import io
from pyodidewsnet.protocol.cmdtypes import CMDType
from pyodidewsnet.protocol import CMD
from pyodidewsnet.protocol.utils import *

class WSNSessionKeyReply(CMD):
	def __init__(self, token, status, sessionkey):
		self.type = CMDType.SESSIONKEYREPLY
		self.token = token
		self.status = status
		self.sessionkey = sessionkey

	@staticmethod
	def from_bytes(data):
		return WSNSessionKeyReply.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		token = buff.read(16)
		status = readStr(buff)
		sessionkey = readBytes(buff)
		return WSNSessionKeyReply(token, status, sessionkey)

	def to_data(self):
		buff = io.BytesIO()
		t = self.type.value.to_bytes(2, byteorder = 'big', signed = False)
		if isinstance(self.token, str):
			t += self.token.encode()
		else:
			t += self.token
		buff.write(t)
		writeStr(buff, self.status)
		writeBytes(buff, self.sessionkey)
		buff.seek(0,0)		
		return buff.read()