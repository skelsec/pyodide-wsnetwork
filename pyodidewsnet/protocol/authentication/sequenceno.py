
import ipaddress
import io
from pyodidewsnet.protocol.cmdtypes import CMDType
from pyodidewsnet.protocol import CMD
from pyodidewsnet.protocol.utils import *

class WSNGetSequenceNo(CMD):
	def __init__(self, token):
		self.type = CMDType.SEQUENCE
		self.token = token

	@staticmethod
	def from_bytes(data):
		return WSNGetSequenceNo.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		token = buff.read(16)
		return WSNGetSequenceNo(token)

	def to_data(self):
		t = self.type.value.to_bytes(2, byteorder = 'big', signed = False)
		if isinstance(self.token, str):
			t += self.token.encode()
		else:
			t += self.token	
		return t