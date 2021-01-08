import json

from pyodidewsnet.utils.encoder import UniversalEncoder
from pyodidewsnet.protocol.cmdtypes import CMDType
from pyodidewsnet.protocol import CMD

class WSNSocketData(CMD):
	def __init__(self, token, data):
		self.type = CMDType.SD
		self.token = token
		self.data = data
	
	@staticmethod
	def from_data(hdr, data):
		return WSNSocketData(hdr['token'], data)


	def get_bytes(self):
		hj = json.dumps({'token': self.token, 'type': self.type.value}).encode()
		payload = len(hj).to_bytes(4, byteorder='big', signed=False) 
		payload += hj
		payload += self.data
		return payload