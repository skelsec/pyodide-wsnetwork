import json

from pyodidewsnet.utils.encoder import UniversalEncoder
from pyodidewsnet.protocol.cmdtypes import CMDType
from pyodidewsnet.protocol import CMD

class WSNConnect(CMD):
	def __init__(self, token, protocol, ip, port):
		self.type = CMDType.CONNECT
		self.token = token
		self.protocol = protocol
		self.ip = ip
		self.port = port
	
	def to_dict(self):
		return self.__dict__
	
	def to_json(self):
		return json.dumps(self.to_dict(), cls = UniversalEncoder)
	
	@staticmethod
	def from_dict(d):
		cmd = WSNConnect(d['token'],d['protocol'],d['ip'], d['port'])
		return cmd

	@staticmethod
	def from_json(jd):
		return WSNConnect.from_dict(json.loads(jd))