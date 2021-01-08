import json

from pyodidewsnet.utils.encoder import UniversalEncoder
from pyodidewsnet.protocol.cmdtypes import CMDType
from pyodidewsnet.protocol import CMD

class WSNStop(CMD):
	def __init__(self, token):
		self.type = CMDType.STOP
		self.token = token
	
	def to_dict(self):
		return self.__dict__
	
	def to_json(self):
		return json.dumps(self.to_dict(), cls = UniversalEncoder)
	
	@staticmethod
	def from_dict(d):
		cmd = WSNStop(d['token'])
		return cmd

	@staticmethod
	def from_json(jd):
		return WSNStop.from_dict(json.loads(jd))