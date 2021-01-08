import json

from pyodidewsnet.utils.encoder import UniversalEncoder
from pyodidewsnet.protocol.cmdtypes import CMDType
from pyodidewsnet.protocol import CMD

class WSNErr(CMD):
	def __init__(self, token, reason, extra = ''):
		self.type = CMDType.ERR
		self.token = token
		self.reason = reason
		self.extra = extra
	
	def to_dict(self):
		return self.__dict__
	
	def to_json(self):
		return json.dumps(self.to_dict(), cls = UniversalEncoder)
	
	@staticmethod
	def from_dict(d):
		cmd = WSNErr(d['token'],d['reason'], d['extra'])
		return cmd

	@staticmethod
	def from_json(jd):
		return WSNErr.from_dict(json.loads(jd))