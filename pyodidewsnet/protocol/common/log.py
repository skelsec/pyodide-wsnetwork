import json

from pyodidewsnet.utils.encoder import UniversalEncoder
from pyodidewsnet.protocol.cmdtypes import CMDType
from pyodidewsnet.protocol import CMD

class WSNLog(CMD):
	def __init__(self, token, level, msg):
		self.type = CMDType.LOG
		self.token = token
		self.level = level
		self.msg = msg
	
	def to_dict(self):
		return self.__dict__
	
	def to_json(self):
		return json.dumps(self.to_dict(), cls = UniversalEncoder)
	
	@staticmethod
	def from_dict(d):
		cmd = WSNLog(d['token'],d['level'], d['msg'])
		return cmd

	@staticmethod
	def from_json(jd):
		return WSNLog.from_dict(json.loads(jd))