
from pyodidewsnet.protocol.cmdtypes import CMDType
from pyodidewsnet.protocol import CMD
from pyodidewsnet.protocol.utils import *
import io
import json

class WSNGetInfoReply(CMD):
	def __init__(self, token, pid, username, domain, logonserver, cpuarch, hostname, usersid):
		self.type = CMDType.GETINFOREPLY
		self.token = token
		self.pid = pid
		self.username = username
		self.domain = domain
		self.logonserver = logonserver
		self.cpuarch = cpuarch
		self.hostname = hostname
		self.usersid = usersid

	
	@staticmethod
	def from_bytes(data):
		return WSNGetInfoReply.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		token = buff.read(16)
		pid = int(readStr(buff))
		username = readStr(buff, 'utf-16-le')
		domain = readStr(buff, 'utf-16-le')
		logonserver = readStr(buff, 'utf-16-le')
		cpuarch = readStr(buff)
		hostname = readStr(buff, 'utf-16-le')
		usersid = readStr(buff)
		return WSNGetInfoReply(token, pid, username, domain, logonserver, cpuarch, hostname, usersid)
	
	def to_data(self):
		raise NotImplementedError()
		t = self.type.value.to_bytes(2, byteorder = 'big', signed = False)
		if isinstance(self.token, str):
			t += self.token.encode()
		else:
			t += self.token
		return t
	
	def to_dict(self):
		return {
			'pid' : self.pid,
			'username' :  self.username,
			'domain' : self.domain,
			'logonserver' : self.logonserver,
			'cpuarch' : self.cpuarch,
			'hostname' : self.hostname,
			'usersid' : self.usersid
		}

	def to_json(self):
		return json.dumps(self.to_dict())
	
	def __str__(self):
		return self.to_json()