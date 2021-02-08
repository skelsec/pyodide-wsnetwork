
import enum
import io



"""

 | length(4 bytes, unsigned, byteorder big) | data_type(short) 0| DATA (length + 5)
length = total length of the "packet" including this length field

"""

class CMD:
	def __init__(self):
		self.type = None

	def to_bytes(self):
		data = self.to_data()
		return (len(data)+4).to_bytes(4, byteorder = 'big', signed = False) + data
	
	def get_bytes(self):
		#to be implemented by child if it's a binary one
		return None

	@staticmethod
	def from_bytes(data):
		return CMD.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder = 'big', signed = False)
		dt = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		return type2cmd[CMDType(dt)].from_buffer(buff)

class OPCMD:
	def __init__(self, agentid, cmd):
		self.agentid = agentid
		self.cmd = cmd

	def to_bytes(self):
		t = self.agentid
		t += self.cmd.to_bytes()
		cmdlen = len(t).to_bytes(4, byteorder='big', signed = False)
		return cmdlen+t


from pyodidewsnet.protocol.cmdtypes import CMDType
from pyodidewsnet.protocol.common.ok import WSNOK
from pyodidewsnet.protocol.common.err import WSNErr
from pyodidewsnet.protocol.common.log import WSNLog
from pyodidewsnet.protocol.common.stop import WSNStop
from pyodidewsnet.protocol.common.stop import WSNStop
from pyodidewsnet.protocol.common.info import WSNGetInfo
from pyodidewsnet.protocol.common.inforeply import WSNGetInfoReply
from pyodidewsnet.protocol.connection.connect import WSNConnect
from pyodidewsnet.protocol.connection.socketdata import WSNSocketData
from pyodidewsnet.protocol.common.wsncontinue import WSNContinue
from pyodidewsnet.protocol.authentication.ntlmauth import WSNNTLMAuth
from pyodidewsnet.protocol.authentication.ntlmauthreply import WSNNTLMAuthReply
from pyodidewsnet.protocol.authentication.ntlmchallengereply import WSNNTLMChallengeReply
from pyodidewsnet.protocol.authentication.ntlmchallenge import WSNNTLMChallenge
from pyodidewsnet.protocol.authentication.sessionkey import WSNGetSessionKey
from pyodidewsnet.protocol.authentication.sessionkeyreply import WSNSessionKeyReply
from pyodidewsnet.protocol.authentication.kerberosauth import WSNKerberosAuth
from pyodidewsnet.protocol.authentication.kerberosauthreply import WSNKerberosAuthReply
from pyodidewsnet.protocol.authentication.autherror import WSNAuthError
from pyodidewsnet.protocol.authentication.sequenceno import WSNGetSequenceNo
from pyodidewsnet.protocol.authentication.sequencenoreply import WSNGetSequenceNoReply
from pyodidewsnet.protocol.common.listagents import WSNListAgents
from pyodidewsnet.protocol.common.listagentsreply import WSNListAgentsReply



__all__ = [
	'CMDType',
	'CMD',
	'WSNOK',
	'WSNErr',
	'WSNLog',
	'WSNContinue',
	'WSNStop',
	'WSNConnect',
	'WSNSocketData',
	'WSNNTLMAuth',
	'WSNNTLMAuthReply',
	'WSNNTLMChallenge',
	'WSNNTLMChallengeReply',
	'WSNGetSessionKey',
	'WSNSessionKeyReply',
	'WSNKerberosAuthReply',
	'WSNKerberosAuth',
	'WSNAuthError',
	'WSNGetSequenceNo',
	'WSNGetSequenceNoReply',
	'WSNGetInfoReply',
	'WSNGetInfo',
	'WSNListAgents',
	'WSNListAgentsReply',

]

BINARY_TYPES = [
	CMDType.SD,
]

type2cmd = {
	CMDType.OK : WSNOK,
	CMDType.ERR : WSNErr,
	CMDType.LOG : WSNLog,
	CMDType.CONTINUE : WSNContinue,
	CMDType.STOP : WSNStop,
	CMDType.CONNECT : WSNConnect,
	CMDType.SD : WSNSocketData,
	CMDType.NTLMAUTH : WSNNTLMAuth,
	CMDType.NTLMAUTHREPLY : WSNNTLMAuthReply,
	CMDType.NTLMCHALL : WSNNTLMChallenge,
	CMDType.NTLMCHALLREPLY : WSNNTLMChallengeReply,
	CMDType.SESSIONKEY : WSNGetSessionKey,
	CMDType.SESSIONKEYREPLY : WSNSessionKeyReply,
	CMDType.KERBEROS : WSNKerberosAuth,
	CMDType.KERBEROSREPLY : WSNKerberosAuthReply,
	CMDType.AUTHERR : WSNAuthError,
	CMDType.SEQUENCE : WSNGetSequenceNo,
	CMDType.SEQUENCEREPLY : WSNGetSequenceNoReply,
	CMDType.GETINFO : WSNGetInfoReply,
	CMDType.GETINFOREPLY : WSNGetInfoReply,
	CMDType.LISTAGENTS : WSNListAgents,
}