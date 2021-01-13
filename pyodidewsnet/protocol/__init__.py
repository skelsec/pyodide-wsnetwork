
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


from pyodidewsnet.protocol.cmdtypes import CMDType
from pyodidewsnet.protocol.common.ok import WSNOK
from pyodidewsnet.protocol.common.err import WSNErr
from pyodidewsnet.protocol.common.log import WSNLog
from pyodidewsnet.protocol.common.stop import WSNStop
from pyodidewsnet.protocol.connection.connect import WSNConnect
from pyodidewsnet.protocol.connection.socketdata import WSNSocketData
from pyodidewsnet.protocol.common.wsncontinue import WSNContinue





__all__ = [
	'CMDType',
	'CMD',
	'WSNOK',
	'WSNErr',
	'WSNLog',
	'WSNContinue',
	'WSNStop',
	'WSNConnect',
	'WSNSocketData'

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
	CMDType.SD : WSNSocketData

}