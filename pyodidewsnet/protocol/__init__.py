
import enum
import json



"""

 | length(4 bytes, unsinged, byteorder big) | data_type(BYTE) 0| DATA (length + 5)
 | length(4 bytes, unsinged, byteorder big) | data_type(BYTE) 1| JSON_HDR_LEN(4 bytes, unsinged, byteorder big) | JSON_HDR | DATA (length + JSON_HDR_LEN + 5)

length = total length of the "packet" including this length field
data_type = byte curtrently supported types are: JSON(0) BINARY(1)
DATA = variable size can be either JSON or raw binary data
"""

class CMD:
	def __init__(self):
		self.type = None

	def to_bytes(self):
		if self.type not in BINARY_TYPES:
			data = b'\x00' + self.to_json().encode()
		else:
			data = b'\x01'
			data += self.get_bytes()

		return (len(data)+4).to_bytes(4, byteorder = 'big', signed = False) + data

	def to_json(self):
		#needs to be implemented by the child class
		return None
	
	def get_bytes(self):
		#to be implemented by child if it's a binary one
		return None

	@staticmethod
	def from_bytes(data):
		length = int.from_bytes(data[:4], byteorder = 'big', signed = False)
		data_type = data[4]
		if data_type == 0:
			return CMD.from_json(data[5:length].decode())
		
		jlength = int.from_bytes(data[5:9], byteorder = 'big', signed = False)
		header = json.loads(data[9:9+jlength].decode())
		return type2cmd[CMDType(header['type'])].from_data(header, data[9+jlength:])

	@staticmethod
	def from_json(data_str):
		dd = json.loads(data_str)
		return type2cmd[CMDType(dd['type'])].from_dict(dd)


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