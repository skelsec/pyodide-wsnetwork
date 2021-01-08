import enum

class CMDType(enum.Enum):
	OK = 'OK'
	ERR = 'ERR'
	LOG = 'LOG'
	STOP = 'STOP'
	CONTINUE = 'CONTINUE'
	CONNECT = 'CONNECT'
	DISCONNECT = 'DISCONNECT'
	SD = 'SD'
