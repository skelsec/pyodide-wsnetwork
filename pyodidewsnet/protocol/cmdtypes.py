import enum

class CMDType(enum.Enum):
	OK = 0
	ERR = 1
	LOG = 2
	STOP = 3
	CONTINUE = 4
	CONNECT = 5
	DISCONNECT = 6
	SD = 7
