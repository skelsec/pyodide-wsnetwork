
import ipaddress
import io
from pyodidewsnet.protocol.cmdtypes import CMDType
from pyodidewsnet.protocol import CMD

class WSNConnect(CMD):
	def __init__(self, token, protocol, ip, port):
		self.type = CMDType.CONNECT
		self.token = token
		self.protocol = protocol
		self.ip = ip
		self.port = port

	@staticmethod
	def from_bytes(data):
		return WSNConnect.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		token = buff.read(16)
		protocol = buff.read(3).decode()
		ipver = buff.read(1)
		if ipver == b'\x04':
			ip = str(ipaddress.ip_address(buff.read(4)))
		elif ipver == b'\x06':
			ip = str(ipaddress.ip_address(buff.read(16)))
		port = int.from_bytes(buff.read(2), byteorder='big', signed=False)
		return WSNConnect(token, protocol, ip, port)

	def to_data(self):
		t = self.type.value.to_bytes(2, byteorder = 'big', signed = False)
		if isinstance(self.token, str):
			t += self.token.encode()
		else:
			t += self.token
		t += self.protocol.encode()
		ip = ipaddress.ip_address(self.ip)
		if ip.version == 4:
			t += b'\x04' + ip.packed
		elif ip.version == 6:
			t += b'\x06' + ip.packed
		else:
			raise Exception('?')
		
		t += self.port.to_bytes(2, byteorder = 'big', signed = False)
		return t