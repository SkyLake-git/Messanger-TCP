import abc
import ast
import cryptocode

PROTOCOL_VERSION = 4
CRYPTO = "iwfNWpeF3NZdNJ2fsJELywZErTvXG7"

class PacketData:

	def __init__(self):
		self.list = {}
		self.header = {"id" : -1}
	
	def putString(self, name: str, data: str):
		self.list[name] = data
	
	def putFloat(self, name: str, data: float):
		self.list[name] = data
	
	def put(self, name: str, data):
		self.list[name] = data

	
	def get(self, name: str):
		if name in self.list:
			return self.list[name]
		else:
			return None

	def getHeader(self, name: str):
		if name in self.header:
			return self.header[name]
		else:
			return None
	
	def putHeader(self, name: str, data):
		self.header[name] = data
		
class PacketIds:

	TEXT_PACKET = 1

	SESSION_PACKET = 2

	DISCONNECT_PACKET = 3
	
	LOGIN_PACKET = 4

	HANDSHAKE_PACKET = 5

	SERVER_RESPONSE_PACKET = 120

class Packet(object, metaclass=abc.ABCMeta):

	def __init__(self):
		pass

	
	@abc.abstractmethod
	def encode(self) -> PacketData:
		pass

	@abc.abstractmethod
	def decode(self, inb: PacketData):
		pass

class Clientbound:
	pass

class Serverbound:
	pass

class Unconnected:
	pass

class PacketFactory:

	def __init__(self):
		self.list = {}

		self.register(PacketIds.TEXT_PACKET, TextPacket())

		self.register(PacketIds.SESSION_PACKET, SessionPacket())

		self.register(PacketIds.SERVER_RESPONSE_PACKET, ServerResponsePacket())

		self.register(PacketIds.DISCONNECT_PACKET, DisconnectPacket())

		self.register(PacketIds.HANDSHAKE_PACKET, HandshakePacket())
		
		self.register(PacketIds.LOGIN_PACKET, LoginPacket())

	def register(self, id: int, packet: Packet):
		self.list[id] = packet

	def get(self, id: int) -> Packet:
		if id in self.list:
			return self.list[id]
		else:
			return None


class NoContextPacket(Packet):

	ID = -1

	def __init__(self):
		pass

	def encode(self):
		outb = PacketData()
		outb.putHeader("id", self.ID)
		return outb
	
	def decode(self, inb: PacketData):
		pass


class HandshakePacket(NoContextPacket, Clientbound):
	ID = PacketIds.HANDSHAKE_PACKET


class SessionPacket(Packet, Unconnected, Serverbound):
	ID = PacketIds.SESSION_PACKET
	
	def __init__(self):
		self.protocol = 0

	def encode(self):
		outb = PacketData()
		outb.putHeader("id", self.ID)
		outb.put("protocol", self.protocol)
		return outb
	
	def decode(self, inb: PacketData):
		self.protocol = inb.get("protocol")

class DisconnectPacket(Packet, Serverbound, Clientbound):
	ID = PacketIds.DISCONNECT_PACKET

	def __init__(self):
		self.reason = ""

	def encode(self):
		outb = PacketData()
		outb.putHeader("id", self.ID)
		outb.put("reason", self.reason)
		return outb
	
	def decode(self, inb: PacketData):
		self.reason = inb.get("reason")

class ServerResponsePacket(Packet, Clientbound):
	ID = PacketIds.SERVER_RESPONSE_PACKET

	STATUS_OK = 0
	STATUS_PACKET_VIOLATION = 1
	STATUS_IGNORED = 2

	def __init__(self):
		self.status = 0

	def encode(self):
		outb = PacketData()
		outb.putHeader("id", self.ID)
		outb.put("status", self.status)
		return outb
	
	def decode(self, inb: PacketData):
		self.status = inb.get("status")

class LoginPacket(Packet, Serverbound):
	ID = PacketIds.LOGIN_PACKET

	def __init__(self):
		self.username = "Unknown"

	def encode(self):
		outb = PacketData()
		outb.putHeader("id", self.ID)
		outb.putString("username", self.username)
		return outb

	def decode(self, inb: PacketData):
		self.username = inb.get("username")

	


class TextPacket(Packet, Serverbound, Clientbound):

	ID = PacketIds.TEXT_PACKET

	text: str

	def __init__(self):
		self.text = ""

	def encode(self):
		outb = PacketData()
		outb.putHeader("id", self.ID)
		outb.putString("text", self.text)
		return outb

	def decode(self, inb: PacketData):
		self.text = inb.get("text")
	
	

def getPacket(data: bytes):
	try:
		dataStr = data.decode()
	except: return None

	dataStr = cryptocode.decrypt(dataStr, CRYPTO)
	if (dataStr == False):
		return False

	try:
		dataDict = ast.literal_eval(dataStr)
	except: return None

	return dataDict

def isValidPacket(dataDict: dict):
	if not "header" in dataDict:
		return False
	
	return True

def createPacketData(dataDict: dict):
	packetId = dataDict["header"]["id"]
	packetData = PacketData()
	packetData.putHeader("id", packetId)
	for name, data in dataDict.items():
		packetData.put(name, data)

	return packetData

def getBytesFromPacketData(packetData: PacketData):
	main = packetData.list
	header = packetData.header
	mdict = main
	mdict["header"] = header

	dictStr = str(mdict)
	dictStr = cryptocode.encrypt(dictStr, CRYPTO)
	bytes = dictStr.encode()
	return bytes

def convertPacketToBytes(packet: Packet):
	packetData = packet.encode()
	bytes = getBytesFromPacketData(packetData)
	return bytes