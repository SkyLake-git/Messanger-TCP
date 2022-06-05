import socket
from protocol import Packet
from protocol import Logger
import threading
import sys
import time
import cryptocode
import crayons

PORT = 19132
TPS = 20

FACTORY = Packet.PacketFactory()
LOGGER = Logger.Logger("Client")

DEBUG = True

RESPONSE = True

SHUTDOWN = False

LISTENER = None
SENDER = None


class SenderThread(threading.Thread):

	def __init__(self, socket):
		threading.Thread.__init__(self)
		self.setDaemon(True)
		self.socket = socket
		self.list = []
		self._running = True
		self.tick = 0
		self.lastSend = 0

	def addByte(self, byte: bytes):
		self.list.append(byte)

	def run(self):
		global RESPONSE
		while True:
			if (not self._running):
				break
			time.sleep(1 / TPS)
			self.tick += 1
			if (len(self.list) > 0 and RESPONSE):
				self.lastSend = self.tick
				RESPONSE = False
				byte = self.list[0]
				del self.list[0]
				remain = len(self.list)
				try:
					self.socket.send(byte)
				except:
					if (DEBUG): LOGGER.send("パケットの送信に失敗しました")
					continue
				if(DEBUG): LOGGER.send(f"パケットを送信しました (残り {remain})")
			
			if (not RESPONSE and (self.tick - self.lastSend >= (10 * 20))):
				LOGGER.send("サーバーの応答が10秒以上ないため、接続を強制終了しています")
				shutdown(disconnect=False, threadWait=False)

			


class ListenerThread(threading.Thread):

	def __init__(self, socket):
		threading.Thread.__init__(self)
		self.setDaemon(True)
		self.socket = socket
		self._running = True

	def run(self):
		global RESPONSE
		while True:
			if (not self._running):
				break

			self.socket.settimeout(3.0)
			try:
				recvdata = self.socket.recv(1024)
			except socket.timeout:
				if (not self._running):
					break
				continue
			packet = readPacket(recvdata)
			if (packet != None):
				if (not isinstance(packet, Packet.Clientbound)):
					LOGGER.send("<!> サーバーから不正なパケットが送られました")
				else:
					if (isinstance(packet, Packet.ServerResponsePacket)):
						RESPONSE = True
						if (DEBUG):
							status = packet.status
							stt = "OK"
							if (status == Packet.ServerResponsePacket.STATUS_PACKET_VIOLATION):
								stt = "Packet Violation (パケットが不正)"
							if (status == Packet.ServerResponsePacket.STATUS_IGNORED):
								stt = "Ignored (無視)"
							LOGGER.send(f"サーバー応答: {stt}")

				if (isinstance(packet, Packet.TextPacket)):
					LOGGER.send(packet.text)
				
				if (isinstance(packet, Packet.DisconnectPacket)):
					LOGGER.send(f"サーバーから切断されました: {packet.reason}")
					shutdown(disconnect=False, threadWait=False)


def readPacket(data: bytes):
	dataDict = Packet.getPacket(data)
	if (dataDict != None and dataDict != False):
		if (Packet.isValidPacket(dataDict)):
			packetData = Packet.createPacketData(dataDict)
			packetId = packetData.getHeader("id")
			packet = FACTORY.get(packetId)
			if (packet != None):
				packet.decode(packetData)
				return packet
	return None

def getArgs(command: str) -> list:
	split = command.split()
	if (len(split) > 1):
		main = split[0]
		return split[1:]
	else:
		return []

def shutdown(disconnect = True, threadWait = True):
	global SHUTDOWN
	LOGGER.send(crayons.red("クライアントをシャットダウンしています", bold=True))
	if (disconnect):
		LOGGER.send("切断パケットを送信しています...")
		disconnect = Packet.DisconnectPacket()
		bytes = Packet.convertPacketToBytes(disconnect)
		SENDER.addByte(bytes)
		LOGGER.send("送信キューが空になるまで待機しています...")
		while (len(SENDER.list) > 0):
			pass
	else:
		LOGGER.send("送信キューを空にしています...")
		SENDER.list = []
	time.sleep(1)
	LOGGER.send("全てのスレッドをシャットダウンしています...")
	if (SENDER != None and LISTENER != None):
		SENDER._running = False
		LISTENER._running = False
		if (threadWait):
			LISTENER.join()
			SENDER.join()
		else:
			LOGGER.send("安全なシャットダウンのために4秒待機します...")# ListenerThreadで3秒のタイムアウトがあるため
			time.sleep(4)
	LOGGER.send("接続を終了しています...")
	SENDER.socket.close()
	LOGGER.send("正常にシャットダウンされました")
	LOGGER.send("もしプログラムが終了されていない場合、何かのキーを押してみてください")
	SHUTDOWN = True
	sys.exit()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	LISTENER = ListenerThread(s)
	SENDER = SenderThread(s)

	while True:
		try:
			s.connect(('hot.mcsvr.online', 35178))
			break
		except:
			LOGGER.send("接続に失敗しました。1秒後に再試行します")
			time.sleep(1)
			continue
	LOGGER.send(crayons.cyan("接続に成功しました！", bold=True))
	LOGGER.send("サーバーからの応答を待っています...")
	s.settimeout(3.0)
	handshake = time.time()
	while True:
		if (time.time() - handshake >= 10):
			LOGGER.send("サーバーからの応答が10秒以上なかったため、接続を強制終了します")
			shutdown(disconnect=False)
			break
		recvdata = ""
		try:
			recvdata = s.recv(1024)
		except socket.timeout:
			pass
		packet = readPacket(recvdata)
		if (packet != None and packet != False):
			if (isinstance(packet, Packet.HandshakePacket)):
				LOGGER.send(crayons.yellow("サーバーからの応答を確認しました。",bold=True))
				LOGGER.send("コマンド入力を準備中です...")
				break
	
	if (SHUTDOWN):
		sys.exit()
		


	LISTENER.start()
	SENDER.start()

	while True:
		try:
			data = input("")
		except KeyboardInterrupt:
			if (SHUTDOWN):
				break
			shutdown()
		if (SHUTDOWN):
			break
		if (len(data) <= 0):
			LOGGER.send("送信するデータは1文字以上である必要があります")
			continue

		main = data.split()[0]
		if (main == "disconnect"):
			disconnect = Packet.DisconnectPacket()
			bytes = Packet.convertPacketToBytes(disconnect)
			SENDER.addByte(bytes)
		elif(main == "login"):
			args = getArgs(data)
			username = ""
			if (len(args) > 0):
				username = args[0]
			else:
				username = input("ユーザーネームを入力してください: ")
			pkt = []
			temp = Packet.SessionPacket()
			temp.protocol = Packet.PROTOCOL_VERSION
			pkt.append(temp)
			temp = Packet.LoginPacket()
			temp.username = username
			pkt.append(temp)

			for pk in pkt:
				bytes = Packet.convertPacketToBytes(pk)
				SENDER.addByte(bytes)
		elif(main == "chat"):
			args = getArgs(data)
			text = ""
			if (len(args) > 0):
				text = args[0]
			else:
				text = input("テキストを入力してください: ")
			pk = Packet.TextPacket()
			pk.text = text

			bytes = Packet.convertPacketToBytes(pk)
			SENDER.addByte(bytes)
		elif(main == "spam"):
			for i in range(1, 100):
				SENDER.addByte(b"a")
		else:
			SENDER.addByte(cryptocode.encrypt(data, Packet.CRYPTO).encode())