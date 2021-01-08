import websockets
import asyncio
import os

from pyodidewsnet import logger
from pyodidewsnet.clienthandler import ClientHandler



class Server:
	def __init__(self, listen_ip = '127.0.0.1', listen_port = 8700, ssl_ctx = None):
		self.listen_ip = listen_ip
		self.listen_port = listen_port
		self.ssl_ctx = ssl_ctx
		self.wsserver = None
		self.clients = {}

	async def handle_client(self, ws, path):
		remote_ip, remote_port = ws.remote_address
		logger.info('Client connected from %s:%d' % (remote_ip, remote_port))
		client = ClientHandler(ws)
		self.clients[client] = 1
		await client.run()
		await client.terminate()
	

	async def run(self):
		self.wsserver = await websockets.serve(self.handle_client, self.listen_ip, self.listen_port, ssl=self.ssl_ctx)
		await self.wsserver.wait_closed()

