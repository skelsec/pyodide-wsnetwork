import websockets
import asyncio
import os
import io
import traceback
import datetime
import logging

from pyodidewsnet import logger
from pyodidewsnet.protocol import *

class ClientServer:
	def __init__(self, out_q, in_q, signal_q_in, signal_q_out, listen_ip = '0.0.0.0', listen_port = 8901, ssl_ctx = None):
		self.listen_ip = listen_ip
		self.listen_port = listen_port
		self.ssl_ctx = ssl_ctx
		self.wsserver = None
		self.clients = {}
		self.out_q = out_q
		self.in_q = in_q
		self.signal_q_in = signal_q_out
		self.signal_q_out = signal_q_in

	async def __handle_signal_in_queue(self):
		while True:
			data = await self.signal_q_in.get()
			print('AGENT SIGNAL IN! %s' % data)

	async def __handle_in_queue(self):
		while True:
			res = await self.in_q.get()
			try:
				agentid, data = res
				#print('AGENT DATA SEND %s' % data)
				await self.clients[agentid].send(data)
			except Exception as e:
				logger.exception('failed sending agent data!')
	

	async def handle_client(self, ws, path):
		agentid = None
		try:
			agentid = os.urandom(16)
			self.clients[agentid] = ws
			remote_ip, remote_port = ws.remote_address
			logger.info('AGENT connected from %s:%d' % (remote_ip, remote_port))
			while True:
				try:
					data = await ws.recv()
					#print('AGENT DATA RECV %s' % data)
					reply = CMD.from_bytes(data)
					if reply.token == b'\x00'*16:
						await self.signal_q_out.put(('AGENTIN', agentid, reply))
						continue
					
					await self.out_q.put((agentid, reply.token, data))
				except Exception as e:
					logger.exception('Error in agent handling')
					return
		except Exception as e:
			traceback.print_exc()
		finally:
			if agentid in self.clients:
				del self.clients[agentid]
				await self.signal_q_out.put(('AGENTOUT', agentid, None))
			await ws.close()

	async def run(self):
		asyncio.create_task(self.__handle_in_queue())
		self.wsserver = await websockets.serve(self.handle_client, self.listen_ip, self.listen_port, ssl=self.ssl_ctx)
		await self.wsserver.wait_closed()
		print('Agent handler exiting')

class OPServer:
	def __init__(self, in_q, out_q, signal_q_in, signal_q_out, listen_ip = '0.0.0.0', listen_port = 8900, ssl_ctx = None):
		self.listen_ip = listen_ip
		self.listen_port = listen_port
		self.ssl_ctx = ssl_ctx
		self.wsserver = None
		self.agents = {}
		self.operators = {}
		self.in_q = in_q
		self.out_q = out_q
		self.data_lookop = {}
		self.signal_q_in = signal_q_in
		self.signal_q_out = signal_q_out
				
	async def __handle_signal_in_queue(self):
		while True:
			data = await self.signal_q_in.get()
			msg, agentid, data = data
			#print('OP SIGNAL IN! %s' % msg)
			if msg == 'AGENTIN':
				print('NEW AGENT : %s' % agentid.hex())
				self.agents[agentid] = data
				agentnotify = WSNListAgentsReply(
					b'\x00'*16,
					agentid,
					data.pid, 
					data.username, 
					data.domain, 
					data.logonserver, 
					data.cpuarch, 
					data.hostname
				)
				for opid in self.operators:
					try:
						await self.operators[opid].send(agentnotify.to_bytes())
					except Exception as e:
						del self.operators[opid]
						#traceback.print_exc()

			elif msg == 'AGENTOUT':
				if agentid in self.agents:
					del self.agents[agentid]

	async def __handle_in_queue(self):
		while True:
			res = await self.in_q.get()
			try:
				#print('OP DATA IN %s' % repr(res))
				agentid, token, data = res
				tid = agentid+token
				if tid in self.data_lookop:
					try:
						await self.data_lookop[tid].send(data)
					except:
						# currently there is no tracking if the operator has disappeared
						del self.data_lookop[tid]
				else:
					print('TID NOT FOUND!')
					print('TOKEN:   %s' % token)
					print('AGENTID: %s' % agentid)
			except Exception as e:
				logger.exception('OP __handle_in_queue')

	async def handle_client(self, ws, path):
		opid = None
		try:
			opid = os.urandom(16)
			self.operators[opid] = ws
			remote_ip, remote_port = ws.remote_address
			logger.info('Client connected from %s:%d' % (remote_ip, remote_port))
			while True:
				data = await ws.recv()
				#print('OP DATA OUT %s' % data)
				buff = io.BytesIO(data)
				dlen = int.from_bytes(buff.read(4), byteorder='big', signed=False)
				agentid = buff.read(16)
				
				
				agentdata = buff.read(-1)
				cmd = CMD.from_bytes(agentdata)
				#print(cmd)
				#print('OP TOKEN: %s' % cmd.token.hex())
				#print('OP AGENTID: %s' % agentid.hex())
				if agentid not in self.agents:
					err = WSNErr(cmd.token, "Agent not found", "")
					await ws.send(err.to_bytes())
					continue

				if cmd.token == b'\x00'*16:
					if cmd.type == CMDType.LISTAGENTS:
						for agentid in self.agents:
							agentinfo = self.agents[agentid]
							reply = WSNListAgentsReply(
								cmd.token,
								agentid,
								agentinfo.pid, 
								agentinfo.username, 
								agentinfo.domain, 
								agentinfo.logonserver, 
								agentinfo.cpuarch, 
								agentinfo.hostname
							)
							await ws.send(reply.to_bytes())
					continue
				self.data_lookop[agentid+cmd.token] = ws
				
				await self.out_q.put((agentid, agentdata))
		
		except Exception as e:
			print('OPERATOR DISCONNECTED!')
		finally:
			if opid in self.operators:
				del self.operators[opid]

	async def run(self):
		asyncio.create_task(self.__handle_signal_in_queue())
		asyncio.create_task(self.__handle_in_queue())
		self.wsserver = await websockets.serve(self.handle_client, self.listen_ip, self.listen_port, ssl=self.ssl_ctx)
		await self.wsserver.wait_closed()

async def amain():
	#logging.basicConfig(level=logging.DEBUG)

	clientsrv_task = None
	opsrv_task = None

	try:
		signal_q_in = asyncio.Queue()
		signal_q_out = asyncio.Queue()
		in_q = asyncio.Queue()
		out_q = asyncio.Queue()
		clientsrv = ClientServer(in_q, out_q, signal_q_in, signal_q_out)
		opsrv = OPServer(in_q, out_q, signal_q_in, signal_q_out)
		clientsrv_task = asyncio.create_task(clientsrv.run())
		await opsrv.run()
		

	except Exception as e:
		traceback.print_exc()

if __name__ == '__main__':
	asyncio.run(amain())