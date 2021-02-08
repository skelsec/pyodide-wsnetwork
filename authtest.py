import asyncio
import websockets
import os

from pyodidewsnet.protocol import CMD
from pyodidewsnet.protocol.authentication.ntlmauth import WSNNTLMAuth
from pyodidewsnet.protocol.authentication.ntlmchallenge import WSNNTLMChallenge
from pyodidewsnet.protocol.authentication.sessionkey import WSNGetSessionKey
from pyodidewsnet.protocol.authentication.kerberosauth import WSNKerberosAuth



async def hello():
	#await asyncio.sleep(5)
	while True:
		try:
			uri = "ws://10.10.10.102:8700"
			token = os.urandom(16)
			async with websockets.connect(uri) as websocket:
				
				authreq = WSNNTLMAuth(token)
				data = authreq.to_bytes()
				print(data)
				await websocket.send(data)
				reply = await websocket.recv()
				print("REPLY! %s" % reply)
				r = CMD.from_bytes(reply)
				print(r)

				print(r.token == token)
				print(r.status)
				print(r.authdata)
				print(r.ctxattr)
				
				authdata = bytes.fromhex("4e544c4d53535000020000000800080038000000158289e2be52a42bbe65eaef000000000000000088008800400000000a0063450000000f540045005300540002000800540045005300540001001200570049004e003200300031003900410044000400120074006500730074002e0063006f007200700003002600570049004e003200300031003900410044002e0074006500730074002e0063006f00720070000500120074006500730074002e0063006f00720070000700080010fa582d3bf7d60100000000")

				chall = WSNNTLMChallenge(token, authdata, r.ctxattr)
				
				data = chall.to_bytes() 
				print(data)
				await websocket.send(data)
				reply = await websocket.recv()
				print("REPLY! %s" % reply)
				r = CMD.from_bytes(reply)
				print(r)

				print(r.token == token)
				print(r.status)
				print(r.authdata)
				print(r.ctxattr)

				sk = WSNGetSessionKey(token)
				
				data = sk.to_bytes() 
				print(data)
				await websocket.send(data)
				reply = await websocket.recv()
				print("REPLY sess! %s" % reply)
				r = CMD.from_bytes(reply)
				print(r)

				print(r.token == token)
				print(r.status)
				print(r.sessionkey)

				try:
					token = os.urandom(16)
					target = 'cifs/win2019AD@TEST'
					kb = WSNKerberosAuth(token, target)
					data = kb.to_bytes()
					print(data)
					await websocket.send(data)
					reply = await websocket.recv()
					print("REPLY! %s" % reply)
					r = CMD.from_bytes(reply)
					print(r)


					sk = WSNGetSessionKey(token)
				
					data = sk.to_bytes() 
					print(data)
					await websocket.send(data)
					reply = await websocket.recv()
					print("REPLY sess! %s" % reply)
					r = CMD.from_bytes(reply)
					print(r)

					print(r.token == token)
					print(r.status)
					print(r.sessionkey)


				except Exception as e:
					print(e)





		except Exception as e:
			print(e)
		await asyncio.sleep(5)

asyncio.get_event_loop().run_until_complete(hello())