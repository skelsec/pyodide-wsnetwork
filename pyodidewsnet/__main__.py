
import os
import ssl
import asyncio
import logging


from pyodidewsnet.server import Server



async def amain():
	import argparse
	parser = argparse.ArgumentParser(description='WSNET ws->TCP proxy server')
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
	parser.add_argument('--listen-ip', default = '127.0.0.1', help='IP address for the server to listen on')
	parser.add_argument('--listen-port', type=int, default=8700, help='Port for the server to listen on')
	parser.add_argument('--ssl-cert', help='Server SSL certificate')
	parser.add_argument('--ssl-key', help='Server SSL key')

	args = parser.parse_args()

	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
			
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
			
	elif args.verbose > 1:
		logging.basicConfig(level=1)

	ssl_ctx = None


	if args.ssl_cert is not None:
		ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
		ssl_ctx.load_cert_chain(args.ssl_cert, args.ssl_key)

	server = Server(
		listen_ip = args.listen_ip, 
		listen_port = args.listen_port, 
		ssl_ctx = ssl_ctx, 
	)

	logging.info('Starting server')
	await server.run()

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()