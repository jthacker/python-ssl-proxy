#!/usr/bin/env python
import argparse
import logging
import select
import socket
import ssl
import threading


def port_type(port_str):
    port = int(port_str)
    if port < 0 or port > 65355:
        raise ValueError('port {!r} is invalid'.format(port_str))
    return port


def run_connection(incoming, port_out):
    outgoing = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    outgoing.connect(('127.0.0.1', port_out))
    logging.info('established outgoing connection to %r', port_out)
    logging.info('proxy connection established')
    partners = {
        incoming: outgoing,
        outgoing: incoming
    }
    rs = [incoming, outgoing]
    ws = []
    es = [incoming, outgoing]
    run = True
    while run:
        readable, _, exceptional = select.select(rs, ws, es)
        if exceptional:
            run = False
            break
        for reader in readable:
            writer = partners[reader]
            try:
                data = reader.recv(1024)
            except socket.ConnectionResetError:
                run = False
                break
            if data:
                writer.sendall(data)
                logging.info('proxy transferred %d bytes', len(data))
            else:
                run = False
                break
    outgoing.close()
    incoming.close()
    logging.info('proxy connection failed')


def start_server(port_in, port_out, context):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', port_in))
    # listen for connections, keep a backlog of 5
    server.listen(5)
    # wrap the socket with a TLS connection
    server_ssl = context.wrap_socket(server, server_side=True)
    logging.info('ssl compression: %r', server_ssl.compression())
    threads = []
    while True:
        logging.info('waiting for connections')
        conn, client_addr = server_ssl.accept()
        logging.info('received connection from %r', client_addr)
        thread = threading.Thread(target=run_connection, args=(conn, port_out))
        thread.start()
        threads.append(thread)


def main():
    FORMAT = '%(asctime)-15s - %(message)s'
    parser = argparse.ArgumentParser()
    parser.add_argument('port_in', type=port_type, metavar='port-in')
    parser.add_argument('port_out', type=port_type, metavar='port-out')
    parser.add_argument('cert_chain', metavar='cert-chain')
    parser.add_argument('private_key', metavar='private-key')
    args = parser.parse_args()

    logging.basicConfig(format=FORMAT)
    logging.getLogger().setLevel(logging.INFO)
    logging.info('starting ssl terminating proxy')
    logging.info('incoming port: %d', args.port_in)
    logging.info('outgoing port: %d', args.port_out)

    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain(args.cert_chain, args.private_key)
    start_server(args.port_in, args.port_out, context)


if __name__ == '__main__':
    main()
