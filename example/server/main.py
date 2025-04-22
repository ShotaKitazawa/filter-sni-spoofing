import http.server
import ssl

httpd = http.server.HTTPServer(('0.0.0.0', 443), http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='/etc/certs/server.crt', keyfile='/etc/certs/server.key', server_side=True)
httpd.serve_forever()
