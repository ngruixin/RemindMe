from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
from pathlib import Path
import datetime as dt
import ssl
import secrets 
import hashlib

'''
Generate self-signed cert with the following command:
	$ openssl genrsa -out server.key 2048
 	$ openssl req -new -key server.key -out server.csr  (generate signing request)
 	$ openssl x509 -req -days 1024 -in server.csr -signkey server.key -out server.crt
  	$ cat server.crt server.key > server.pem
Refer to: http://pankajmalhotra.com/Simple-HTTPS-Server-In-Python-Using-Self-Signed-Certs
'''

IP = "127.0.0.1"						# server ip
PORT = 8080 							# server port
KEY = str.encode("get secret key")		# secret key of server (do not store plaintext!)
COOKIE_EXPIRATION = 60 * 60 			# amount of time for which a client auth cookie is valid
CERT = './server.pem'					# the certificate for the ssl connection

users = {}								# stores {username : {'password' : @password, 
										# 					 'pwd_salt' : @pwd_salt,
										# 					 'key_salt' : @key_salt}}
										# pwd_salt is the salt for the hashed and salted password stored 
										# key_salt is the salt users require to generate their secret key 
										# from their password

database = {}							# stores { username: @encrypted data of user }
										# data of users are key-value pairs used to fill forms 
										# (eg "first name" : "John')

class S(BaseHTTPRequestHandler):
	
	def _set_headers(self, status, content_type="text/json", cookie=None):
		self.send_response(status)
		self.send_header('Content-type', content_type)
		if cookie is not None:
			self.send_header('Set-Cookie', cookie)
		self.end_headers()

	def do_GET(self): 
		print("--------------")
		src = self.path[1:]
		content_type = ""
		if self.path.endswith('js'):
			content_type = 'application/javascript'
		elif self.path.endswith('html'):
			content_type = 'text/html'
		elif self.path.endswith('css'):
			content_type = 'text/css'
		elif "jpeg" in self.path:
			content_type = 'image/jpeg'
		elif "jpg" in self.path:
			content_type = 'image/jpg'
		elif "png" in self.path:
			content_type = 'image/png'
		elif self.path == "/":   
			src = 'login.html'
			content_type = 'text/html'
		self.serveFile(src, content_type)
		return

	def do_POST(self):
		print("--------------")
		try: 
			src = self.path[1:]
			#print("headers: ")
			#print(self.headers)
			content_length = self.headers['Content-Length']
			length = int(content_length) if content_length else 0
			post_data = self.rfile.read(length)
			if (src == "login.html"):
				post_data = json.loads(post_data)
				self.login(post_data)
			elif (src == "register.html"):
				post_data = json.loads(post_data)
				self.register(post_data)
			else: 
				# checks if the client is authorized before modifying data
				cookie = self.headers['Cookie']
				# print(cookie)
				if (self.isAuthorized(src, cookie)):
					self.modifyFields(src, post_data)
				else:
					self._set_headers(401)
					self.wfile.write("User is not authorized".encode())
		except (Exception) as e:
			print(e)
			self._set_headers(503)
			self.wfile.write("Invalid request".encode())

	def isAuthorized(self, username, cookie):
		'''
		Checks if the client is authorized by verifying that 
		@cookie["AUTH"] = hmac(@username, password, cookie["TIMESTAMP"])
		Uses the password stored in the database for the check 
		Also, checks that the cookie has not expired
		'''
		print("Checking authorization...")
		try: 
			cookie = json.loads(cookie)
			tag = cookie["AUTH"]
			ts = cookie["TIMESTAMP"]
			# check cookie has not expired  
			if ((dt.datetime.now() - dt.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")).total_seconds() <= COOKIE_EXPIRATION):
				user = users[username]
				password = user["password"]
				token = self.genAuthToken(username, password, ts)
				if (token == tag): 
					print("user is authorized")
					return True
			return False
		except (Exception) as e:
			print(e)
			return False

	def genAuthToken(self, username, password, ts):
		'''
		Generates the tag (i.e. hmac(@username : @password : @ts)) using 
		the server's secret key (@KEY)
		'''
		mac_msg = username + ":" + password + ":" + ts
		return CryptUtils.mac(mac_msg, KEY)

	def modifyFields(self, username, post_data):
		'''
		Modifies the data of the client (i.e. database[@username] = @post_data)
		'''
		print("modifying fields...")
		try: 
			if username in users.keys():
				database[username] = post_data.decode('utf-8')
				print("adding data to " + username + ": ")
				print(post_data)
				self._set_headers(200)
				self.wfile.write("Successfully modified fields".encode())
			else:
				self._set_headers(503)
				self.wfile.write("Invalid user".encode())
		except (Exception) as e:
			print("Adding fields exception: " + e)
			self._set_headers(503)
			self.wfile.write("Invalid request".encode())

	def login(self, post_data):
		'''
		Attempts to login to the system using the username and password
		sent in @post_data. Salts and hashes the password sent to 
		verify credentials. Send an auth cookie back with a token and timestamp 
		for future verification of credentials. Also, sends the key_salt to
		the client. 
		'''
		try:
			username = post_data["username"]
			password = post_data["password"]
			user = users[username]
			pwd = user["password"]
			salt = user["pwd_salt"]
			password = CryptUtils.saltAndHash(salt, password)
			if (password == pwd):
				key_salt = user["key_salt"]
				ts = str(dt.datetime.now())
				auth_token = self.genAuthToken(username, password, ts)
				cookie = json.dumps({"AUTH" : auth_token, "TIMESTAMP" : ts})
				self._set_headers(200, cookie=cookie)
				self.wfile.write(("salt=" + key_salt).encode())
				print(key_salt)
				print(username + " has logged in")
				return
			else:
				self._set_headers(401)
				self.wfile.write("Invalid user".encode())
				print(username + " failed to log in")
				return
		except (KeyError) as e:
			print(e)
			print("Invalid username login")
			self._set_headers(401)
			self.wfile.write("Invalid user".encode())

	def register(self, post_data):
		'''
		Adds a new user to the system. Checks if the username is 
		available, and stores the hashes and salts the password sent 
		before storing. Also stores the salt for the key and password. 
		'''
		print("registering...")
		print(post_data)
		try:
			username = post_data["username"]
			if username in users.keys():
				self._set_headers(503)
				self.wfile.write("The username is not available".encode())
				return	
			pwd = post_data["password"]
			pwd_salt = self.genSalt()
			pwd_to_store = self.saltAndHash(pwd_salt, pwd)
			users[username] = {"password": pwd_to_store, "pwd_salt": pwd_salt}
			database[username] = ""
			self._set_headers(200)
			self.wfile.write(("User " + username + " has been created. Please login to continue.").encode())
		except (Exception) as e:
			print(e)
			self._set_headers(503)
			self.wfile.write("Registration of user failed, please try again.".encode())


	def serveFile(self, file_name, content_type, resp=200):
		try:
			f = open("./src/" + file_name, "rb")
			self._set_headers(resp, content_type)
			self.wfile.write(f.read())
			f.close()
		except IOError as e:
			print(e)
			self.serveFile("error.html", "text/html", 404)

	def genSalt(self):
		'''
		Generates a random salt of length 16 bytes
		'''
		return secrets.token_hex(16)

	def saltAndHash(salt, pwd):
		'''
		Returns a hex value of the salted and hashed password 
		'''
		return hashlib.sha256((pwd+salt).encode()).hexdigest()

def parse(stdin):
	print(stdin)

def getStdin(): 
    threading.Timer(1, getStdin).start()
    while (True):
        stdin = input("")
        parse(stdin)

def initDB():
	'''
	Loads users.db adn data.db if the files exist
	'''
	user_file = Path("users.db")
	if user_file.exists():
		global users
		global database
		f = open("users.db", "r")
		users = json.loads(f.read())
		print("users loaded: ")
		print(users)
	data_file = Path("data.db")
	if data_file.exists():
		f = open("data.db", "r")
		database = json.loads(f.read())
		print("database loaded: ")
		print(database)

def run(server_class=HTTPServer, handler_class=S):
    server_address = (IP, PORT)
    httpd = server_class(server_address, handler_class)
    # opens ssl connection 
    #httpd.socket = ssl.wrap_socket (httpd.socket, certfile=CERT, server_side=True)
    print ('Starting httpd...')
    httpd.serve_forever()

if __name__ == "__main__":
    from sys import argv
    initDB()
    thread = threading.Thread(target=run)
    thread.daemon = True
    thread.start()
    while True:
    	# exit saves all data of users and database into the files users.db and data.db respectively
	    exit_signal = input('Type "exit" anytime to save state and stop server\n')
	    if exit_signal == 'exit':
	    	f = open("data.db","w+")
	    	json_db = json.dumps(database)
	    	f.write(json_db)
	    	f.close()
	    	f = open("users.db", "w+")
	    	json_users = json.dumps(users)
	    	f.write(json_users)
	    	f.close()
	    	break