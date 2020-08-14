import socket
import signal
import _pickle as pickle
import threading
from io import BytesIO
from PIL import Image
import json
import os
import requests
import time
import re



class MyProtocol:

	"""
	A class for defining protocol for commuinacation between Worker and Master
	__________________________________________________________________________________________________________
	|   WORKER'S MESSAGE    |       |                      SERVER'S RESPONSE                                 |
	|-----------------------|       |------------------------------------------------------------------------|
	|header | method | body |       | header  |  method     |                 body                           |
	|-----------------------|       |------------------------------------------------------------------------|
	|length    GRAB    count|   ->  |length    DATA/NOPE    data/ALREADY_PROCESSING/INVALID_RANGE(int int)   |
	|length    DONE    text |   ->  |length    OKAY/NOPE    None/TIMEOUT/INVALID_FORMAT/WRONG_KEYS           |
	|length    QUIT         |   ->  |                                                                        |
	----------------------------------------------------------------------------------------------------------


	Attributes
	----------
	header_size : int
		Size of the header field in bytes
	method_size : int
		Size of the method field in bytes
	encoding : str
		Encoding used to encode and decode messages
	
	Methods
	-------
	compile_grab(count)
		Compile workers's request message for new images to process
	compile_done(text)
		Compile worker's message to send converted text
	compile_quit()
		Compile worker's message to tell it is quitting
	
	compile_data(images)
		Compile server's message to send images to worker
	compile_okay()
		Compile server's message to tell that everything went okay
	compile_nope(why)
		Compile server's message to tell that something went wrong
	
	parse(bytes)
		parse the body of the message
	"""

	header_size = 32
	method_size = 4
	encoding = "utf-8"

	def __init__():
		pass
	
	@classmethod
	def compile_grab(cls, count):
		"""
		Compiles message with GRAB method

		Parameters
		----------
		count : int
			amount of images to request
		"""
		return cls.__compile_generic("GRAB", str(count))

	@classmethod
	def compile_done(cls, text):
		"""
		Compiles message with DONE method

		Parameters
		----------
		twxt : str
			Converted text
		"""
		return cls.__compile_generic("DONE", text.encode('unicode-escape').decode("utf-8"))

	@classmethod
	def compile_quit(cls):
		"""
		Compiles message with QUIT method
		"""
		return cls.__compile_generic("QUIT", "")

	@classmethod
	def compile_data(cls, data):
		"""
		Compiles message with DATA method

		Parameters
		----------
		data : dic of (str: PIL)
			Dictionary of key image pairs
		"""
		dumped_data = pickle.dumps(data, -1)
		length = cls.header_size + cls.method_size + len(dumped_data)
		header = str(length).zfill(cls.header_size) + "DATA"
		return header.encode(cls.encoding) + dumped_data

	@classmethod
	def compile_okay(cls):
		"""
		Compiles message with OK method
		"""
		return cls.__compile_generic("OKAY", "")

	@classmethod
	def compile_nope(cls, why):
		"""
		Compiles message with NOPE method

		Attributes
		----------
		why : str
			Describes what went wrong (INVALID_FORMAT, WRONG_KEYS, TIMEOUT, INVALID_RANGE(int int), ALREADY_PROCESSING)
		"""
		return cls.__compile_generic("NOPE", why)

	@classmethod
	def parse(cls, message_bytes):
		"""
		Parses the body of the message.

		Parameters
		----------
		message_body_bytes : bytes
			raw bytes of the body of the message
		"""
		splitat = cls.method_size
		method, body = message_bytes[:splitat], message_bytes[splitat:]	
			
		# Decode method 
		method = method.decode(cls.encoding)
		
		# Decode body
		if method == "DATA": body = pickle.loads(body)
		elif method == "DONE": body = body.decode('unicode-escape')
		else: body = body.decode(cls.encoding)

		if method == "GRAB": body = int(body)

		return (method, body)
	
	@classmethod
	def __compile_generic(cls, method, body):
		"""
		Compiles generic message

		Parameters
		----------
		method : str
			method to use
		body : str
			body of the message
		"""
		if len(method) != cls.method_size: raise Exception("Illegal length of protocol field.")
		length = cls.header_size + cls.method_size + len(body)
		header = str(length).zfill(cls.header_size)
		message = header + method + body
		return message.encode(cls.encoding)

class Key:

	"""
	Class defining omegle's chat log's key.
	Valid key is a padded hex number with 5-10 digits.

	Attributes
	----------
	allowed_chars : str
		string of allowed characters in a key
	size_range : (int, int)
		Max and min size of the key
	string : str
		String representation of the key
	
	Methods
	-------
	add(amount)
		Adds amount to the key
	inc()
		Increments the key by one
	"""

	allowed_chars = "0123456789abcdef"
	size_range = (5, 11)

	def __init__(self, string):
		"""
		Parameters
		----------
		string : str
			String representation of the key
		"""
		if not self.__is_allowed(string): raise ValueError("Illegal characters in a key.")
		if not self.__in_range(string): raise ValueError("Key out of range.")

		self.string = string
	
	def add(self, amount):
		"""
		Adds to the key the amount like keys would be on a number line starting from
		5-digit key '00000' and ending with 10-digit key 'ffffffffff'

		e.g.
		"fffff".add(1) -> "000000"
		"ffffe".add(1) -> "fffff"

		Parameters
		----------
		amount : int
			Amount to be added to the key
		"""
		int_num = int(self.string, 16) + amount
		hex_str = format(int_num, "x")
		padded = hex_str.zfill(len(self.string))
		
		# if overflow occours e.g "fffff".add(1) = "000000"
		if len(padded) != len(self.string):
			padded = "0" * len(padded)

		if not self.__in_range(padded): raise ValueError("Key out of range.")

		self.string = padded
	
	def inc(self):
		"""Increments key"""
		self.add(1)
	
	@classmethod
	def __is_allowed(cls, key_string):
		"""Checks if all characters in a key are allowed"""
		return all(c in cls.allowed_chars for c in key_string)
	
	@classmethod
	def __in_range(cls, key_string):
		"""Checks if key is not too short or long"""
		return cls.size_range[0] <= len(key_string) < cls.size_range[1]
		


class KeyGenerator:
	"""
	Generates all syntactically valid keys, but does not check if chats exists at given keys

	KeyGenerator is stateful and keeps track of all given keys. When keys are done processing,
	they should be marked as done using done(keys) method

	state_file : str
		.json file where the state of the KeyGenerator will be saved
	
	Methods
	-------
	get(amount)
		Get specified amount of keys
	done(keys)
		Mark keys as done
	give(keys)
		Give back keys which could not have been processed
	stop_jobs()
		Moves all keys that are being processed to list where whey will be processed later
	save_state()
		Saves all the attributes in a .json file
	load_state()
		Loads all attributes from a .json file
	clear_state()
		Clears the state of the program
	"""

	def __init__(self):
		self.__cur_key = Key(Key.size_range[0] * "0") # Next key to be given
		self.__processing = []                        # List of key strings being processed
		self.__to_process = []                        # List of key strings needed to be processed
		self.state_file = "KeyGenState.json"
	
	def get(self, amount):
		"""
		Gives the specified amount of keys

		Parameters
		----------
		amount : int
			amount of keys
		"""
	
		diff = len(self.__to_process) - amount

		# Amount of keys to get from self.__to_process
		from_to_process = amount if (diff > 0) else len(self.__to_process)

		# Take keys from self.__to_process
		keys = self.__to_process[:from_to_process]
		self.__to_process = self.__to_process[from_to_process:]

		# Generate new keys if self.__to_process didn't have enough
		for i in range(amount - from_to_process):
			keys.append(self.__cur_key.string)
			self.__cur_key.inc()
		
		self.__processing += keys
		return keys
	
	def done(self, keys):
		"""
		Marks keys done after they have been processed

		Parameters
		----------
		keys : list of str
			key strings to be marked as done
		"""
		self.__processing = [k for k in self.__processing if k not in keys]
	
	def give(self, keys):
		"""
		Give back requested keys if they have not been processed

		Parameters
		----------
		keys : list of str
			key strings to be given back
		"""
		self.__to_process += keys
		self.done(keys)
	
	def stop_jobs():
		"""Moves all keys that are being processed to list where whey will be processed later"""
		self.__to_process += self.__processing
		self.__processing = []
	
	def save_state(self):
		"""Saves the state of the KeyGenerator"""
		state = {
			"cur_key": self.__cur_key.string,
			"processing": self.__processing,
			"to_process": self.__to_process
		}
		with open(self.state_file, "w+") as f:
			json.dump(state, f)
	
	def load_state(self):
		"""Loads the state of the KeyGenerator"""
		state_exists = os.stat(self.state_file).st_size != 0
		if not state_exists: return

		with open(self.state_file, "r+") as f:
			state = json.load(f)
			self.__cur_key = Key(state['cur_key'])
			self.__processing = state['processing']
			self.__to_process = state['to_process']
	
	def clear_state(self):
		"""Clears the state of the KeyGenerator"""
		self.__cur_key = Key(Key.size_range[0] * "0")
		self.__processing = []
		self.__to_process = []
		with open(self.state_file, "w+") as f:
			f.write("")


class ChatImageDownloader:
	"""
	Downlods images from Omegle's chats and stores them in a pool

	Attributes
	----------
	base_url : str
		Base url of where ot find Omegle's chats
	max_pool_size : int
		Max amount of images stored at a time
	pool_size : int
		Current size of the pool
	pool_empty : bool
		Is pool empty
	pool_full : bool
		Is pool full
	
	Methods
	-------
	get(amount)
		Get specified amount of images
	give(keys)
		Give back keys of images that were not processed
	save_state()
		Saves the state of the underlying KeyGenerator
	load_state()
		Loads the state of the underlying KeyGenerator and stops all jobs of KeyGenerator
	"""

	base_url = "http://l.omegle.com/"
	max_pool_size = 10

	def __init__(self, thread_count):
		"""
		Parameters
		----------
		thread_count : int
			Amount of worker threads to download images
		"""
		self.__image_pool = {}
		self.__key_gen = KeyGenerator()
		self.__threads = []
		self.__start_threads(thread_count)
	
	def get(self, amount):
		"""
		Gets the specified amount of images from the image pool. Waits if it is empty.

		Parameters
		----------
		amount : int
			Amount of images to get
		"""
		got = {}
		while len(got.keys()) < amount:
			if not self.pool_empty:
				key = list(self.__image_pool.keys())[0]
				image = self.__image_pool.pop(key, None)
				if image: got[key] = image
		return got
	
	def give(self, keys):
		"""
		Give back the keys of images that were requested, but not processed

		Parameters
		----------
		keys : list of str
			list of key strings to be given back
		"""
		self.__key_gen.give(keys)
	
	def save_state(self):
		"""Save the state of the underlying KeyGenerator"""
		self.__key_gen.save_state()
	
	def load_state(self):
		"""
		Loads the state of the underlying KeyGenerator and stops all jobs of KeyGenerator
		"""
		self.__key_gen.load_state()
		self.__key_gen.stop_jobs()

	def __fill_pool(self):
		"""
		Constantly fills the pool with images.
		"""
		while True:
			while not self.pool_full:
				key = self.__key_gen.get(1)[0]
				full_url = ChatImageDownloader.base_url + key + ".png"
				response = requests.get(full_url)
				if response.status_code == 200:
					img = Image.open(BytesIO(response.content))
					self.__image_pool[key] = img
				self.__key_gen.done([key])
	
	def __start_threads(self, count):
		"""
		Starts threads for downloading images

		Parameters
		----------
		count : int
			Amount of threads to use for downloading images
		"""
		for _ in range(count):
			t = threading.Thread(target=self.__fill_pool)
			t.start()
			self.__threads.append(t)
		
	@property
	def pool_size(self):
		"""Size of the pool"""
		return len(self.__image_pool)
	
	@property
	def pool_empty(self):
		"""Is pool empty"""
		return self.pool_size == 0
	
	@property
	def pool_full(self):
		"""Is pool full"""
		return self.pool_size >= ChatImageDownloader.max_pool_size




downloader = ChatImageDownloader(5)


class Worker:
	
	"""
	Handles all communications with the worker

	Attributes
	----------
	batch_range : (int, int)
		Max number of images a worker can request
	addr : (str, int)
		IP and port number of the Worker
	socket : socket.socket
		Communication channel with Worker
	time_start : time
		Time at which worker started processing the last batch of images
	processing : list of str
		List of keys of images Worker is currently processing
	image_timeout : int
		Time in seconds given to Workers to process a single image
	
	Methods
	-------
	listen()
		Listens for messages in socket and handles them
	"""

	batch_range = (5, 20)
	image_timeout = 2

	def __init__(self, conn, addr):
		"""
		Parameters
		----------
		conn : socket.socket
			Worker's socket
		addr : (str, int)
			Address of the Worker
		"""

		self.conn = conn                  # Socket object
		self.addr = addr                  # Address of the worker
		self.time_start = None            # Time when processing a batch started
		self.processing = []              # List of keys of images curently being processed
		self.__monitoring = False         # Variable to indicate if timeout is being monitored
		self.__monitoring_thread = None   # Thread which monitors the timeout
		self.__timeout_occoured = False   # Flag to indicate whether timeout occoured
					
	def listen(self):
		"""Listens to messages"""
		print(f"[CONNECTION] {self.addr[0]} connected on port {self.addr[1]}.")
		while True:
			header_bytes = self.conn.recv(MyProtocol.header_size)
			if not header_bytes: break
			total_length = int(header_bytes.decode(MyProtocol.encoding))
			message_bytes = self.conn.recv(total_length - MyProtocol.header_size)
			r = header_bytes + message_bytes
			print(f"[REQUEST] {r[:60]}{f'...({len(r)-60} more bytes)' if len(r) > 60 else ''}")
			self.__handle(message_bytes)
		print(f"[DISCONNECTED] {self.addr[0]} disconnected.")
		
	def __handle(self, message_bytes):
		"""
		Handles a messege received from Worker

		Parameters
		----------
		message_bytes : bytes
			Encoded message
		"""
		method, body = MyProtocol.parse(message_bytes)

		if method == "GRAB":
			self.__timeout_occoured = False
			if not self.__in_batch_range(body):
				valid_range = " ".join([str(i) for i in Worker.batch_range])
				resp = MyProtocol.compile_nope(f"INVALID_RANGE({valid_range})")

			elif self.processing:
				resp = MyProtocol.compile_nope("ALREADY_PROCESSING")

			else:
				images = downloader.get(body)
				self.time_start = time.time()
				self.processing = list(images.keys())
				self.__start_monitoring()
				resp = MyProtocol.compile_data(images)

			self.__send(resp)
			
		elif method == "DONE":
			min_size, max_size = Key.size_range
			valid_format_patt = r"^(?:key=[\da-f]{" + f"{min_size}," + f"{max_size-1}" + r"}(?:\n[01]:.*)+\n+)+$"
			key_finding_patt = r"key=([\da-f]{" + f"{min_size}," + f"{max_size-1}" + "})"
			keys_received = re.findall(key_finding_patt, body)
			valid_format = re.match(valid_format_patt, body)

			if self.__timeout_occoured:
				resp = MyProtocol.compile_nope("TIMEOUT")
				self.__timeout_occoured = False

			elif not valid_format:
				resp = MyProtocol.compile_nope("INVALID_FORMAT")

			elif not all(k in self.processing for k in keys_received):
				resp = MyProtocol.compile_nope("WRONG_KEYS")


			else:
				resp = MyProtocol.compile_okay()
				self.processing = []

			self.__send(resp)

		elif method == "QUIT":
			downloader.give(self.processing)
	
	def __send(self, message_bytes):
		"""
		Send message to the Worker

		Parameters
		----------
		message_bytes : bytes
			Encoded message
		"""
		r = message_bytes
		print(f"[RESPONSE] {r[:60]}{f'...({len(r)-60} more bytes)' if len(r) > 60 else ''}")
		self.conn.sendall(message_bytes)
	
	def __start_monitoring(self):
		"""Starts thread to mintor timeout"""
		self.__monitoring = True
		self.__monitoring_thread = threading.Thread(target=self.__monitor_timeout)
		self.__monitoring_thread.start()

	def __monitor_timeout(self):
		"""Monitors if Worker is processing for too long"""
		total_timeout = Worker.image_timeout * len(self.processing)
		while self.__monitoring:
			now = time.time()
			elapsed = now - self.time_start
			if elapsed >= total_timeout:
				self.__handle_timeout()

	def __handle_timeout(self):
		"""Handles the timeout"""
		downloader.give(self.processing)
		self.__timeout_occoured = True
		self.processing = []
		self.time_start = None
		self.__monitoring = False

	@classmethod		
	def __in_batch_range(cls, batch_size):
		"""
		Checks if the batch_size is valid

		Parameters
		----------
		batch_size : int
			Size of the batch
		"""
		return cls.batch_range[0] <= batch_size < cls.batch_range[1];
	


master_addr = ("127.0.0.1", 8080)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(master_addr)

def exit_handler():
	server.shutdown(socket.SHUT_RDWR)
	server.close()
	print("[SHUTDOWN] Server has been shut down.")

def listen():
	s.listen()
	print(f"Server {master_addr[0]} listening on port {master_addr[1]}...")
	
	while True:
		conn, addr = s.accept()
		worker = Worker(conn, addr)
		thread = threading.Thread(target=worker.listen)
		thread.start()

listen()
