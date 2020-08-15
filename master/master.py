import socket
import threading
import json
import os
import requests
import time
import re
from configparser import ConfigParser
import _pickle as pickle
from PIL import Image
from io import BytesIO
from math import floor


class MyProtocol:
	"""Definition of a protocol for communication between Worker and Master.
	__________________________________________________________________________________________________________
	|   WORKER'S MESSAGE    |       |                      MASTERS'S RESPONSE                                |
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
		"""Compiles message with GRAB method.

		GRAB method is used by the Worker to request images
		from the master.

		Parameters
		----------
		count : int
			Amount of images to request

		Returns
		-------
		bytes
			Bytes of the message

		"""
		return cls.__compile_generic("GRAB", str(count))

	@classmethod
	def compile_done(cls, text):
		"""Compiles message with DONE method.

		DONE method is used by the Worker to send converted
		text to the Master.

		Parameters
		----------
		twxt : str
			Converted text

		Returns
		-------
		bytes
			Bytes of the message
		"""
		return cls.__compile_generic("DONE", text.encode('unicode-escape').decode("utf-8"))

	@classmethod
	def compile_quit(cls):
		"""Compiles message with QUIT method.

		QUIT method is used by the Worker to tell Master
		that it is shutting down and won't make any more requests.

		Returns
		-------
		bytes
			Bytes of the message
		"""
		return cls.__compile_generic("QUIT", "")

	@classmethod
	def compile_data(cls, data):
		"""Compiles message with DATA method.

		DATA method is used by the Master to send the worker keys
		and images that need to be converted to text.

		Parameters
		----------
		data : dict of (str: PIL.Image)
			Dictionary of key-image pairs

		Returns
		-------
		bytes
			Bytes of the message
		"""
		dumped_data = pickle.dumps(data, -1)
		length = cls.header_size + cls.method_size + len(dumped_data)
		header = str(length).zfill(cls.header_size) + "DATA"
		return header.encode(cls.encoding) + dumped_data

	@classmethod
	def compile_okay(cls):
		"""Compiles message with OKAY method.

		OKAY method is used by the Master to tell the Worker
		that everything went as expected with its last request.

		Returns
		-------
		bytes
			Bytes of the message
		"""
		return cls.__compile_generic("OKAY", "")

	@classmethod
	def compile_nope(cls, why):
		"""Compiles message with NOPE method.

		NOPE method is used by the Master to tell the Worker
		that something went wrong with its last request.

		Attributes
		----------
		why : str
			Describes what went wrong (INVALID_FORMAT, WRONG_KEYS, TIMEOUT, INVALID_RANGE(int int), ALREADY_PROCESSING)

		Returns
		-------
		bytes
			Bytes of the message
		"""
		return cls.__compile_generic("NOPE", why)

	@classmethod
	def parse(cls, message_bytes):
		"""Parses the raw bytes of the message.

		Parameters
		----------
		message_bytes : bytes
			raw bytes of the body of the message

		Returns
		-------
		(str, str)
			Method and body of the message
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
		# Compiles a generic message
		if len(method) != cls.method_size: raise Exception("Illegal length of protocol field.")
		length = cls.header_size + cls.method_size + len(body)
		header = str(length).zfill(cls.header_size)
		message = header + method + body
		return message.encode(cls.encoding)


class Key:
	"""Definition of Omegle's chat log key.

	Each Omegle's chat log has a unique identifier - key
	with which it can be retrieved. Valid key is a padded
	hex number with 5-10 (inclusive) digits.

	Attributes
	----------
	allowed_chars : str
		Allowed characters in a key
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

		Raises
		------
		ValueError
			if illegal characters in a key or it has too many/little characters
		"""
		if not self.__is_allowed(string): raise ValueError("Illegal characters in a key.")
		if not self.__in_range(string): raise ValueError("Key out of range.")

		self.string = string
	
	def add(self, amount):
		"""Adds amount to the key.

		Adds amount to the key like keys would be on a number line starting from
		5-digit key '00000' and ending with 10-digit key 'ffffffffff'

		Parameters
		----------
		amount : int
			Amount to be added to the key

		Examples
		--------
		>>> Key("fffff").add(1)
		Key("000000")
		>>> Key("00000").add(10)
		Key("0000a")

		Raises
		------
		ValueError
			If key is out of range

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
		# Checks if all characters in a key are allowed
		return all(c in cls.allowed_chars for c in key_string)
	
	@classmethod
	def __in_range(cls, key_string):
		# Checks if key is not too short or long
		return cls.size_range[0] <= len(key_string) < cls.size_range[1]
		

class KeyGenerator:
	"""Generates all syntactically valid keys.

	KeyGenerator keeps track of all generated and given keys until they are returnd
	via done(keys) method.

	state_file : str
		.json file where the state of the KeyGenerator can be saved and loaded
	
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
		Clears the state of the KeyGenerator
	"""

	def __init__(self):
		self.__cur_key = Key(Key.size_range[0] * "0") # Next key to be given
		self.__processing = []                        # List of key strings being processed
		self.__to_process = []                        # List of key strings needed to be processed
		self.state_file = "key_gen_state.json"
	
	def get(self, amount):
		"""Gives the specified amount of keys.

		Parameters
		----------
		amount : int
			Amount of keys

		Returns
		-------
		list of str
			String representations of requested amount of keys

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
		"""Marks keys done after they have been processed.

		Parameters
		----------
		keys : list of str
			Key strings to be marked as done

		"""
		self.__processing = [k for k in self.__processing if k not in keys]
	
	def give(self, keys):
		"""Give back keys that were requested, but could not be processed.

		Parameters
		----------
		keys : list of str
			key strings to be given back

		"""
		self.__to_process += keys
		self.done(keys)
	
	def stop_jobs(self):
		"""Moves all keys that are being processed to list where whey will be processed later."""
		self.__to_process += self.__processing
		self.__processing = []
	
	def save_state(self):
		"""Saves the state of the KeyGenerator."""
		state = {
			"cur_key": self.__cur_key.string,
			"processing": self.__processing,
			"to_process": self.__to_process
		}
		with open(self.state_file, "w+") as f:
			json.dump(state, f)
	
	def load_state(self):
		"""Loads the state of the KeyGenerator."""
		state_exists = os.stat(self.state_file).st_size != 0
		if not state_exists: return

		with open(self.state_file, "r+") as f:
			state = json.load(f)
			self.__cur_key = Key(state['cur_key'])
			self.__processing = state['processing']
			self.__to_process = state['to_process']
	
	def clear_state(self):
		"""Clears the state of the KeyGenerator."""
		self.__cur_key = Key(Key.size_range[0] * "0")
		self.__processing = []
		self.__to_process = []
		with open(self.state_file, "w+") as f:
			f.write("")


class ChatImageDownloader:
	"""Downlods images from Omegle's chats and stores them in a pool.

	Attributes
	----------
	base_url : str
		Base url of where to find Omegle's chats
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
		Give back keys that were not processed to underlying KeyGenerator
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
		"""Gets the specified amount of images from the image pool. Waits if it is empty.

		Parameters
		----------
		amount : int
			Amount of images to get

		Returns
		-------
		dict of (str: PIL.Image)
			Dictionary of key and its coresponding image pairs

		"""
		got = {}
		while len(got.keys()) < amount:
			if not self.pool_empty:
				key = list(self.__image_pool.keys())[0]
				image = self.__image_pool.pop(key, None)
				if image: got[key] = image
		return got
	
	def give(self, keys):
		"""Give back the keys of images that were requested, but not processed.

		Parameters
		----------
		keys : list of str
			list of key strings to be given back

		"""
		self.__key_gen.give(keys)
	
	def save_state(self):
		"""Save the state of the underlying KeyGenerator."""
		self.__key_gen.save_state()
	
	def load_state(self):
		"""Loads the state of the underlying KeyGenerator and stops all jobs of KeyGenerator."""
		self.__key_gen.load_state()
		self.__key_gen.stop_jobs()

	def __fill_pool(self):
		"""Constantly fills the pool with images.
		
		Pool might overflow a little bit, because of the many threads working.
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
		"""Starts threads for downloading images.

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


class Worker:	
	"""Handles commuination with Worker.

	Attributes
	----------
	addr : (str, int)
		IP and port number of the Worker
	socket : socket.socket
		Communication channel with Worker
	batch_range : (int, int)
		Range of images a worker can request
	downloader : ChatImageDownloader
		Downloader of chat images
	timeout_per_image : int
		Time in seconds given to Worker to process a single image
	output_file : str
		File where the converted text will be saved
	
	Methods
	-------
	listen()
		Listens for messages in socket and handles them
	"""

	batch_range = (5, 20)
	downloader = ChatImageDownloader(5)
	timeout_per_image = 2
	output_file = "chat_log.txt"

	def __init__(self, socket, addr):
		"""
		Parameters
		----------
		conn : socket.socket
			Worker's socket
		addr : (str, int)
			Address of the Worker
		"""
		self.socket = socket
		self.addr = addr
		self.__processing = []                     # List of keys of images curently being processed
		self.__time_start = None                   # Time when processing a batch started
		self.__monitoring = False                  # Variable to indicate if timeout is being monitored
		self.__timeout_flag = False                # Flag to indicate whether timeout occoured
					
	def listen(self):
		"""Listens to messages"""
		log("CONNECTION", f"{self.addr[0]} connected on port {self.addr[1]}.")

		while True:
			message_bytes = self.__recv_message()
			if not message_bytes: break
			else: self.__handle_message(message_bytes)

		log("DISCONNECTED", f"{self.addr[0]} disconnected.")
		
	def __handle_message(self, message_bytes):
		# Handles a messege received from Worker
		method, body = MyProtocol.parse(message_bytes)

		if method == "GRAB": self.__handle_grab(body)
		elif method == "DONE": self.__handle_done(body)
		elif method == "QUIT": self.__handle_quit()
	
	def __handle_grab(self, amount):
		# Handles a message with GRAB methd
		self.__timeout_flag = False
		if not self.__in_batch_range(amount): resp = MyProtocol.compile_nope(f"INVALID_RANGE({str(self.batch_range)})")
		elif self.__processing: resp = MyProtocol.compile_nope("ALREADY_PROCESSING")
		else:
			images = self.downloader.get(amount)
			self.__time_start = time.time()
			self.__processing = list(images.keys())
			self.__start_monitoring()
			resp = MyProtocol.compile_data(images)

		self.__send(resp)
	
	def __handle_done(self, text):
		# Handles a message with DONE method
		min_size, max_size = Key.size_range
		valid_format_patt = r"^(?:key=[\da-f]{" + f"{min_size}," + f"{max_size-1}" + r"}(?:\n[01]:.*)+\n+)+$"
		key_finding_patt = r"key=([\da-f]{" + f"{min_size}," + f"{max_size-1}" + "})"

		keys_received = re.findall(key_finding_patt, text)
		is_right_keys = all(k in self.__processing for k in keys_received)
		valid_format = re.match(valid_format_patt, text)

		if self.__timeout_flag: resp = MyProtocol.compile_nope("TIMEOUT")
		elif not valid_format: resp = MyProtocol.compile_nope("INVALID_FORMAT")
		elif not is_right_keys: resp = MyProtocol.compile_nope("WRONG_KEYS")
		else:
			self.__save_to_file(text)
			resp = MyProtocol.compile_okay()
			self.__processing = []

		self.__timeout_flag = False
		self.__send(resp)
	
	def __handle_quit(self):
		# Handles a message with QUIT method
		self.downloader.give(self.__processing)
	
	def __save_to_file(self, text):
		with open(self.output_file, "a+") as f:
			f.write(text)
		
	def __send(self, message_bytes):
		# Send message to the Worker
		log("RESPONSE", message_bytes, 60)
		self.socket.sendall(message_bytes)
	
	def __recv_message(self):
		# Receives message defined in MyProtocol
		header_bytes = self.socket.recv(MyProtocol.header_size)
		if not header_bytes: return None
		total_length = int(header_bytes.decode(MyProtocol.encoding))
		message_bytes = self.__recv_all(total_length - MyProtocol.header_size)
		log("REQUEST", header_bytes + message_bytes, 60)
		return message_bytes
		
	def __recv_all(self, length):
		# Receives all data
		packets = floor(length / 60000)
		buff = b""
		for i in range(packets):
			buff += self.socket.recv(60000)
		buff += self.socket.recv(length)
		return buff
	
	def __start_monitoring(self):
		# Starts thread to mintor timeout
		self.__monitoring = True
		self.__monitoring_thread = threading.Thread(target=self.__monitor_timeout)
		self.__monitoring_thread.start()

	def __monitor_timeout(self):
		# Monitors if Worker is processing for too long
		total_timeout = Worker.timeout_per_image * len(self.__processing)
		while self.__monitoring:
			now = time.time()
			elapsed = now - self.__time_start
			if elapsed >= total_timeout:
				self.__handle_timeout()

	def __handle_timeout(self):
		# Handles the timeout
		self.downloader.give(self.__processing)
		self.__timeout_flag = True
		self.__processing = []
		self.__monitoring = False

	@classmethod
	def __in_batch_range(cls, batch_size):
		# Checks if the batch_size is valid
		return cls.batch_range[0] <= batch_size < cls.batch_range[1]


def log(event, msg, restricted_length=-1):
	"""Logs to console.
	
	Parameters
	----------
	event : str
		Event that triggered the message
	msg : str
		Message itself
	restricted_length : int, optional
		Restrict the length of the message. -1 means no restriction.

	"""
	if restricted_length >= 0:
		l = restricted_length
		print(f"[{event}] {msg[:l]}{f'...({len(msg)-l} more bytes)' if len(msg) > l else ''}")
	else:
		print(f"[{event}] {msg}")


def listen(s):
	"""Listens for connections and creates a new Worker for each.

	Parameters
	----------
	s : socket.socket
		Socket to listen to

	"""
	s.listen()
	log("LISTENING", f"Server {s.getsockname()[0]} listening on port {s.getsockname()[1]}...")

	while True:
		conn, addr = s.accept()
		worker = Worker(conn, addr)
		thread = threading.Thread(target=worker.listen)
		thread.start()


def handle_exit(s):
	Worker.downloader.save_state()
	s.shutdown(socket.SHUT_RDWR)
	s.close()
	log("SHUTDOWN", "Server shutting down...")
	exit()


if __name__ == "__main__":
	config = ConfigParser()
	config.read("config.ini")
	ip, port = config["master"]["ip"], int(config["master"]["port"])

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((ip, port))

	Worker.downloader.load_state()

	try:
		listen(s)
	except:
		handle_exit(s)


