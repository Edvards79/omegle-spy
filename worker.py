import pytesseract
import socket
import os
import re
from PIL import Image
import _pickle as pickle
from math import floor

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


class OmegleChatToText:

	"""
	Converts Omegles chat log images to text
	
	Attributes
	----------
	cleanup_pattern : str
		Regex pattern used to split all chat into individual messages
	replacements : dict of (str: str)
		Dictionary of strings that need to be replaced in the text

	Methods
	-------
	convert(image) 
		Converts image to text
	"""

	cleanup_pattern = r"(Stranger:\s|You:\s)(.*?)(?=Stranger:\s|You:\s|$)"
	replacements = {
		"Stranger:": "0:",
		"You:": "1:",
		"Your? (conversational partner )?ha(ve|s) disconnected.*": "",
		"Technical error:.*": "",
		"Stranger has disconnected.*": ""
	}

	def __init__(self):
		pass
	
	@classmethod
	def convert(cls, image):
		"""Converts image to text"""
		text = pytesseract.image_to_string(image)
		pretty_text = cls.__prettify_text(text, cls.cleanup_pattern, cls.replacements)
		return pretty_text
	
	@classmethod
	def __prettify_text(cls, text, cleanup_pattern=None, replacements={}):
		"""
		Makes chat look prettier.

		Parameters
		----------
		cleanup_pattern : str
			Regex pattern used to split chat into individual messages
		replacemnts: dict of (str: str)
			Dictionary specifying what needs to be replaced with what
		"""
		pretty_text = ""
		no_new_lines = re.sub("\n", "", text)
		matches = re.findall(cleanup_pattern, no_new_lines)
		for m in matches:
			pretty_text += f"{m[0]} {m[1]}\n"

		for r in replacements:
			pretty_text = re.sub(r, replacements[r], pretty_text)

		return pretty_text
		

class Master:
	"""
	Handles communication with Master

	Attributes
	----------
	socket : socket.socket
		Master's socket
	addr : (str, int)
		IP address and port of Master
	
	Methods
	-------
	grab(amount)
		Request Master for images
	done(text)
		Send master processed text
	quit()
		Tell master that Worker is quitting
	"""

	def __init__(self, addr):
		"""
		Parameters
		----------
		addr : (str int)
			IP address and port of the master
		"""
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.connect(addr)
		self.addr = addr
	
	def grab(self, amount):
		"""
		Request Master for images.

		Parameters
		----------
		amount : int
			Amount of images to be requested
		"""
		request = MyProtocol.compile_grab(amount)
		self.__send(request)
		method, body = self.__recv_response()
		if method == "NOPE": return self.__handle_grab_error(body, amount)
		return body
	
	def done(self, text):
		"""
		Send Master the proccesed text

		Attributes
		----------
		text : str
			The proccessed text
		"""
		message = MyProtocol.compile_done(text)
		self.__send(message)
		method, body = self.__recv_response()
	
	def quit(self):
		"""Tells Master that worker is quitting"""
		message = MyProtocol.compile_quit()
		self.__send(message)
			
	def __send(self, message):
		"""Sends message to the Master's socket"""
		print(f"[REQUEST] {message[:60]}{f'...({len(message)-60} more bytes)' if len(message) > 60 else ''}")
		self.socket.sendall(message)
	
	def __recv_response(self):
		"""Listens on socket for a message"""
		header_bytes = self.socket.recv(MyProtocol.header_size)
		total_length = int(header_bytes.decode(MyProtocol.encoding))
		message_length = total_length - MyProtocol.header_size
		message_bytes = self.__recv_all(message_length)
		# Log response
		r = header_bytes + message_bytes
		print(f"[RESPONSE] {r[:60]}{f'...({len(r)-60} more bytes)' if len(r) > 60 else ''}")
		method, body = MyProtocol.parse(message_bytes)
		return (method, body)
	
	def __recv_all(self, length):
		"""
		Receive all data from a socket

		Parameters
		----------
		length : int
			length of the message in bytes
		"""
		packets = floor(length / 60000)
		buff = b""
		for i in range(packets):
			buff += self.socket.recv(60000)
		buff += self.socket.recv(length)
		return buff
	
	def __handle_grab_error(self, body, tried_grab):
		"""
		Handles case when response to GRAB request is NOPE

		Parameters
		----------
		body : str
			Body of the message
		tried_grab : int
			Amount of images that were tried to be grabbed
		"""
		if body == "ALREADY_PROCESSING":
			return None

		elif body.startswith("INVALID_RANGE"):
			min_r, max_r = body.replace("INVALID_RANGE", "").replace("(", "").replace(")", "").split()
			min_r, max_r = int(min_r), int(max_r)
			if tried_grab < min_r: return self.grab(min_r)
			elif tried_grab >= max_r: return self.grab(max_r-1)

		else:
			raise Exception("Could not handle grabbing error.")



master_addr = ("127.0.0.1", 8080)
master = Master(master_addr)

def process_images(images):
	buff = ""
	for key in images:
		text = OmegleChatToText.convert(images[key])
		if text: buff += f"key={key}\n" + text + "\n"
	return buff

while True:
	images = master.grab(15)
	text = process_images(images)
	master.done(text)

def exit_handler():
	master.quit()
	master.socket.shutdown(socket.SHUT_RDWR)
	master.socket.close()
	print("[DISCONNECT] Disconnected from the server.")

