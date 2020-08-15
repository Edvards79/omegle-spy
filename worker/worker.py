import pytesseract
import _pickle as pickle
import socket
import os
import re
from configparser import ConfigParser
from math import floor
from PIL import Image

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


class OmegleChatToText:
	"""Converts Omegles chat log images to text
	
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
		"""Converts image to text
		
		Parameters
		----------
		image : PIL.Image
			Image that needs to be converted

		Returns
		-------
		str
			Text that was in the image
		"""
		text = pytesseract.image_to_string(image)
		pretty_text = cls.__prettify_text(text)
		return pretty_text
	
	@classmethod
	def __prettify_text(cls, text):
		# Makes text look prettier
		pretty_text = ""
		no_new_lines = re.sub("\n", "", text)
		matches = re.findall(cls.cleanup_pattern, no_new_lines)
		for m in matches:
			pretty_text += f"{m[0]} {m[1]}\n"

		for r in cls.replacements:
			pretty_text = re.sub(r, cls.replacements[r], pretty_text)

		return pretty_text
		

class Master:
	"""Handles communication with Master.

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
		log("CONNECTED", f"Connected to Master {addr[0]} on port {addr[1]}.")
		self.addr = addr
	
	def grab(self, amount):
		"""Request Master for images.

		If requested amount is not in range defined by Master, the
		amount will be adjusted to be in range.

		Parameters
		----------
		amount : int
			Amount of images to be requested

		Returns
		-------
		dict of (str: PIL.Image)
			Dictionary of key and its corresponding image pairs
		None
			If already have grabbed, but not marked as done
		"""
		request = MyProtocol.compile_grab(amount)
		self.__send(request)
		method, body = self.__recv_response()
		return body if method == "DATA" else self.__handle_grab_error(body, amount)
	
	def done(self, text):
		"""Send Master the proccesed text.

		Attributes
		----------
		text : str
			The proccessed text

		Returns
		-------
		bool
			True if Master told it is validly processed, False otherwise

		"""
		message = MyProtocol.compile_done(text)
		self.__send(message)
		method, body = self.__recv_response()
		return True if method == "OKAY" else False
	
	def quit(self):
		"""Tells Master that Worker is quitting and closes the socket."""
		message = MyProtocol.compile_quit()
		self.__send(message)
		self.socket.shutdown(socket.SHUT_RDWR)
		self.socket.close()
	
	def __send(self, message_bytes):
		# Sends message to the Master's socket
		log("REQUEST", message_bytes, 60)
		self.socket.sendall(message_bytes)
	
	def __recv_response(self):
		# Listens on socket for a message
		header_bytes = self.socket.recv(MyProtocol.header_size)
		total_length = int(header_bytes.decode(MyProtocol.encoding))
		message_length = total_length - MyProtocol.header_size
		message_bytes = self.__recv_all(message_length)
		log("RESPONSE", header_bytes + message_bytes, 60)
		method, body = MyProtocol.parse(message_bytes)
		return (method, body)
	
	def __recv_all(self, length):
		# Receive all data from a socket
		packets = floor(length / 60000)
		buff = b""
		for i in range(packets):
			buff += self.socket.recv(60000)
		buff += self.socket.recv(length)
		return buff
	
	def __handle_grab_error(self, body, tried_grab):
		# Handles case when response to GRAB request is NOPE
		if body == "ALREADY_PROCESSING": return None
		elif body.startswith("INVALID_RANGE"):
			min_r, max_r = body.replace("INVALID_RANGE", "").eval()
			return self.grab(min_r) if tried_grab < min_r else self.grab(max_r-1)
		else: raise Exception("Error occoured in grabbing that could not be handled.")


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


def handle_exit(master):
	"""Tells Master that Worker is qutting"""
	master.quit()
	log("DISCONNECT", "Disconnecting from Master.")
	exit()


def images_to_text(images):
	"""Converts images to text using OmegleChatToText
	
	Parameters
	----------
	images : dict of (str: PIL.Image)
		Images that need to be converted
	
	Returns
	-------
	str
		Text that was converted
	"""
	buff = ""
	for key in images:
		text = OmegleChatToText.convert(images[key])
		if text: buff += f"key={key}\n" + text + "\n"
	return buff


def work(master):
	"""Grabs images from the Master, converts them to text and send text to Master
	
	Parameters
	----------
	master : Master
		Master object

	"""
	while True:
		images = master.grab(15)
		print(f"KEYS RECEIVED: {list(images.keys())}")
		if images:
			text = images_to_text(images)
			master.done(text)


if __name__ == "__main__":
	config = ConfigParser()
	config.read("config.ini")
	ip, port = config["master"]["ip"], int(config["master"]["port"])

	master = Master((ip, port))

	try:
		work(master)
	except:
		handle_exit(master)

