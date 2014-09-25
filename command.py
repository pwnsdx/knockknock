__author__ = 'patrick'

import json

#project imports
import whitelist

class Command():

	#init method
	# ->save command and set white list flag
	def __init__(self, command):

		#save command
		self.command = command

		#init whitelist flag
		# ->simply set to True if command is list of whitelisted commands
		self.isWhitelisted = (self.command in whitelist.whitelistedCommands)

		return

	#TODO: is this used?
	#for json output
	def __repr__(self):

		#return obj as JSON string
		return json.dumps(self.__dict__)

	#for normal output
	def prettyPrint(self):

		return '%s\n' % (self.command)