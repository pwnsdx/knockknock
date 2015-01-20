__author__ = 'patrick'

import os
import json

#project imports
import utils
import whitelist

#apple signing authorities
APPLE_AUTHORITIES = ['Apple Code Signing Certification Authority', 'Apple Root CA']

class File():

	#init method
	# ->init instance variables, hash file, etc
	def __init__(self, path, plist=None, parent=None):

		#init path for bundle
		self.bundle = None

		#if its a directory (e.g. an app bundle)
		# ->get binary (from app's Info.plist)
		if os.path.isdir(path):

			#save bundle path
			self.bundle = path

			#get path
			self.path = utils.getBinaryFromBundle(path)

			#if binary could not be found
			# ->default to 'unknown'
			if not self.path:

				#just set to something...
				self.path = '<unknown>'

		#path is to file
		# ->just save into class var
		else:

			#save
			self.path = path

		#convert file path to utf-8 if needed
		if isinstance(self.path, unicode):

			#convert
			self.path = self.path.encode('utf-8')

		#save plist
		# ->this will be set for launch daemons/agents, inserted dylibs, etc
		self.plist = plist

		#compute/save name
		self.name = os.path.split(self.path)[1]

		#compute/save hash
		self.hash = utils.md5sum(self.path)

		#init whitelist flag
		self.isWhitelisted = False

		#check if its whitelisted
		# ->path is key
		if self.path in whitelist.whitelistedFiles:

			#check if hash is in white list
		 	self.isWhitelisted = (self.hash in whitelist.whitelistedFiles[self.path])

		#init
		self.signatureStatus = None

		#init signing authorities
		self.signingAuthorities = None

		#check if signed and if so, by apple
		# note: sets class's signatureStatus and signingAuthorities iVars
		self.initSigningStatus()

		return

	#return file's path
	def path(self):

		#path
		return self.path

	#return file's name
	def name(self):

		#name
		return self.name

	#return hash
	def hash(self):

		#hash
		return self.hash

	#for normal output
	def prettyPrint(self):

		signedMsg = ''

		#handle case where hash was unable to be generated
		# ->file wasn't found/couldn't be accessed
		if not self.hash:

			#set some default
			self.hash = 'unknown'

		#handle when file is signed
		if 0 == self.signatureStatus:

			#yup
			signedMsg = 'yes'

			#add signing auth's
			if len(self.signingAuthorities):

				#add
				signedMsg += ' (%s)' % self.signingAuthorities

		#handle when file is not signed
		elif self.signatureStatus:

			#no
			signedMsg = 'no (%d)' % self.signatureStatus

		#error case
		# ->couldn't check signature
		else:

			#unknown
			signedMsg = 'unknown'


		#non-plisted files
		if not self.plist:

			return '\n%s\n path: %s\n hash: %s\n signed? %s\n' % (self.name, self.path, self.hash, signedMsg)

		#plisted files
		else:

			return '\n%s\n path: %s\n plist: %s\n hash: %s \n signed? %s\n' % (self.name, self.path, self.plist, self.hash, signedMsg)


	#determine if a file (or bundle) is signed, and if so, by Apple
	def initSigningStatus(self):

		#default path to check as file's path
		path = self.path

		#however for kexts, use their bundle
		# ->this avoids issue with where errSecCSInfoPlistFailed is returned when the kext's binary is checked
		if self.bundle and utils.isKext(self.bundle):

			#set path to bundle
			path = self.bundle

		#check the signature
		(status, self.signatureStatus, self.signingAuthorities) = utils.checkSignature(path, self.bundle)

		#check
		if 0 != status:

			#reset
			self.signatureStatus = None

			#reset
			self.signingAuthorities = []

		return

	#check if a file is signed by Apple
	def signedByApple(self):

		#check that file is signed and is signed by apple
		return self.signatureStatus == utils.SecCSSignatureOK and all(x in self.signingAuthorities for x in APPLE_AUTHORITIES)
