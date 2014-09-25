__author__ = 'patrick'

import os
import sys
import glob
import ctypes
import fnmatch
import hashlib
import platform
import plistlib
import traceback
import subprocess
import ctypes.util

#min supported OS X version
MIN_OS_VERSION = 10.9

#max supported OS X version
MAX_OS_VERSION = 10.9

#global verbose/logging flag
verbose = False

#logging mode; info
MODE_INFO = 'INFO'

#logging mode; error
MODE_ERROR = 'ERROR'

#path to security framework
# ->for validating signatures
SECURITY_FRAMEWORK = '/System/Library/Frameworks/Security.framework/Versions/Current/Security'

#'handle' to loaded security framework
securityFramework = None

#global objcRuntime 'handle'
objcRuntime = None

#from OS X
kSecCSDefaultFlags = 0x0

#from OS X
kSecCSDoNotValidateResources = 0x4

#from OS X
errSecSuccess = 0x0

#from me
SecCSSignatureOK = errSecSuccess

#from OS X
# ->see CSCommon.h
errSecCSUnsigned = -67062

#from OS X
kSecCSSigningInformation = 0x2

#from OS X
kSecCodeInfoCertificates = 'certificates'

#base directory for users
USER_BASE_DIRECTORY = '/Users/'

#apple prefix
__kOSKextApplePrefix = 'com.apple.'

'''
kSecCSCheckAllArchitectures = 1 << 0
kSecCSDoNotValidateExecutable = 1 << 1
kSecCSDoNotValidateResources = 1 << 2
kSecCSBasicValidateOnly = kSecCSDoNotValidateExecutable | kSecCSDoNotValidateResources
kSecCSCheckNestedCode = 1 << 3
'''


#load python <-> Objc bindings
# ->might fail if non-Apple version of python is being used
def loadObjcBindings():

	#imports must be global
	# ->ensures rest of code can access em
	global objc
	global Foundation

	#flag indicating load OK
	loadOK = False

	#wrap
	try:

		#attempt imports
 		import objc
		import Foundation

		#set flag
		# ->load OK
		loadOK = True

	#imports not found
	except ImportError, e:

		#set flag
		# ->load not OK
		loadOK = False

	return loadOK


#set verbose
def initLogging(verbosity):

	#global flag
	global verbose

	#set global flag
	verbose = verbosity

	return True

#display msgs
def logMessage(mode, msg):

	#always display errors
	if MODE_ERROR == mode:

		#display it
		print '%s: %s' % (mode, msg)

	#in verbose mode
	# ->display error
	elif verbose:

		#display it
		print '%s: %s' % (mode, msg)

	return

#check if OS version is supported
def isSupportedOS():

	#flag indicating supported OS
	supportedOS = False

	#get OS version
	version = getOSVersion()

	#make sure version is inbetween min and max
	if MIN_OS_VERSION <= version <= MAX_OS_VERSION:

		#supported
		supportedOS = True

	return supportedOS

#get OS X version
# ->returns is as a float (e.g. 10.9f)
def getOSVersion():

	#get version (as string)
	version, _, _ = platform.mac_ver()

	#return OS version as float
	# ->e.g. 10.9
	return float('.'.join(version.split('.')[:2]))


#get the base directory of KnockKnock
def getKKDirectory():

	#return script's directory
	return os.path.dirname(os.path.realpath(__file__)) + '/'

#load a bundle's Info.plist
def loadInfoPlist(bundlePath):

	#dictionary info
	infoDictionary = None

	#wrap
	# ->had some issues with bundleWithPath_()
	try:

		#get main bundle
		mainBundle = Foundation.NSBundle.bundleWithPath_(bundlePath)
		if mainBundle is not None:

			#get dictionary from Info.plist
			infoDictionary = mainBundle.infoDictionary()

	#ignore
	except:

		pass

	return infoDictionary

#given a loaded plist (e.g. from a bundle)
# ->returns the path of the Info.plist
def getPathFromPlist(loadedPlist):

	#path to plist
	plistPath = None

	#wrap
	try:

		#check for Info plist key
		if 'CFBundleInfoPlistURL' in loadedPlist:

			#extract the path
			plistPath =  loadedPlist['CFBundleInfoPlistURL'].fileSystemRepresentation()

	#ignore
	except:

		pass

	return plistPath


#get a bundle's executable binary
def getBinaryFromBundle(bundlePath):

	#executable's path
	binaryPath = None

	#wrap
	# ->had some issues with bundleWithPath_()
	try:

		#get main bundle
		mainBundle = Foundation.NSBundle.bundleWithPath_(bundlePath)
		if mainBundle is not None:

			#extract executable path
			binaryPath = mainBundle.executablePath()

	#ignore
	except:

		pass

	return binaryPath


#given a list of paths, expand any '~'s into all users
# ->returned paths are checked here to ensure they exist
def expandPaths(paths):

	#expanded paths
	expandedPaths = []

	#iterate over all paths
	for path in paths:

		#check if it needs expanding
		if '~' in path:

			#expand path and insert list
			# ->expanded paths are checked inside function to ensure that they exist
			expandedPaths.extend(expandPath(path))

		#no expansion necessary
		else:

			#make sure file exist
			if os.path.exists(path):

				#add
				expandedPaths.append(path)

	return expandedPaths


#given a a path, expand '~' into all users
def expandPath(path):

	#expanded paths
	expandedPaths = []

	#get all users
	users = getUsers()

	#iterate over all users
	# ->replace '~' in provided path with user's name
	for user in users:

		#expand path
		# ->case where path starts with '~', insert /User and user name
		if path.startswith('~'):

			#expand
			expandedPath = USER_BASE_DIRECTORY + path.replace('~', user)

		#expand path
		# ->case where '~' is in path, just replace with user name
		else:

			#expand
			expandedPath = path.replace('~', user)

		#ignore non-existant directory
		# ->'user' might be a system account (e.g. _spotlight), so won't have 'real' directories/files
		if not os.path.exists(expandedPath):

			#skip
			continue

		#save expanded path
		expandedPaths.append(expandedPath)

	return expandedPaths


#get all users
def getUsers():

	#users
	users = []

	#wrap
	try:

		#init name
		name = Foundation.NSString.stringWithUTF8String_("/Local/Default")

		#init record type
		recordType = Foundation.NSString.stringWithUTF8String_("dsRecTypeStandard:Users")

		#get root session and check result
		# ->note: pass None as first arg for default session
		root = Foundation.ODNode.nodeWithSession_name_error_(None, name, None)

		#make query and check result
		query = Foundation.ODQuery.queryWithNode_forRecordTypes_attribute_matchType_queryValues_returnAttributes_maximumResults_error_(
			root, recordType, None, 0, None, None, 0, None)

		#get results
		results = query.resultsAllowingPartial_error_(0, None)

		#iterate over all
		# ->name is user
		for result in results:

			#get user
			users.append(result.recordName())

	#ignore exceptions
	except Exception, e:

		#ignore
		pass

	return users


#load a plist from a file
def loadPlist(path):

	#load/return
	return Foundation.NSDictionary.dictionaryWithContentsOfFile_(path)

#determine if a bundle is a kext
# ->checks CFBundlePackageType for 'KEXT'
def isKext(path):

	#flag indicating bundle is kext
	bundleIsKext = False

	#wrap
	try:

		#load Info.plist
		infoPlist = loadInfoPlist(path)
		if infoPlist is not None and 'CFBundlePackageType' in infoPlist:

			#extact package type
			packageType = infoPlist['CFBundlePackageType']

			#load plist and check 'CFBundlePackageType' for 'KEXT'
			bundleIsKext = (packageType.upper() == 'KEXT')

	#ignore exceptions
	except Exception, e:

		print e

		#ignore
		pass

	return bundleIsKext

#TODO: memory free'ing?
def checkSignature(file, bundle=None):

	#global security framework 'handle'
	global securityFramework

	#global objcRuntime 'handle'
	global objcRuntime

	#status
	# ->just related to execution (e.g. API errors)
	status = not errSecSuccess

	#signed status of file
	signedStatus = None

	#list of authorities
	authorities = []

	#load security framework
	if not securityFramework:

		#load and check
		securityFramework = ctypes.cdll.LoadLibrary(SECURITY_FRAMEWORK)
		if not securityFramework:

			#err msg
			logMessage(MODE_ERROR, 'could not load securityFramework')

			#bail
			return (status, None, None)

	#load objC runtime lib
	if not objcRuntime:

		#load and check
		objcRuntime = ctypes.cdll.LoadLibrary(ctypes.util.find_library('objc'))
		if not objcRuntime:

			#err msg
			logMessage(MODE_ERROR, 'could not load objcRuntime library')

			#bail
			return (status, None, None)

		#init objc_getClass function's return types
		objcRuntime.objc_getClass.restype = ctypes.c_void_p

		#init sel_registerName function's return types
		objcRuntime.sel_registerName.restype = ctypes.c_void_p

	#file as NSString
	file = Foundation.NSString.stringWithUTF8String_(file)

	#file with spaces escaped
	file = file.stringByAddingPercentEscapesUsingEncoding_(Foundation.NSUTF8StringEncoding).encode('utf-8')

	#init file as url
	path = Foundation.NSURL.URLWithString_(Foundation.NSString.stringWithUTF8String_(file))

	#pointer for static code
	staticCode = ctypes.c_void_p(0)  #ctypes.c_uint64(0)

	#create static code from path and check
	result = securityFramework.SecStaticCodeCreateWithPath(ctypes.c_void_p(objc.pyobjc_id(path)), kSecCSDefaultFlags, ctypes.byref(staticCode))
	if errSecSuccess != result:

		#error
		logMessage(MODE_ERROR, 'SecStaticCodeCreateWithPath(\'%s\') failed with %d' % (path, result))

		#bail
		return (status, None, None)

	#checking the signature of a kext requires the use of a requirement string
	# ->initialize this based on bundle ID
	#   see: checkKextSignature() in security.c (kext_tools) for details
	'''if bundle and isKext(bundle):

		#requirement reference
		# ->used for checking signature of kexts
		#requirementReference = None

		#requirement = None

		#wrap
		try:

			#load kext's plist
			kextPlist = loadPlist(os.path.join(bundle, 'Contents', 'Info.plist'))

			#extract bundle ID
			bundleID = kextPlist['CFBundleIdentifier']

			#set requirement reference for Apple's kexts
			if bundleID.startswith(__kOSKextApplePrefix):

				#set
				requirementReference = "anchor apple"

			#set requirement reference for non-Apple's kexts
			else:

				#set
				requirementReference = "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[field.1.2.840.113635.100.6.1.18]"


			#get NSString class
			NSString = objcRuntime.objc_getClass('NSString')

			#init return type for 'stringWithUTF8String:' method
			objcRuntime.objc_msgSend.restype = ctypes.c_void_p

			#init arg types for 'stringWithUTF8String:' method
			objcRuntime.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

			#init key via 'stringWithUTF8String:' method
			requirementsString = objcRuntime.objc_msgSend(NSString, objcRuntime.sel_registerName('stringWithUTF8String:'), requirementReference)

			#print 'type of requirementsString'
			#print type(requirementsString)

			#pointer for requirement
			requirement = ctypes.c_void_p(0)

			#create sec requirement
			if errSecSuccess != securityFramework.SecRequirementCreateWithString(ctypes.c_void_p(requirementsString), kSecCSDefaultFlags, ctypes.byref(requirement)):

				#print 'ERROR'
				pass
			else:

				pass
				#print 'OK'


			#	print 'ERRROR: SecRequirementCreateWithString()'

			#else:

			#	print 'OK!!'

		#ignore exceptions
		except:

			#ignore
			pass
	'''

	#print 'securityFramework.SecStaticCodeCheckValidity:',
	#print securityFramework.SecStaticCodeCheckValidity(staticCode, 1 << 30, None)

	#check signature
	signedStatus = securityFramework.SecStaticCodeCheckValidityWithErrors(staticCode, kSecCSDoNotValidateResources,
																		  None, None)
	#make sure binary is signed
	# ->then, extract signing authorities
	if errSecSuccess == signedStatus:

		#print 'File is signed!'

		#pointer for info dictionary
		information = ctypes.c_void_p(0)

		#get code signing info, including authorities and check
		result = securityFramework.SecCodeCopySigningInformation(staticCode, kSecCSSigningInformation,
																 ctypes.byref(information))
		if errSecSuccess != result:

			#err msg
			logMessage(MODE_ERROR, 'SecCodeCopySigningInformation() failed with %d' % result)

			#bail
			return (status, None, None)

		#get NSString class
		NSString = objcRuntime.objc_getClass('NSString')

		#init return type for 'stringWithUTF8String:' method
		objcRuntime.objc_msgSend.restype = ctypes.c_void_p

		#init arg types for 'stringWithUTF8String:' method
		objcRuntime.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

		#init key via 'stringWithUTF8String:' method
		key = objcRuntime.objc_msgSend(NSString, objcRuntime.sel_registerName('stringWithUTF8String:'), kSecCodeInfoCertificates)

		#init return type for 'objectForKey:' method
		objcRuntime.objc_msgSend.restype = ctypes.c_void_p

		#init arg types for 'objectForKey:' method
		objcRuntime.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

		#get cert chain from dictionary
		# ->returns NSArray
		certChain = objcRuntime.objc_msgSend(information, objcRuntime.sel_registerName('objectForKey:'), key)

		#init return type for 'count:' method
		objcRuntime.objc_msgSend.restype = ctypes.c_uint

		#init arg types for 'count' method
		objcRuntime.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

		#get number of items in array
		count = objcRuntime.objc_msgSend(certChain, objcRuntime.sel_registerName('count'))

		#init pointer for cert name(s)
		certName = ctypes.c_char_p(0)

		#get all certs
		for index in range(count):

			#init return type for 'objectAtIndex:' method
			objcRuntime.objc_msgSend.restype = ctypes.c_void_p

			#init arg types for 'objectAtIndex:' method
			objcRuntime.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]

			#extract cert from array
			cert = objcRuntime.objc_msgSend(certChain, objcRuntime.sel_registerName('objectAtIndex:'), index)

			#get cert's common name and check
			result = securityFramework.SecCertificateCopyCommonName(ctypes.c_void_p(cert), ctypes.byref(certName))
			if errSecSuccess != result:

				#just try next
				continue

			#init return type for 'UTF8String' method
			objcRuntime.objc_msgSend.restype = ctypes.c_char_p

			#init arg types for 'UTF8String' method
			objcRuntime.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

			#extract cert name and append to list
			# ->this is the authority
			authorities.append(objcRuntime.objc_msgSend(certName, objcRuntime.sel_registerName('UTF8String')))

		#TODO: CFRelease information

	#no errors
	# ->might be unsigned though
	status = errSecSuccess

	return (status, signedStatus, authorities)

#parse a bash file (yes, this is a hack and needs to be improved)
# ->returns a list of all commands that are not within a function
#   see http://tldp.org/LDP/abs/html/functions.html for info about bash functions
def parseBashFile(filePath):

	#list of commands
	commands = []

	#flag indicating code is in function
	inFunction = False

	#number of brackets
	bracketCount = 0

	#wrap
	try:

		#open
		with open(filePath, mode='r') as file:

			#read lines
			lines = file.readlines()

	#just bail on error
	except:

		#bail with empty commands
		return commands

	#parse each line
	# ->looking for commands that aren't commented out, and that are not within a function
	for index in range(0, len(lines)):

		#strip line
		strippedLine = lines[index].strip()

		#skip blank lines
		if not strippedLine:

			#skip
			continue

		#skip comments
		if strippedLine.startswith('#'):

			#skip
			continue

		#keep count of '{' and '{'
		if strippedLine.startswith('{'):

			#inc
			bracketCount += 1

		#keep count of '{' and '{'
		if strippedLine.startswith('}'):

			#dec
			bracketCount -= 1

		#check if in function
		# ->ignore all commands, though care about end of function
		if inFunction:

			#check for end of function
			if strippedLine.startswith('}') and 0 == bracketCount:

				#end of function
				inFunction = False

			#go on
			continue

		#check for function start
		# -> a line ends with () with { on next line
		if strippedLine.endswith('()') and index != len(lines) - 1 and lines[index+1].strip().startswith('{'):

			#entered function
			inFunction = True

			#go on
			continue

		#check for function start
		# -> a line ends with () {
		if "".join(strippedLine.split()).endswith('(){'):

			#inc
			bracketCount += 1

			#entered function
			inFunction = True

			#go on
			continue

		#ok, got a command, not in a function
		commands.append(strippedLine)

	return commands


def findBundles(startDirectory, pattern, depth):

	#list of files
	matchedBundles = []

	#initial depth of starting dir
	# simply count '/'
	initialDepth = startDirectory.count(os.path.sep)

	#get all directories under directory
	# ->walk top down, so depth checks work
	for root, dirnames, filenames in os.walk(startDirectory, topdown=True):

		#check depth
		# ->null out remaining dirname if depth is hit
		if root.count(os.path.sep) - initialDepth >= depth:

			#null out
			dirnames[:] = []

		#filter directories
		# ->want a bundle that matches the pattern
		for dir in dirnames:

			#full path
			fullPath = os.path.join(root, dir)

			#check if matches patter and is a bundle
			if pattern in dir and Foundation.NSBundle.bundleWithPath_(fullPath):

				#save
				matchedBundles.append(fullPath)

	return matchedBundles


#get all installed apps
# ->invokes system_profiler/SPApplicationsDataType
def getInstalledApps():

	#list of apps
	installedApps = None

	#wrap
	try:

		#get info about all installed apps via 'system_profiler'
		# ->(string)output is read in as plist
		systemProfileInfo = plistlib.readPlistFromString(subprocess.check_output(['system_profiler', 'SPApplicationsDataType', '-xml']))

		#get all installed apps
		# ->under '_items' key
		installedApps = systemProfileInfo[0]['_items']

	#exception
	except Exception, e:

		#reset
		installedApps = None

		#err msg
		#logMessage(MODE_ERROR, '\n EXCEPTION, %s() threw: %s' % (sys._getframe().f_code.co_name, e))
		#traceback.print_exc()

	return installedApps




#recursively find files
# from: http://stackoverflow.com/questions/2186525/use-a-glob-to-find-files-recursively-in-python
'''
def findFiles(startDirectory, pattern, depth):

	#initial depth of starting dir
	# simply count '/'
	initialDepth = startDirectory.count(os.path.sep)

	#list of all files
	files = []

	#list of files
	matchedFiles = []

	#get all files under directory
	for root, dirnames, filenames in os.walk(startDirectory, topdown=True):

		print 'ROOT: ' + root
		if root.count(os.path.sep) - initialDepth == depth:

			#files += [os.path.join(root, d) for d in dirnames]
			dirnames[:] = []

		print 'DIRS: %s' % dirnames
		print filenames
		#get all files that match
		for filename in fnmatch.filter(filenames, pattern):

			#save em
			matchedFiles.append(os.path.join(root, filename))

	#print matchedFiles

	return matchedFiles
'''

#hash (MD5) a file
# from: http://stackoverflow.com/questions/7829499/using-hashlib-to-compute-md5-digest-of-a-file-in-python-3
def md5sum(filename):

	#md5 hash
	digest = None

	#wrap
	try:

		#open
		with open(filename, mode='rb') as f:

			#init hash
			d = hashlib.md5()

			#read in/hash
			while True:

				#read in chunk
				buf = f.read(4096)

				#eof?
				if not buf:
					#bail
					break

				#update
				d.update(buf)

			#grab hash
			digest = unicode(d.hexdigest())

	#exception
	except Exception, e:

		#reset
		digest = None

	return digest


