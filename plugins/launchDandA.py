__author__ = 'patrick w'

'''
launch daemons and agents

    launch daemons and agents are binaries that can be automatically loaded by the OS (similar to Windows services)

    this plugin parses all plists within the OS's and users' launchd daemon/agent directories and extracts
    all auto-launched daemons/agents
'''

import os
import glob

#project imports
import file
import utils

#plugin framework import
from yapsy.IPlugin import IPlugin

#directories for launch daemons
LAUNCH_DAEMON_DIRECTORIES = ['/System/Library/LaunchDaemons/', '/Library/LaunchDaemons/']

#directories for launch agents
LAUNCH_AGENTS_DIRECTORIES = ['/System/Library/LaunchAgents/', '/Library/LaunchAgents/', '~/Library/LaunchAgents/']

#for output, item name
LAUNCH_DAEMON_NAME = 'Launch Daemons'

#for output, description of items
LAUNCH_DAEMON_DESCRIPTION = 'Non-interactive daemons that are executed by Launchd'

#for output, item name
LAUNCH_AGENT_NAME = 'Launch Agents'

#for output, description of items
LAUNCH_AGENT_DESCRIPTION = 'Interactive agents that are executed by Launchd'

#(base) directory that has overrides for launch* and apps
OVERRIDES_DIRECTORY = '/private/var/db/launchd.db/'


#TODO: malware could abuse 'WatchPaths' 'StartOnMount' 'StartInterval', etc....
#     for now, we just look for the basics ('RunAtLoad' and 'KeepAlive')

class scan(IPlugin):

	#disabled items
	disabledItems = []

	#init results dictionary
	# ->item name, description, and list
	def initResults(self, name, description):

		#results dictionary
		return {'name': name, 'description': description, 'items': []}

	#invoked by core
	def scan(self):

		#results
		results = []

		#dbg msg
		utils.logMessage(utils.MODE_INFO, 'running scan')

		#init results
		# ->for launch daemons
		results.append(self.initResults(LAUNCH_DAEMON_NAME, LAUNCH_DAEMON_DESCRIPTION))

		#init results
		# ->for launch agents
		results.append(self.initResults(LAUNCH_AGENT_NAME, LAUNCH_AGENT_DESCRIPTION))

		#init disabled items
		# ->scans overrides plists
		self.disabledItems = self.getDisabledItems()

		#scan for auto-run launch daemons
		# ->save in first index of array
		results[0]['items'] = self.scanLaunchItems(LAUNCH_DAEMON_DIRECTORIES)

		#scan for auto-run launch agents
		# ->save in second index of array
		results[1]['items'] = self.scanLaunchItems(LAUNCH_AGENTS_DIRECTORIES)

		return results

	#scan either launch agents or daemons
	# ->arg is list of directories to scan
	def scanLaunchItems(self, directories):

		#launch items
		launchItems = []

		#results
		results = []

		#expand directories
		# ->ensures '~'s are expanded to all user's
		directories = utils.expandPaths(directories)

		#get all files (plists) in launch daemon/agent directories
		for directory in directories:

			#dbg msg
			utils.logMessage(utils.MODE_INFO, 'scanning %s' % directory)

			#get launch daemon/agent
			launchItems.extend(glob.glob(directory + '*'))

		#process
		# ->get all auto-run launch services
		autoRunItems = self.autoRunBinaries(launchItems)

		#iterate over all auto-run items (list of the plist and the binary)
		# ->create file object and add to results
		for autoRunItem in autoRunItems:

			#create and append
			results.append(file.File(autoRunItem[0], autoRunItem[1]))

		return results


	#given a list of (launch daemon/agent) plists
	# ->return a list of their binaries that are set to auto run
	#   this is done by looking for 'RunAtLoad' &&/|| 'KeepAlive' set to true
	def autoRunBinaries(self, plists):

		#auto run binaries
		autoRunBins = []

		#iterate over all plist
		# ->check 'RunAtLoad' (for true) and then extract the first item in the 'ProgramArguments'
		for plist in plists:

			#wrap
			try:

				#program args from plist
				programArguments = []

				#load plist
				plistData = utils.loadPlist(plist)

				#skip files that couldn't be loaded
				if not plistData:

					#skip
					continue

				#skip disabled launch items
				if 'Label' in plistData and plistData['Label'] in self.disabledItems:

					#skip
					continue

				#skip binaries that aren't auto run
				if not 'RunAtLoad' in plistData or not plistData['RunAtLoad']:

					#launch items can also be started with just 'KeepAlive'
					# ->so if 'RunAtLoad' wasn't found, check for this too
					if not 'KeepAlive' in plistData or not plistData['KeepAlive']:

						#skip
						# ->neither 'RunAtLoad' nor 'KeepAlive' is set
						continue

				#check for 'ProgramArguments' key
				if 'ProgramArguments' in plistData:

					#extract program arguments
					programArguments = plistData['ProgramArguments']

					#skip funky args
					if len(programArguments) < 1:

						#skip
						continue

					#extract launch item's binary
					# ->should be first item in args array
					binary = programArguments[0]

					#skip files that aren't found
					# ->e.g firmwaresyncd
					if not os.path.isfile(binary):

						#skip
						continue

				#also check for 'Program' key
				# ->e.g. /System/Library/LaunchAgents/com.apple.mrt.uiagent.plist
				elif 'Program' in plistData:

					#extract binary
					binary = plistData['Program']

					#skip files that aren't found
					# ->e.g firmwaresyncd
					if not os.path.isfile(plistData['Program']):

						#skip
						continue

				#save extracted launch daemon/agent binary
				if binary:

					#save
					autoRunBins.append([binary, plist])

			#ignore exceptions
			except Exception, e:

				#ignore
				pass

		return autoRunBins

	#scan the overrides files to determine if launch item is disabled
	# ->returns list of disabled items
	def getDisabledItems(self):

		#list of disabled items
		disabledItems = []

		#get all overrides plists
		overrides = glob.glob(OVERRIDES_DIRECTORY + '*/overrides.plist')

		#process
		# ->check all files for overrides
		for overide in overrides:

			#wrap
			try:

				#dbg msg
				utils.logMessage(utils.MODE_INFO, 'opening %s' % overide)

				#load plist and check
				plistData = utils.loadPlist(overide)
				if not plistData:

					#skip
					continue

				#now parse 'normal' overrides
				for overrideItem in plistData:

					#check if item is disabled
					if 'Disabled' in plistData[overrideItem] and plistData[overrideItem]['Disabled']:

						#save
						disabledItems.append(overrideItem)

			#ignore exceptions
			except Exception, e:

				#skip
				continue

		return disabledItems
















