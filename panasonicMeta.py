#!/usr/bin/python

"""This script is intended to reverse-engineer the Panasonic .CONT and .PMPD metadata files."""

__version__ = "1.0"
__author__ = "Joshua White"
__copyright__ = "Copyright 2019"
__email__ = "jwhite88@gmail.com"
__licence__ = "GNU Lesser General Public License v3.0"

import os
import sys
import datetime
import platform
import struct
import array
import argparse
import shutil
import reveng # Custom reverse-engineering module


# Absolute path to the script's current directory
PATH = os.path.dirname(os.path.abspath(__file__))


def initMenu():
	"""Initialise the command-line parser."""
	
	parser = argparse.ArgumentParser()
	
	# Can't analyse and output a file at the same time
	group = parser.add_mutually_exclusive_group()
	group.add_argument("-a", "--analyse", help="source CONT file to analyse")
	group.add_argument("-i", "--input", help="source M2TS video file")

	parser.add_argument("-d", "--debug", help="enable debug outputs",
		action="store_true")
	parser.add_argument("-u", "--unknown", help="shown only unknown fields when analysing",
		action="store_true")
	
	return parser.parse_args()


#############################################
# CONT file analysis
#############################################

def identifySource(field, debug=False):
	'''Assumes this flag is what I think it is...'''
	
	if field == 32:
		return "Directly Imported"
	elif field == 33:
		return "Single-Clip Project"
	elif field == 48:
		return "Previous Library Import (TBC)"
	elif field == 49:
		return "Multi-Clip Project"
	else:
		return "Unknown Value (%d)" % field


def readContTimestamp(data, debug=False):
	'''Take an array of 16-bit ints and convert to a timestamp.'''
	
	return datetime.datetime(data[1],data[2],data[4],data[5],data[6],data[7])
	

def filetimeToTimestamp(data, debug=False):
	'''Convert a little-endian Windows FILETIME field into a Python timestamp.'''
	
	filetime = (data[3] << 48) + (data[2] << 32) + (data[1] << 16) + data[0]
	usecs = filetime/10
	dt = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=usecs)
	return dt


def printCont(data, unknown_fields=False, debug=False):
	'''Print out the Panasonic CONT file in a human-readable format.'''
	
	if type(data) == bytes:
		data = array.array('H',data)
	
	blocks = len(data)
	
	if not unknown_fields:
		# First 14 bytes are the file type
		print(reveng.extractChars(data[0:7]))
	
	# Header information that I haven't decoded yet
	# This is of varying length (depending on the source device)
	for n in range(29,38,1):
		# Use the datestamp fields to detect the header length
		if data[n] == data[n+8] == data[n+16] == data[n+24] and data[n+1] == data[n+9]:
			break

	print()
	reveng.printHex(data[7:n])
	reveng.printInts(data[7:n])
	print()

	# File metadata
	print("File Metadata")

	if not unknown_fields:
		# File timestamps
		print("\tRecorded:\t", readContTimestamp(data[n:n+8]))
		print("\tRecorded (UTC):\t", readContTimestamp(data[n+8:n+16]))
		print("\tLast Modified:\t", readContTimestamp(data[n+16:n+24]))
		print("\tFile Created:\t", readContTimestamp(data[n+24:n+32]))

		# File size
		n += 33
		fsize = (data[n+1] << 16) + data[n]
		print("\tFile Size:\t", fsize, "bytes")
		n += 2
	else:
		n += 35

	# Unidentified fields
	x = n+16
	print()
	reveng.printHex(data[n+2:n+5])
	reveng.printInts(data[n+2:n+5])
	print("\tUnknown Data 1:\t", format(data[n+2], '#018b'))
	print("\tUnknown Data 2:\t", format(data[n+3], '#018b'))
	print("\tUnknown Data 3:\t", format(data[n+4], '#018b'))
	print()
	print("\tUnknown:\t", data[n+10])
	print("\tUnknown Flag:\t", data[n+11])
	print("\tUnknown Const:\t", data[n+12])
	print("\tUnknown Const:\t", data[n+13])
	print("\tOrigin (TBC):\t", identifySource(data[n+14]),"\n")

	if not unknown_fields:

		# Video stream
		print("Video stream (TBC)")
		print("\tUnknown:\t", data[x])
		print("\tFrame size:\t", data[x+2], 'x', data[x+4])
		print("\tAspect ratio:\t", data[x+6], 'x', data[x+8])
		print("\tFrame rate:\t", data[x+10])
		print("\tUnknown:\t", data[x+12]) # Maybe stream count?

		# Audio stream
		print("\nAudio stream (TBC)")
		print("\tUnknown:\t", data[x+14])
		print("\tStream ID:\t", data[x+15])
		print("\tUnknown:\t", data[x+16]) # Maybe stream count?
		print("\tBitrate:\t", (data[x+19] << 16) + data[x+18])
		print("\tBitdepth:\t", data[x+20])
		print("\tChannels:\t", data[x+21])
		print("\tFrequency:\t", data[x+22])

	# End of header
	dev_start = x+22+4

	if not unknown_fields:
		print("\nHeader End Fields")
		reveng.printHex(data[x+21:dev_start])

		# Device information
		print("\nDevice Information")
		print("==================")
		brand = data[dev_start:dev_start+128]
		print(reveng.extractChars(brand))
		device = data[dev_start+128:dev_start+256]
		print(reveng.extractChars(device))
		print("==================")
	
	# Start of file information
	i = dev_start+256
	
	while i < len(data):
		element = data[i]
	
		# Datestamp
		if element == 22:
			dt = []
			x = i+2
			while data[x] != 0:
				dt.append(data[x])
				x += 1
			
			print("\nDatestamp detected:", reveng.extractChars(dt))
			
			# Update the pointer
			i = x
		
		# Video (M2TS) file
		elif element == 1:
			print("\nVideo File")
			reveng.printHex(data[i+1:i+8])
			#reveng.printInts(data[i+1:i+8])
			m2ts_size = (data[i+9] << 16) + data[i+8]
			file_date = filetimeToTimestamp(data[i+12:i+16], debug)
			x = i+17
			str_len = int(data[x-1] / 2)
			str_data = data[x:x+str_len]
			if not unknown_fields:
				print("\tFile Size:\t", m2ts_size, "bytes")
				print("\tCreation Date:\t", file_date)
				print("\tFile Name:\t",reveng.extractChars(str_data))

			# Update the pointer
			i = x+str_len
			
		# Thumbnail (TMB) file
		elif element == 2:
			print("\nThumbnail file:")
			reveng.printHex(data[i+1:i+8])
			file_date = filetimeToTimestamp(data[i+8:i+12], debug)
			x = i+13
			str_len = int(data[x-1] / 2)
			str_data = data[x:x+str_len]
			if not unknown_fields:
				print("\tCreation Date:\t", file_date)
				print("\tFile Name:\t",reveng.extractChars(str_data))

			# Update the pointer
			i = x+str_len

		# XML (PMPD) file
		elif element == 4:
			print("\nXML file:")
			file_date = filetimeToTimestamp(data[i+2:i+6], debug)
			x = i+7
			str_len = int(data[x-1] / 2)
			str_data = data[x:x+str_len]
			if not unknown_fields:
				print("\tCreation Date:\t", file_date)
				print("\tFile Name:\t",reveng.extractChars(str_data))

			# Update the pointer
			i = x+str_len
			
		i += 1

def analyseCont(cont_file, unknown_fields=False, debug=False):
	'''Print out the Panasonic CONT file in a human-readable format.'''
	
	if not os.path.exists(cont_file):
		print("Error: file %s not found." % cont_file)
		sys.exit(1)
	
	data = reveng.readFile16(cont_file, "little", True)
	printCont(data, unknown_fields, debug)


###############################################################################
# Metadata File Creation
###############################################################################

def fileCreationDate(path_to_file):
	"""	Try to get the date that a file was created, falling back to when it was
	last modified if that isn't possible.
	See http://stackoverflow.com/a/39501288/1709587 for explanation."""
	if platform.system() == 'Windows':
		return os.path.getctime(path_to_file)
	else:
		stat = os.stat(path_to_file)
		try:
			return stat.st_birthtime
		except AttributeError:
			# We're probably on Linux. No easy way to get creation dates here,
			# so we'll settle for when its content was last modified.
			return stat.st_mtime


def makeWindowsFiletime(unix_time):
	'''Take a Unix time and return the Windows FILETIME.'''
	
	# Unix timestamp is in seconds, so convert to hundreds of nanoseconds
	n = int(unix_time*10000000)
	
	# Add offset for 1601-01-01
	filetime = 116444736000000000 + n
	
	return filetime


def makeContTimestamp(dt, x=5):
	'''Convert a datetime into a timestamp object for the cont file.'''
	
	fields = [dt.year, dt.month, x, dt.day, dt.hour, dt.minute, dt.second]
	return fields


def makeContDateString(dt):
	'''Create a string suitable for the CONT file date field.'''

	return dt.strftime('%d.%m.%Y')


def buildMetadata(m2ts_file, debug=False):
	'''Create cont and pmpd files.'''
	
	# Check that the file exists
	if not os.path.exists(m2ts_file):
		print("Error: file %s not found." % m2ts_file)
		sys.exit(1)
	else:
		fname = os.path.basename(m2ts_file)
		m2ts_creation_date = fileCreationDate(m2ts_file)
		print("Preparing metadata files for %s..." % fname)
		
		# Generate the filename for the CONT file
		fbase = os.path.splitext(fname)[0]
		cont_file = '%s.cont' % fbase
		tmb_file = '%s.tmb' % fbase
		pmpd_file = '%s.pmpd' % fbase
	
	# Prepare the parameters required for the CONT and XML files

	# Read file timestamps
	params = {
		'file_created': datetime.datetime.fromtimestamp(m2ts_creation_date),
		'file_modified': datetime.datetime.fromtimestamp(os.path.getmtime(m2ts_file)),
		'file_size': os.path.getsize(m2ts_file),
		'audio_stream': 4352, # TO DO: Read from file
		'audio_bitrate': 256000, # TO DO: Read from file
		'audio_bitdepth': 16, # TO DO: Read from file
		'audio_channels': 2, # TO DO: Read from file
		'audio_frequency': 48000, # TO DO: Read from file
	}
	
	# Use the file creation date for the recording date if not provided
	if 'record_dt' not in params:
		params['record_dt'] = params['file_created']
		
		try:
			tz_offset = params['file_created'].utcoffset()
		except Exception as err:
			tz_offset = None
			
		if tz_offset is None:
			print("WARNING: Couldn't get UTC offset, so using local timezone offset")
			tz_offset = datetime.datetime.now() - datetime.datetime.utcnow()
		
		params['record_dt_utc'] = params['file_created'] - tz_offset
		
	params['record_str'] = makeContDateString(params['record_dt'])
	if debug:
		print(params)
	
	
	###########################################################################
	# Create the thumbnail and PMPD (XML) files first, since we need the creation dates to put into the CONT file
	###########################################################################
	
	# Use the template thumbnail (blank)
	shutil.copy2('templates/panasonic/thumbnail.tmb', tmb_file)
	print("Created thumbnail file from template:", tmb_file)

	# The PMPD file is XML and we only need to substitute a few fields
	templatef = open('templates/panasonic/xml.pmpd', 'r')
	pmpd = templatef.read()
	
	# datetime = YYYY/MM/DD HH:MM:SS
	# bias = utc offset in minutes
	pmpd = pmpd.replace('$bias$','%d' % round(tz_offset.seconds/60.0))
	pmpd = pmpd.replace('$datetime$', params['record_dt'].strftime('%Y/%m/%d %H:%M:%S'))
	
	# Write out the PMPD (XML) file
	f = open(pmpd_file, 'w')
	f.write(pmpd)
	f.close()
	print("Created PMPD file from template:", pmpd_file)
	
	
	###########################################################################
	# Now create the CONT file
	###########################################################################
	
	# Formats
	fmts = '<H'	# Little-endian unsigned short (2 bytes)
	fmti = '<I' # Little-endian unsigned int (4 bytes)
	fmtl = '<Q' # Little-endian unsigned long long (8 bytes)
	fmtc = 'B'	# For the occasional characters
	
	# Distinct blocks of data in the binary CONT file
	file_structure = [
	
		# File format header
		{'data':'P_Cont_', 'fmt': fmts, 'raw':False},
		{'data':'\nCont\n', 'fmt': fmtc, 'raw':False},
		
		# Unidentified binary data
		# This remains constant between files from the camera
		{'data':b'\x0a\x00\x00\x00\x00\x10\x01\x00\x00\x00\x00\x01\x05\x00\x00\x00\x01\x00\x00\x00\x4c\x00\x00\x00\x02\x00\x00\x00\xe4\x02\x00\x00\x05\x00\x00\x00\xfe\x02\x00\x00\x06\x00\x00\x00\x50\x03\x00\x00\x0a\x00\x00\x00\xd6\x03', 'raw':True}, # Camera Header
		
		# Recording information
		# Suspect it is year, month, ?, day, hour, mins, seconds
		{'data':makeContTimestamp(params['record_dt']), 'fmt': fmts, 'raw':False, 'prenul':2}, # Date of recording
		{'data':makeContTimestamp(params['record_dt_utc']), 'fmt': fmts, 'raw':False, 'prenul':2}, # Date of recording (UTC)
		{'data':makeContTimestamp(params['file_modified']), 'fmt': fmts, 'raw':False, 'prenul':2}, # Last modified
		{'data':makeContTimestamp(params['file_created']), 'fmt': fmts, 'raw':False, 'prenul':2}, # Creation date
		
		# Video file size in bytes
		{'data':params['file_size'], 'fmt': fmti, 'raw':False, 'prenul': 2},
		
		# Unidentified binary data
		{'data': b'\x80', 'raw':True, 'prenul':4}, # This is always 0x80 when sourced from the camera
		{'data': b'\x10', 'raw':True}, # This varies, but the last bit is typically 0
		{'data': 19064, 'fmt': fmts, 'raw':False}, # Varies significantly
		{'data': 0, 'fmt': fmts, 'raw':False}, # Almost always zero, but occasionally 1-4
		{'data': [0, 0, 0, 0, 0], 'fmt': fmts, 'raw':False}, # Possibly unused fields?
		{'data': [26570, 240], 'fmt': fmts, 'raw':False}, # First value varies significantly; second varies around 240
		{'data': [1, 256], 'fmt': fmts, 'raw':False}, # These bytes are always consistent in my examples

		# Video stream fields
		{'data': b'\x20\x00', 'raw':True}, # This seems to be a flag that to indicates the source of the video (camera is 0x2000)
		{'data': 0, 'fmt': fmts, 'raw':False, 'prenul': 2}, # Unidentified field (always 0 in examples available to me)
		{'data': 1920, 'fmt': fmts, 'raw':False, 'prenul': 2}, # Video dimensions
		{'data': 1080, 'fmt': fmts, 'raw':False, 'prenul': 2},
		{'data': 16, 'fmt': fmts, 'raw':False, 'prenul': 2}, # Aspect ratio
		{'data': 9, 'fmt': fmts, 'raw':False, 'prenul': 2},
		{'data': 25, 'fmt': fmts, 'raw':False, 'prenul': 2}, # Frame rate
		{'data': 1, 'fmt': fmts, 'raw':False, 'prenul': 2}, # Unidentified field (always 1 in examples available to me)
		
		# Audio stream fields
		{'data': 128, 'fmt': fmts, 'raw':False, 'prenul': 2}, # Unidentified field (always 128 in examples available to me)
		{'data': params['audio_stream'], 'fmt': fmts, 'raw':False}, # Audio stream ID?
		{'data': 1, 'fmt': fmts, 'raw':False}, # Unidentified field (always 1 in examples available to me)
		{'data': params['audio_bitrate'], 'fmt': fmti, 'raw':False, 'prenul': 2}, # Audio bitrate
		{'data': params['audio_bitdepth'], 'fmt': fmts, 'raw':False}, # Audio bitdepth
		{'data': params['audio_channels'], 'fmt': fmts, 'raw':False}, # Audio channels
		{'data': params['audio_frequency'], 'fmt': fmts, 'raw':False}, # Audio frequency
		
		# Unidentified binary data (seems to indicate end of header); consistent between sample files
		{'data':b'\x04\x00\x00\x21', 'raw':True, 'prenul':2},
		
		# Brand
		{'data':'Panasonic', 'fmt': fmts, 'raw':False, 'length':256},
		
		# Device
		{'data':'01\0' + 'HC-V210/V110\0' + '00\0' + '00', 'fmt': fmts, 'raw':False, 'length':254}, # Note: it's actually 256, but for convenience purposes I have used 254 here so that the datestamp code can be easily commented out
		
		# Datestamp (optional)
		{'data':b'\x16\x00', 'raw':True, 'prenul':2}, # Flag to indicate datestamp value
		{'data':params['record_str'], 'fmt': fmts, 'raw':False, 'prenul':2},
		
		# M2TS File
		{'data':b'\x01\x00', 'raw':True, 'prenul': 2}, # Flag to indicate M2TS file
		{'data':b'\x06\x03', 'raw':True, 'prenul': 2}, # Seems to be a flag that indicates video source (x0603 for the camera, 0xDC02 for HD Writer)
		{'data':b'\x00' * 8, 'raw':True},
		{'data': params['file_size'], 'fmt': fmti, 'raw':False, 'prenul': 2},
		{'data':b'\x00' * 4, 'raw':True},
		{'data': makeWindowsFiletime(m2ts_creation_date), 'raw':False, 'fmt':fmtl}, # M2TS file creation timestamp
		{'data': 2*len(fname)+2, 'raw':False, 'fmt': fmts}, # Length of filename field
		{'data': fname, 'raw':False, 'fmt': fmts, 'prenul': 2}, # Filename string
		
		# The TMB and PMPD entries are needed for HD Writer to recognise the file
		# (even though the files themselves might not be required)
		
		# TMB File
		{'data':b'\x02\x00', 'raw':True, 'prenul': 2}, # Flag to indicate thumbnail file
		{'data':b'\x00' * 10, 'raw':True, 'prenul': 2}, # Unidentified binary data
		{'data': makeWindowsFiletime(fileCreationDate(tmb_file)), 'raw':False, 'fmt':fmtl, 'prenul': 2}, # TMB file creation timestamp
		{'data': 2*len(tmb_file)+2, 'raw':False, 'fmt': fmts}, # Length of filename field
		{'data': tmb_file, 'raw':False, 'fmt': fmts, 'prenul': 2}, # Filename string
		
		# PMPD File
		{'data':b'\x04\x00', 'raw':True, 'prenul': 2}, # Flag to indicate PMPD XML file
		{'data': makeWindowsFiletime(fileCreationDate(pmpd_file)), 'raw':False, 'fmt':fmtl, 'prenul': 2}, # PMPD file creation timestamp
		{'data': 2*len(pmpd_file)+2, 'raw':False, 'fmt': fmts}, # Length of filename field
		{'data': pmpd_file, 'raw':False, 'fmt': fmts, 'prenul': 2}, # Filename string
		
		# End of file
		{'data':b'\x00' * 2, 'raw':True},
	]
	
	# Object to store all resultant binary in
	data = b''
	
	# Iterate through the blocks in the file
	for element in file_structure:
		chars = element['data']
		start = len(data)
		
		# Check if we need to add any NUL bytes before the field
		if 'prenul' in element and element['prenul'] > 0:
			for x in range(0, element['prenul']):
				data += b'\x00'
		
		# Just inject the raw bytes
		if element['raw']:
			data += chars
		
		# Convert characters to bytes
		elif type(chars) == str:
			for c in chars:
				data += struct.pack(element['fmt'], ord(c))

		# Convert integers to bytes
		else:
			try:
				for c in chars:
					data += struct.pack(element['fmt'], c)
			except TypeError as e:
				data += struct.pack(element['fmt'], chars)
			
		end = len(data)
		diff = end - start
		
		# Check length of field
		if 'length' in element and element['length'] > diff:
			add = b'\x00' * (element['length'] - diff)
			data += add
		
	
	# Debug output
	if debug:
		reveng.printHex(data)
		printCont(data, debug=debug)
		print()
	
	# Write out the cont file
	f = open(cont_file, 'w+b')
	f.write(data)
	f.close()
	print("Created CONT file:", cont_file)



if __name__ == '__main__':
	args = initMenu()
	if args.input:
		buildMetadata(args.input, args.debug)
	elif args.analyse:
		analyseCont(args.analyse, args.unknown, args.debug)
