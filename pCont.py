#! /usr/bin/python

"""This script is intended to reverse-engineer the Panasonic .CONT file format."""

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
import reveng # Custom reverse-engineering module


# FILE PRINTING FUNCTIONS

def prettyPrint(data, camera=False):
	'''Print out the Panasonic CONT file in a human-readable format.'''
	
	if type(data) == bytes:
		data = array.array('H',data)
	
	blocks = len(data)
	
	# First 14 bytes are the file type
	reveng.printChars(data[0:7])
	
	# Header information that I haven't decoded yet
	# This is of varying length (depending on the source device)

	if camera:
		n = 37 # Camera
	else:
		n = 29 # HD Writer

	print()
	reveng.printHex(data[7:n])
	reveng.printInts(data[7:n])
	print()

	# Modification dates?
	print("Recording and file timestamps:")
	reveng.printInts(data[n:n+8])
	reveng.printInts(data[n+8:n+16])
	reveng.printInts(data[n+16:n+24])
	reveng.printInts(data[n+24:n+32])

	n = n+33
	x = n+20

	fsize = (data[n+1] << 16) + data[n]
	print("File size (bytes):", fsize)
	print()

	reveng.printHex(data[n+2:x])
	reveng.printInts(data[n+2:x])
	print()

	# File format information
	pixel_w = data[x]
	pixel_h = data[x+2]
	ratio_w = data[x+4]
	ratio_h = data[x+6]
	frame_r = data[x+8]
	unknown1 = data[x+10]
	unknown2 = data[x+12]
	audio_id = data[x+13]
	unknown3 = data[x+14]
	audio_bitrate = (data[x+17] << 16) + data[x+16]
	audio_bitdepth = data[x+18]
	audio_channels = data[x+19]
	audio_freq = data[x+20]
	
	dev_start = x+20+4
	
	print("Frame size:\t", pixel_w, 'x', pixel_h)
	print("Aspect ratio:\t", ratio_w, 'x', ratio_h)
	print("Frame rate:\t", frame_r)
	print("Unknown:\t", unknown1)
	print("Unknown:\t", unknown2)
	print("Audio ID?:\t", audio_id)
	print("Unknown:\t", unknown3)
	print("Audio bitrate?:\t", audio_bitrate)
	print("Audio depth?:\t", audio_bitdepth)
	print("Audio channels?:\t", audio_channels)
	print("Audio freq?:\t", audio_freq)

	print()
	reveng.printHex(data[x+21:dev_start])
	print()

	brand = data[dev_start:dev_start+128]
	device = data[dev_start+128:dev_start+256]
	reveng.printChars(brand)
	reveng.printChars(device)
	
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
			
			print("\nDatestamp detected:")
			reveng.printChars(dt)
			
			# Update the pointer
			i = x
		
		# Video (M2TS) file
		elif element == 1:
			print("\nVideo file:")
			reveng.printHex(data[i+1:i+8])
			#reveng.printInts(data[i+1:i+8])
			m2ts_size = (data[i+9] << 16) + data[i+8]
			print("File size (bytes):", m2ts_size)
			reveng.printHex(data[i+12:i+16])
			#reveng.printInts(data[i+12:i+16])
			x = i+17
			str_len = int(data[x-1] / 2)
			str_data = data[x:x+str_len]
			reveng.printChars(str_data)

			# Update the pointer
			i = x+str_len
			
		# Thumbnail (TMB) file
		elif element == 2:
			print("\nThumbnail file:")
			reveng.printHex(data[i+1:i+8])
			reveng.printHex(data[i+8:i+12])
			#reveng.printInts(data[i+8:i+12])
			x = i+13
			str_len = int(data[x-1] / 2)
			str_data = data[x:x+str_len]
			reveng.printChars(str_data)

			# Update the pointer
			i = x+str_len

		# XML (PMPD) file
		elif element == 4:
			print("\nXML file:")
			reveng.printHex(data[i+2:i+6])
			#reveng.printInts(data[i+2:i+6])
			x = i+7
			str_len = int(data[x-1] / 2)
			str_data = data[x:x+str_len]
			reveng.printChars(str_data)

			# Update the pointer
			i = x+str_len
			
		i += 1



# FILE CREATION FUNCTIONS

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


def makeContTimestamp(dt, x=5):
	'''Convert a datetime into a timestamp object for the cont file.'''
	
	fields = [dt.year, dt.month, x, dt.day, dt.hour, dt.minute, dt.second]
	return fields


def makeContDateString(dt):
	'''Create a string suitable for the CONT file date field.'''

	return dt.strftime('%d.%m.%Y')


def buildCont(m2ts_file, debug=False):
	'''Create a cont file.'''
	
	# Check that the file exists
	if not os.path.exists(m2ts_file):
		print("Error: file %s not found.")
		sys.exit(1)
	else:
		fname = os.path.basename(m2ts_file)
		print("Preparing CONT file for %s..." % fname)
		
		# Generate the filename for the CONT file
		fbase = os.path.splitext(fname)[0]
		cont_file = '%s.cont' % fbase
		tmb_file = '%s.tmb' % fbase
		pmpd_file = '%s.pmpd' % fbase
	
	# Prepare the parameters required for the CONT file

	# Read file timestamps
	params = {
		'file_created': datetime.datetime.fromtimestamp(fileCreationDate(m2ts_file)),
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
			
		if tz_offset is not None:
			params['record_dt_utc'] = params['file_created'] - tz_offset
		else:
			params['record_dt_utc'] = params['file_created'] - (datetime.datetime.now() - datetime.datetime.utcnow())
	
	params['record_str'] = makeContDateString(params['record_dt'])
	#print(params)
	
	# Formats
	fmts = '<H'	# Little-endian unsigned short (2 bytes)
	fmti = '<I' # Little-endian unsigned int (4 bytes)
	fmtc = 'B'	# For the occasional characters
	
	# Distinct blocks of data in the binary file
	file_structure = [
	
		# File format header
		{'data':'P_Cont_', 'fmt': fmts, 'raw':False},
		{'data':'\nCont\n', 'fmt': fmtc, 'raw':False},
		
		# Unidentified binary data
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
		{'data':[0, 54400, 19064, 1, 0, 0, 0, 0, 0, 26570, 234], 'fmt': fmts, 'raw':False, 'prenul':2},
		{'data':[1, 256], 'fmt': fmts, 'raw':False}, # These bytes are always consistent in my examples

		# Video stream fields
		{'data': b'\x20\x00', 'raw':True}, # This seems to be a flag that to indicates that the video is either imported from the camera (x2000), produced from a single-file (0x2100) or composite project (0x3100)
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
		
		# Unidentified binary data (seems to indicate end of header)
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
		{'data':params['file_size'], 'fmt': fmti, 'raw':False, 'prenul': 2},
		{'data':b'\x00' * 4, 'raw':True},
		{'data':b'\x00' * 4, 'raw':True}, # Unidentified binary data
		{'data':b'\x00' * 4, 'raw':True}, # Unidentified binary data (this should match the fields from the TMB and PMPD files)
		{'data': 2*len(fname)+2, 'raw':False, 'fmt': fmts}, # Length of filename field
		{'data': fname, 'raw':False, 'fmt': fmts, 'prenul': 2}, # Filename string
		
		# Seems the TMB and PMPD entries are needed for HD Writer to recognise the file
		# (even though the files themselves aren't required)
		
		# TMB File
		{'data':b'\x02\x00', 'raw':True, 'prenul': 2}, # Flag to indicate thumbnail file
		{'data':b'\x00' * 10, 'raw':True, 'prenul': 2}, # Unidentified binary data
		{'data':b'\x00' * 8, 'raw':True, 'prenul': 2}, # Unidentified binary data (shared by TMB and PMPD files)
		{'data': 2*len(tmb_file)+2, 'raw':False, 'fmt': fmts}, # Length of filename field
		{'data': tmb_file, 'raw':False, 'fmt': fmts, 'prenul': 2}, # Filename string
		
		# PMPD File
		{'data':b'\x04\x00', 'raw':True, 'prenul': 2}, # Flag to indicate PMPD XML file
		{'data':b'\x00' * 8, 'raw':True, 'prenul': 2}, # Unidentified binary data (shared by TMB and PMPD files)
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
		prettyPrint(data, True)
	
	f = open(cont_file, 'w+b')
	f.write(data)
	f.close()


if __name__ == '__main__':
	buildCont('/cygdrive/k/Projects/HCV130_Camera/Test/00019.M2TS', True)