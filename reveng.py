#! /usr/bin/python

"""This script is intended to aid reverse-engineering of binary formats."""

__version__ = "1.0"
__author__ = "Joshua White"
__copyright__ = "Copyright 2019"
__email__ = "jwhite88@gmail.com"
__licence__ = "GNU Lesser General Public License v3.0"

import math
import binascii

from array import array
from sys import byteorder as system_endian
from os import stat


def readFile16(filename, endian="little", unsigned=True):
	'''Read a binary file in 16-bit values.'''

	# Treat values as either unsigned or signed 16-bit ints
	if unsigned:
		result = array('H')
	else:
		result = array('h')

	# Based on https://stackoverflow.com/questions/5030919/how-to-read-write-binary-16-bit-data-in-python-2-x
	count = stat(filename).st_size / 2
	count = math.floor(count)
	with open(filename, 'rb') as f:
		result.fromfile(f, count)
		if endian != system_endian:
			result.byteswap()

	return result


def printHex(data):
	'''Print out an array of data as a hex string.'''
	
	hex = binascii.hexlify(data).decode('ascii')
	w = 4
	blocks = [hex[i:i+w] for i in range(0, len(hex), w)]

	i = 0
	while i < len(blocks):
		print(blocks[i:i+8])
		i += 8


def printInts(data, debug=False):
	'''A function to print all values as 16-bit ints.
	Prints 16 values per line (to aid use of HxD Hex Editor).'''
	
	if debug:
		print("\n16-bit integers:")
	
	i = 0
	while i < len(data):
		print(data[i:i+16])
		i += 16


def extractChars(data, debug=False):
	'''Extract a string. Consecutive NULs are replaced with a 
	single new-line char for ease of reading.'''
	
	if debug:
		print("\n16-bit characters:")
	
	s = []
	for a in data:
		try:
			if a == 0:
				if len(s) > 0 and s[-1] != '\n':
					s.append('\n')
			else:
				s.append(chr(a))
		except ValueError:
			s.append('?')

	return ''.join(s)


if __name__ == '__main__':
	pass