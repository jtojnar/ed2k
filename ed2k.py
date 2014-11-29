#!/usr/bin/env python3

import hashlib
import os, sys
from Crypto.Hash import MD4

if len(sys.argv) == 1:
	print("This quickly gets ed2k links for anidb crequing.")
	print("Usage: %s [files]" % sys.argv[0])
	exit()

def md4(x):
	h = MD4.new()
	h.update(x)
	return h

def ed2k(file_name):
	ed2k_block = 9500 * 1024
	ed2k_hash = b''
	file_size = None
	with open(file_name, 'rb') as f:
		file_size = os.fstat(f.fileno()).st_size #while at it, fetch the size of the file
		while True:
			block = f.read(ed2k_block)
			if not block:
				break

			#hashes are concatenated md4 per block size for ed2k hash
			ed2k_hash += md4(block).digest()
		#on size of modulo block size, append another md4 hash of a blank string
		if file_size % ed2k_block == 0:
			ed2k_hash += md4('').digest()

	#finally
	ed2k_hash = md4(ed2k_hash).hexdigest()
	return [ file_size, ed2k_hash ]


# ed2k sample link: ed2k://|file|The_Two_Towers-The_Purist_Edit-Trailer.avi|14997504|965c013e991ee246d63d45ea71954c4d|/
for file in sys.argv[1:]:
	filebase = os.path.basename(file)
	size, hash = ed2k(file)
	print("ed2k://|file|{filebase}|{size}|{hash}|/".format(filebase = filebase, size = size, hash = hash))

