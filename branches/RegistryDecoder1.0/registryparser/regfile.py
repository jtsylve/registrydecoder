#
# Registry Decoder
# Copyright (c) 2011 Digital Forensics Solutions, LLC
#
# Contact email:  registrydecoder@digitalforensicssolutions.com
#
# Authors:
# Andrew Case       - andrew@digitalforensicssolutions.com
# Lodovico Marziale - vico@digitalforensicssolutions.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#
'''
regfile 1.0
2010
Lodovico Marziale
'''


import regkey
import regvalue		
import pyregfi


'''
	Implement the following nomenclature for sanity across documentation etc.
		KEY:   last element of a registry path, or the path itself 	// folder
		VALUE: name:data pair in a key								// file
		NAME:  the name of a VALUE									// filename
		DATA: the encoded data of a value							// file contents

		keys have (optional) subkeys
		keys have values, min one: default:""
'''

			
class RegFile:

	'''
	DOCME
	'''

	def __init__(self, regfile):
		self.regfile = regfile

	def get_keygen(self):

		reghive = pyregfi.openHive(self.regfile)
		regiter = pyregfi.HiveIterator(reghive)

		for key in regiter:
			path_list = []
			for val in regiter.current_path():
				path_list.append(val)
			value_list = []
			for val in key.values:
				v = regvalue.Value(val.name, val.type, val.fetch_data())
				value_list.append(v)
			yield regkey.RegKeyNK(path_list, value_list, key.modified)
		
			
# for now, give me a registry file and I will try to parse some stuff out
def main():
	
	if len(sys.argv) != 2:
		usage()
		sys.exit()
	
	regfile = RegFile(sys.argv[1])
		
	generator = regfile.get_keygen()
	for key in generator:
		print key


if __name__ == "__main__":
	main()
	
