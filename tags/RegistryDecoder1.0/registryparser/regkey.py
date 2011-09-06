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

	
# Base classs for some registry structures. BUG: probably shouldn't be here.
class RegStructure:

	'''
	Parent class of all internal registry structures.
	'''

	def __init__(self):
		self.children = []
		self.sig = ""
		
	def has_children(self):
		return (len(self.children) > 0)
				
	def get_children(self):
		return self.children
		
	def num_children(self):
		return len(self.children)
		
	def key_type(self):
		return self.sig



class RegKeyNK(RegStructure):

	'''
	The registry structure representing an actual registry key.
	'''
	
	def __init__(self, path_list, value_list, timestamp):

		RegStructure.__init__(self)

		self.path = path_list
		self.value_list = value_list		
		self.timestamp = timestamp

		

if __name__ == "__main__":
	main()		
