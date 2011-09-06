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

# regfile test harness


import os, sys
import regfile
import cPickle
import getopt


def print_keys(keylist):

	for element in keylist:
		print element.path + " TYPE " + str(type(element.path))
		for e in element.value_list:
			print "\tname: %s\t\ttype: %s\tvalue: %s" % (e.name, e.type_of_data, e.value)

		return



def usage():
	print "python harness.py  -i <registry file> | -r"
	print "\t-i: input new registry file for parsing"
	print "\t-r reload previously parsed registry file"

def main():
	
	diskfile = "pickle.dat"
	
	if len(sys.argv) < 2:
		sys.stderr.write("Too few arguments.\n")
		usage()
		exit(1)
	
	try:
		opts, args = getopt.getopt(sys.argv[1:], "i:r", ["input", "restore"])
	except getopt.GetoptError, err:
		sys.stderr.write(str(err)+"\n")
		usage()
		sys.exit(1)
		
	for o, a in opts:
		if o in ("-i", "--input"):
			mode = 'INPUT'
			bytes = open(a, 'rb').read()
		elif o in ("-r", "--reload"):
			mode = 'RELOAD'
		else:
			assert False, "unhandled option"

	if mode == 'INPUT':
	
		rf = regfile.RegFile(bytes)
		# get a generator for keys
		keylist = []
		keygen = rf.get_keygen()
#		rf.parse_file(keylist)
		outfile = open(diskfile, "wb")

		# iterate through and add to list for pickling
		for element in keygen:
			keylist.append(element)
			
		sys.stderr.write("list built\n")
		cPickle.dump(keylist, outfile, 2) 
		sys.stderr.write("list dumped\n")
		outfile.close()
		print_keys(keylist)
		
	elif mode == 'RELOAD':
		infile = open(diskfile, "rb")
		keylist = cPickle.load(infile)
		sys.stderr.write("list loaded\n")
		print_keys(keylist)
	
	else:	
		sys.stderr.write("mode error: mode == %s\n" % (str(mode)))
		usage()
		exit(1)






			
if __name__ == "__main__":
	main()			
