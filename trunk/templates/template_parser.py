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
# template_parser.py


import os, sys, re
from pyparsing import *
from template import Template


''' 
TODO
	fix exception handling
	document HIVE, OS_LEVEL
	test 64-bit safety
	document common registry key meanings

	similar to timestamp, want:
		 print value_data for value_name
		 list subkeys
		 list value_names
		 list value_names_and_data
	
	eliminate concept of prereqs till we can determine a use (don't care about circular dependencies)
	restrict templates to dealing with one hive type (don't need registry sets)
	REMEMBER: keys have lastwritetimes, not values
'''	


class TemplateException(Exception):

	'''
	An error handling class for template parsing problems.
	'''
	
	# @fname: this templates file's name
	# @ message: description of the parsing error encountered
	def __init__(self, fname, message):
		self.fname = fname
		self.message = message

		
	def get_fname(self):
		return self.fname
		
	def get_message(self):
		return self.message
		
		

class TemplateParser:

	'''
	Parses template files into Template objects. See 'template_test' files for
	description of the file format.

	
	Sample template:
	
	///////////////////////////////////////////////////////////////////////////

	NAME = "some name"				# user-defined name

	DESCRIPTION = "a description"	# user-defined description

	HIVE = "SYSTEM"	# one of SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER, add others
	
	OS_LEVEL = "XP"		# zero or more of WIN2000, WINXP, VISTA, WIN7 ... not sure about the best way to use yet

	DISPLAY_STRING = "some display GET_TIME[HKLM\Software\Microsoft\Windows] string GET_TIME[HKLM\Software\Google\Android]"	
	
	REQUIRED_KEY = "HKLM\Software\Microsoft\Windows"
	REQUIRED_KEY = "HKLM\Software\Google\Android"
	required_value_name = "HKLM\Software\Microsoft\Windows" "what's_up"
	REQUIRED_VALUE_DATA = "HKLM/Software\Google\Android" "some_value_name" "some_data"

	
	///////////////////////////////////////////////////////////////////////////
	
	'''
	
	def __init__(self):
		self.tplate = Template()


	# 'set' functions matching those in class Template; here for when parsing
	# output from the parser gets more interesting.
	def set_name(self, match):
		self.tplate.set_name(match[1])
	
	def set_description(self, match):
		self.tplate.set_description(match[1])

	def add_required_key(self, match):
		self.tplate.add_required_key(match[1])
		
	def add_required_value_name(self, match):
		self.tplate.add_required_value_name(match[1], match[2])
		
	def add_required_value_data(self, match):
		self.tplate.add_required_value_data(match[1], match[2], match[3])
		
	def set_display(self, match):
		self.tplate.set_display_string(match[1])
		
	def set_hive(self, match):
		self.tplate.set_hive(match[1])

	def set_oslevel(self, match):
		self.tplate.set_oslevel(match[1])


	# Parse the given template file into Template object. Makes heavy use of 
	# machinery from pyparsing module, look there for more documentation.
	
	def parse(self, template_file):
	
		# some basic pieces
		comment = Literal("#") + SkipTo("\n")
		quote = QuotedString('"', multiline=True)

		# basic section
		name = (CaselessKeyword("NAME") + Suppress("=") + quote).setParseAction(self.set_name)
		description = (CaselessKeyword("DESCRIPTION") + Suppress("=") + quote).setParseAction(self.set_description)
		display = (CaselessKeyword("DISPLAY_STRING") + Suppress("=") + quote).setParseAction(self.parse_display_string)
		hive = (CaselessKeyword("HIVE") + Suppress("=") + quote).setParseAction(self.set_hive)
		oslevel = (CaselessKeyword("OS_LEVEL") + Suppress("=") + quote).setParseAction(self.set_oslevel)
		required_key = (CaselessKeyword("REQUIRED_KEY") + Suppress("=") + quote).setParseAction(self.add_required_key)
		required_value_name = (CaselessKeyword("REQUIRED_VALUE_NAME") + Suppress("=") + quote + quote).setParseAction(self.add_required_value_name)
		required_value_data = (CaselessKeyword("REQUIRED_VALUE_DATA") + Suppress("=") + quote + quote + quote).setParseAction(self.add_required_value_data)
		
#		# required keys template section
#		id_key_attribute = Group(CaselessKeyword("ID") + Suppress("=") + quote)
#		path_key_attribute = Group(CaselessKeyword("PATH") + Suppress("=") + quote)
#		value_name_key_attribute = Group(CaselessKeyword("VALUE_NAME") + Suppress("=") + quote)
#		data_key_attribute = Group(CaselessKeyword("DATA") + Suppress("=") + quote)
#		key_value_pair = value_name_key_attribute + Suppress(",") + data_key_attribute
#		key_desc = Group(id_key_attribute + Suppress(",") + path_key_attribute + Suppress(",") + Optional(key_value_pair))
#		reqd_key_section = Suppress(CaselessKeyword("REQUIRED_KEYS")) + Suppress(":") + OneOrMore(key_desc).setParseAction(self.set_reqd_keys)

#		# prerequisite templates section
#		prereq_name = Word(alphanums + "_")
#		prereq_list = Group(delimitedList(prereq_name))
#		prerequisite_section = (CaselessKeyword("PREREQUISITES") + Suppress(":") + Optional(prereq_list)).setParseAction(self.set_prerequisites)	
				
		# require that we have exactly one of each of the following terms
		terms = name & description & hive & oslevel & ZeroOrMore(required_key) \
				& Optional(display) & ZeroOrMore(required_value_name) \
				& ZeroOrMore(required_value_data)

		# ignore comments
		terms.ignore(comment)

		# do some work
		try:
			terms.parseFile(template_file)
		except ParseException as e:
			#raise TemplateException(template_file, str(e))
			print e
		return self.tplate

		
	def get_time(self, match):
		print "GET_TIME %s" % (match[2][0])
#		return self.tplate.get_time(match[2][0])
		
		
	def get_subkeys(self, match):
		print "GET_SUBKEYS: %s" % (match[2][0])

		
	def get_values(self, match):
		print "GET_VALUES: %s" % (match[2][0])
		
		
	# we would like to be able to put in VALUE_DATA, and ??
	def parse_display_string(self, match):
	
		match = match[1]
		g_time = (Keyword("GET_TIME") + "[" + SkipTo("]", include=True)).setParseAction(self.get_time)
		g_subkeys = (Keyword("GET_SUBKEYS") + "[" + SkipTo("]", include=True)).setParseAction(self.get_subkeys)
		g_values = (Keyword("GET_VALUES") + "[" + SkipTo("]", include=True)).setParseAction(self.get_values)
		terms = ZeroOrMore(g_time) & ZeroOrMore(g_subkeys)  & ZeroOrMore(g_values)
		self.tplate.set_display_string(terms.transformString(match))
		
		
		
if __name__ == "__main__":

	print TemplateParser().parse("template_files\\template_test.txt")
	
		