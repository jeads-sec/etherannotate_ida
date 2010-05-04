'''  
   EtherAnnotate IDA Pro Plugin
   Author: Josh Eads (eads.josh@gmail.com)
   Summary: The second half of my EtherAnnotate Xen modifications from my
            thesis paper.  Takes an EtherAnnotate instruction trace file,
            parses the file, and adds annotations of run-time values and
            code coverage to an IDA Pro .idb file.
   Last Modified: May 4, 2010
 
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 '''

from idautils import *
from idaapi import *
from sys import exit
import re

# Get current ea
#ea = ScreenEA()

#MakeComm(ea, "Current Address")

#Open the input trace file
filename = AskFile(0, "*.trace", "Select the instruction trace file")

if not filename:
	exit()

#open the file and parse the data
trace_file = open(filename)
#trace_data = trace_file.read()
#trace_file.close()

#create table for storing line comments
cmt_tbl = {}

for line in trace_file: #('\n'):
	#print "line: " + line
	if not re.search("((?:\d|\w)+)\: \w+\s+.+\# ((?:\w+: (?:\w|\d)+(?:\s,\s)*)*)", line):
		continue
	try:
		(instr_str, annotations) = line.split(" # ")
	except ValueError:
		print "Error with line: " + line
		continue
	instruction = re.match("((?:[0-9]|[a-f])+)", instr_str).groups()[0]

	for annotation in annotations.split(", "):
		if len(annotation.split("ptr_val[]:")) == 2:
			if cmt_tbl.has_key(instruction):
				cmt_tbl[instruction] += ', ' + annotation.split("ptr_val[]:")[1].strip()#annotation.split("ptr_val[]:")[0].strip() + ' "' + annotation.split("ptr_val[]:")[1].strip() + '"'
			else:
				cmt_tbl[instruction] = annotation.split("ptr_val[]:")[1].strip()#annotation.split("ptr_val[]:")[0].strip() + ' "' + annotation.split("ptr_val[]:")[1].strip() + '"'
			
			original_cmt = GetCommentEx(int(instruction,16), 0)
			if original_cmt == None:
				original_cmt = ''
			MakeComm(int(instruction, 16), str(original_cmt) + annotation.split("ptr_val[]:")[1].strip())

		'''else:
			if cmt_tbl.has_key(instruction):
				cmt_tbl[instruction] += annotation.strip()
			else:
				cmt_tbl[instruction] = annotation.strip()'''

	'''if match and len(match.groups()[1]) > 0:
		instruction = match.groups()[0]
		comments = match.groups()[1]
		annotation = comments.split(" , ")
		
		if cmt_tbl.has_key(instruction):
			cmt_tbl[instruction] = cmt_tbl[instruction] + comments.split(' , ')
		else:
			cmt_tbl[instruction] = comments.split(' , ')'''
			
	#MakeCode(int(instruction, 16))
	#code coverage: color all executed lines a light green
	SetColor(int(instruction, 16), CIC_ITEM, 0x32CD32)

trace_file.close()
	
'''for entry in cmt_tbl:
	#print entry + " >> " + str(list(set(cmt_tbl[entry])))
	original_cmt = ''#GetCommentEx(int(entry,16))
	MakeComm(int(entry, 16), original_cmt + str(list(set(cmt_tbl[entry].split(', ')))))#str(list(set(cmt_tbl[entry]))))'''