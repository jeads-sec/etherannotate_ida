#include <windows.h>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <diskio.hpp>
#include <graph.hpp>
#include <kernwin.hpp>

#include <string>
#include <iostream>
#include <fstream>

#include <boost/regex.hpp>

using namespace std;

int IDAP_init(void)
{
      // Do checks here to ensure your plug-in is being used within
      // an environment it was written for. Return PLUGIN_SKIP if the
      // checks fail, otherwise return PLUGIN_KEEP.
      return PLUGIN_KEEP;
}
void IDAP_term(void)
{
       // Stuff to do when exiting, generally you'd put any sort
       // of clean-up jobs here.
       return;
}

// The plugin can be passed an integer argumenct from the plugins.cfg
// file. This can be useful when you want the one plug-in to do
// something different depending on the hot-key pressed or menu
// item selected.
void IDAP_run(int arg)
{
	// The "meat" of your plug-in
	ea_t cur_ea;
	char* trace_name = NULL;
	FILE* fin;
	string cur_line, instruction, annotation;
	ifstream trace_file;
	unsigned int annotation_pos = 0;
	boost::regex trace_re("((?:\\d|\\w)+)\\: \\w+\\s+.+\\# ((?:\\w+: (?:\\w|\\d)+(?:\\s,\\s)*)*)");
	boost::regex instruction_re("((?:[0-9]|[a-f])+)");
	boost::cmatch instruction_matches;
 
	msg("Annotated Tracing Plugin 1.0\n");
	//cur_ea = get_screen_ea();
	//describe(cur_ea, 0, "test comment!");
	//set_cmt(cur_ea, "test comment!", false);
	trace_name = askfile_c(0,"instrtrace.trace","Select the instruction trace file");
	msg("Selected file: %s\n", trace_name);
	
	if(trace_name)
	{
		trace_file.open(trace_name);
		while(!trace_file.eof())
		{
			annotation_pos = 0;
			getline(trace_file, cur_line);

			//if (!boost::regex_search(cur_line, trace_re))
			{
				//continue;
			}
			
			/*boost::regex_search(cur_line.c_str(), instruction_matches, instruction_re);
			
			if(!instruction_matches.empty())
			{
				instruction = string(instruction_matches[1].first, instruction_matches[1].second);
			}*/

			//msg(instruction.c_str());
			
			instruction = cur_line.substr(0, 7);
			cur_ea = strtol(instruction.c_str(), NULL, 16);
			
			annotation_pos = cur_line.find("#");
			//set_cmt(strtol(instruction.c_str(), NULL, 16), "TEST!", false);
			set_item_color(cur_ea, 0x32CD32);
			if(annotation_pos != 0)
			{
				annotation = cur_line.substr(annotation_pos+1);
				set_cmt(cur_ea, annotation.c_str(), false);
			}
			//msg(cur_line.c_str());
		}
	}
	
	/*for annotation in annotations.split(", "):
		if len(annotation.split("ptr_val[]:")) == 2:
			if cmt_tbl.has_key(instruction):
				cmt_tbl[instruction] += ', ' + annotation.split("ptr_val[]:")[1].strip()#annotation.split("ptr_val[]:")[0].strip() + ' "' + annotation.split("ptr_val[]:")[1].strip() + '"'
			else:
				cmt_tbl[instruction] = annotation.split("ptr_val[]:")[1].strip()#annotation.split("ptr_val[]:")[0].strip() + ' "' + annotation.split("ptr_val[]:")[1].strip() + '"'
			
			original_cmt = GetCommentEx(int(instruction,16), 0)
			if original_cmt == None:
				original_cmt = ''
			MakeComm(int(instruction, 16), str(original_cmt) + annotation.split("ptr_val[]:")[1].strip())

	SetColor(int(instruction, 16), CIC_ITEM, 0x32CD32)*/
	
	return;
}
// There isn't much use for these yet, but I set them anyway.
char IDAP_comment[]       = "This is my test plug-in";
char IDAP_help[]          = "My plugin";
// The name of the plug-in displayed in the Edit->Plugins menu. It
// can be overridden in the user's plugins.cfg file.
char IDAP_name[]          = "Annotated Tracing";
// The hot-key the user can use to run your plug-in.
char IDAP_hotkey[]        = "Alt-1";
// The all-important exported   PLUGIN object
plugin_t PLUGIN =
{
   IDP_INTERFACE_VERSION,       // IDA version plug-in is written for
   0,                           // Flags (see below)
   IDAP_init,                   // Initialisation function
   IDAP_term,                   // Clean-up function
   IDAP_run,                    // Main plug-in body
   IDAP_comment,                // Comment – unused
   IDAP_help,                   // As above – unused
   IDAP_name,                   // Plug-in name shown in
                                // Edit->Plugins menu
   IDAP_hotkey                  // Hot key to run the plug-in
};