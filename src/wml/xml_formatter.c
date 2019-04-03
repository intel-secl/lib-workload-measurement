/*
 * xml_formatter.c
 *
 *  Created on: 28-May-2018
 *      Author: Arvind Rawat
 */

#include "common.h"
#include "xml_formatter.h"

#define power_shell "powershell "
#define power_shell_prereq_command "-noprofile -executionpolicy bypass -file "
#define formatXml_script_path "format-xml.ps1"

FILE *formatManifestXml(char *manifest_xml, FILE *fd) {

	char Cmd_Str[MAX_CMD_LEN] = {'\0'};
#ifdef _WIN32
	snprintf(Cmd_Str, sizeof(Cmd_Str), power_shell power_shell_prereq_command "%s -inlineXml \"%s\"", formatXml_script_path, manifest_xml);
#elif __linux__
	snprintf(Cmd_Str, sizeof(Cmd_Str), "echo '%s' | xmllint --format -", manifest_xml);
#endif
	log_info("********manifest_xml is ---------- %s and command is %s",manifest_xml,Cmd_Str);
	
	fd = popen(Cmd_Str,"r");
	return fd;
}
