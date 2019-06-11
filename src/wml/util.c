/*
 * util.c
 *
 *  Created on: 28-May-2018
 *      Author: Arvind Rawat
 */

#include <unistd.h>

#include "common.h"
#include "crypt.h"
#include "util.h"

/*
* getSymLinkValue:
* @path : path of the file/symbolic link
*
* Returns the actual value for the symbolic link provided as input
*/
int getSymLinkValue(char *path, int version) {
	char symlinkpath[512];
    char sympathroot[512];
    struct stat p_statbuf;
    if (lstat(path, &p_statbuf) < 0) {  /* if error occured */
        log_error("Not a valid path - %s", path);
        return -1;
    }

    // Check if the file path is a symbolic link
    if (S_ISLNK(p_statbuf.st_mode) ==1) {
        // If symbolic link doesn't exists read the path its pointing to
        int len = readlink(path, symlinkpath, sizeof(symlinkpath));
        if (len != -1) {
            symlinkpath[len] = '\0';
        }
        log_debug("Symlink %s points to %s", path, symlinkpath);

        // If the path is starting with "/" and 'fs_mount_path' is not appended
        if(((strstr(symlinkpath, "/") - symlinkpath) == 0) && (strstr(symlinkpath,fs_mount_path) == NULL)) {
            snprintf(sympathroot, sizeof sympathroot, "%s%s", fs_mount_path, symlinkpath);
            log_debug("Absolute symlink path %s points to %s", symlinkpath, sympathroot);
        }
        else {
            char* last_backslash = strrchr(path, '/');
            if (last_backslash) {
                *last_backslash = '\0';
            }
            snprintf(sympathroot, sizeof sympathroot, "%s%s%s", path, "/", symlinkpath);
            log_debug("Relative symlink path %s points to %s", symlinkpath, sympathroot);
        }

        strcpy_s(path, MAX_LEN, sympathroot);
        if(version == 2) {
            strcpy_s(path, MAX_LEN, symlinkpath);
		}
		else {
			return getSymLinkValue(path, version);
		}
    }
	else {
		log_error("Not a valid Symlink - %s", path);
		return -1;
	}
    return 0;
}

char *toUpperCase(char *str) {

	char *temp = str;
	while (*temp) {
		if (*temp >= 97 && *temp <= 122)
			*temp -= 32;
		temp++;
	}
	return str;
}

void replaceAllStr(char * orig_str, char * search_str, char * replace_str) {

      //a buffer variable to do all replace things
      char buffer[NODE_LEN];
      //to store the pointer returned from strstr
      char * ch;

      //first exit condition
      if(!(ch = strstr(orig_str, search_str)))
              return;

      //copy all the content to buffer before the first occurrence of the search string
      strncpy_s(buffer, sizeof(buffer), orig_str, ch-orig_str);

      //prepare the buffer for appending by adding a null to the end of it
      buffer[ch-orig_str] = 0;

      //append using snprintf function
      snprintf(buffer + (ch - orig_str), sizeof(buffer), "%s%s", replace_str, ch + strnlen_s(search_str, NODE_LEN));

      //empty orig_str for copying
      orig_str[0] = 0;
      strcpy_s(orig_str, MAX_LEN, buffer);

      //pass recursively to replace other occurrences
      return replaceAllStr(orig_str, search_str, replace_str);
}

/*
Check if file exist on file system or not.
return 0 if file exist, non zero if file does not exist or can't be found
*/
int doesFileExist(char * filename) {
	struct stat info;
	if (stat(filename, &info)) {
		log_error("Not a valid path - %s", filename);
		return -1;
	}
	return 0;
}

/*
Check if directory exist on file system or not.
return 0 if directory exist, non zero if directory does not exist or can't be found
*/
int doesDirExist(char * dirname) {
	struct stat info;
	if (stat(dirname, &info)) {
		log_error("Not a valid path - %s", dirname);
		return -1;
	}
	else if (!(info.st_mode & S_IFDIR)) {
		log_error("Not a valid directory - %s", dirname);
		return -1;
	}
	return 0;
}

/*This function returns the value of an XML tag. 
Input parameter: Line read from the XML file
Output: Value in the tag
How it works: THe function accepts a line containing tag value as input
it parses the line until it reaches quotes (" ") 
and returns the value held inside them 
so <File Path = "a.txt" .....> returns a.txt
include="*.out" ....> returns *.out and so on..
*/
void tagEntry (char* line) {

    int i =0;
    char key[NODE_LEN];
    char *start,*end;
    /*We use a local string 'key' here so that we dont make any changes
    to the line pointer passed to the function. 
    This is useful in a line containing more than 1 XML tag values.
    E.g :<Dir Path="/etc" include="*.bin" exclude="*.conf">
    */
    strcpy_s(key,sizeof(key),line);
 
    while(key[i] != '\"')
        i++;
    start = &key[++i];

    end = start;
    while(*end != '\"')
        end++;
    *end = '\0';

    strcpy_s(node_value, sizeof(node_value), start);
}

void convertWildcardToRegex(char *wildcard) {

    int i=0, j=0;
    char c;
    char key[NODE_LEN];

    strcpy_s(key,sizeof(key),wildcard);
    node_value[j++] = '^';

    c = key[i];
    while(c) {
    	switch(c) {
      	    case '*':
		node_value[j++] = '.';
        	node_value[j++] = '*';
        	break;
            case '?':
        	node_value[j++] = '.';
        	break;
      	    case '(':
      	    case ')':
      	    case '[':
      	    case ']':
      	    case '$':
     	    case '^':
      	    case '.':
      	    case '{':
      	    case '}':
      	    case '|':
      	    case '\\':
        	node_value[j++] = '\\';
        	node_value[j++] = c;
        	break;
      	    default:
        	node_value[j++] = c;
        	break;
	}
	c = key[++i];
    }

    node_value[j++] = '$';
    node_value[j] = '\0';
}

char *getTagValue(char *line, char *key) {

	char *temp_ptr = NULL;
	temp_ptr = strstr(line, key);
	if (temp_ptr != NULL ) {
		tagEntry(temp_ptr);
		return node_value;
    }
	return temp_ptr;
}

char *tokenizeString(char *line, char *delim) {

	size_t dhash_max = 128;
    char *dhash = NULL;
	char *next_token = NULL;
	
	strcpy_s(node_value,NODE_LEN,line);
	dhash = node_value;
	dhash_max = strnlen_s(node_value, NODE_LEN);
	strtok_s(dhash,&dhash_max,delim,&next_token);

	return dhash;
}

FILE *getMatchingEntries(char *line, FILE *fd, char file_type) {
	
	int slen = 0;
	char *last_oblique_ptr = NULL;
	char Cmd_Str[MAX_CMD_LEN] = {'\0'};
	char bPath[256] = {'\0'};
    char mPath[256] = {'\0'};
	char sPath[256] = {'\0'};

	strcpy_s(sPath,sizeof(sPath),fs_mount_path);
    strcat_s(sPath,sizeof(sPath),tokenizeString(line, ".*"));//path in the VM
	
	last_oblique_ptr = strrchr(sPath,'/');
	strncpy_s(bPath, sizeof(bPath), sPath, strnlen_s(sPath, sizeof(sPath))-strnlen_s(last_oblique_ptr+1,sizeof(sPath)));
	
	strcpy_s(mPath,sizeof(mPath),fs_mount_path);
    strcat_s(mPath,sizeof(mPath),line);//path in the VM
	
	//to remove mount path from the find command output and directory path and +1 is to remove the additional / after directory
    slen = strnlen_s(fs_mount_path,sizeof(fs_mount_path));
	snprintf(Cmd_Str, sizeof(Cmd_Str), "find \"%s\" -regex \"%s\" -type %c | sed -r 's/.{%d}//'", bPath, mPath, file_type, slen);
	log_info("********mPath is ---------- %s and command is %s",mPath,Cmd_Str);

	fd = popen(Cmd_Str,"r");
	return fd;
}

void calculateDirHashUtil(char *dir_path, char *include, char *exclude, FILE *fq, char *hash_type) {

	int slen = 0;
	int retval = -1;
	char Cmd_Str[MAX_CMD_LEN] = {'\0'};
	char dir_name_buff[1024] = {'\0'};
	char output[MAX_HASH_LEN] = {'\0'};
	FILE *dir_file;
	
	snprintf(dir_name_buff, sizeof(dir_name_buff), "%s%s", fs_mount_path, dir_path);
	log_debug("dir path : %s", dir_name_buff);
	retval = doesDirExist(dir_name_buff);
	if (retval == 0) {
		log_info("Mounted dir path for dir %s is %s", dir_path, dir_name_buff);

		//to remove mount path from the find command output and directory path and +1 is to remove the additional / after directory
		slen = strnlen_s(dir_name_buff, sizeof(dir_name_buff)) + 1;
		if(strcmp(include,"") != 0 && strcmp(exclude,"") != 0 )
			snprintf(Cmd_Str, sizeof(Cmd_Str), "find \"%s\" -maxdepth 1 ! -type d | sed -r 's/.{%d}//' | grep -E  \"%s\" | grep -vE \"%s\" | LANG=C sort",dir_name_buff, slen, include, exclude);
		else if(strcmp(include,"") != 0)
			snprintf(Cmd_Str, sizeof(Cmd_Str), "find \"%s\" -maxdepth 1 ! -type d | sed -r 's/.{%d}//' | grep -E  \"%s\" | LANG=C sort",dir_name_buff, slen, include);
		else if(strcmp(exclude,"") != 0)
			snprintf(Cmd_Str, sizeof(Cmd_Str), "find \"%s\" -maxdepth 1 ! -type d | sed -r 's/.{%d}//' | grep -vE \"%s\" | LANG=C sort",dir_name_buff, slen, exclude);
		else
			snprintf(Cmd_Str, sizeof(Cmd_Str), "find \"%s\" -maxdepth 1 ! -type d | sed -r 's/.{%d}//' | LANG=C sort",dir_name_buff, slen);
		log_info("********dir_name_buff is ---------- %s and command is %s", dir_name_buff, Cmd_Str);

		dir_file = popen(Cmd_Str, "r");
		if (dir_file != NULL) {
			generateFileHash(output, dir_file, hash_type);
			pclose(dir_file);
		}
		else {
			log_warn("Unable to get result of command execution- %s", Cmd_Str);
		}

		fprintf(fq, "<Dir Exclude=\"%s\" Include=\"%s\" Path=\"%s\">", exclude, include, dir_path);
		fprintf(fq, "%s</Dir>", output);
		log_info("Dir : %s Hash Measured : %s", dir_path, output);
	}
}

void calculateFileHashUtil(char *file_path, FILE *fq, char *hash_type, int version) {

	int retval = -1;
	char file_name_buff[1024] = {'\0'};
	char output[MAX_HASH_LEN] = {'\0'};
	FILE *file;
	
	snprintf(file_name_buff, sizeof(file_name_buff), "%s%s", fs_mount_path, file_path);
    log_debug("file path : %s",file_name_buff);
    retval = doesFileExist(file_name_buff);
    if( retval == 0 ) {
		log_info("Mounted file path for file %s is %s",file_path,file_name_buff);
   
	    /*How the process works: 
        1. Open the file pointed by value
        2. Read the file contents into char * buffer
        3. Pass those to SHA function.(Output to char output passed to the function)
        4. Return the Output string.
        */
	    file = fopen(file_name_buff, "rb");
		if (file) {
			generateFileHash(output, file, hash_type);
			fclose(file);
		}
		else {
			log_warn("File not found- %s",file_name_buff);
		}
		
		fprintf(fq,"<File Path=\"%s\">",file_path);
		fprintf(fq,"%s</File>", output);
		log_info("File : %s Hash Measured : %s",file_path,output);
    }
}

void calculateSymlinkHashUtil(char *sym_path, FILE *fq, char *hash_type, int version) {

	int retval = -1;
	char hash_str[MAX_LEN] = {'\0'};
	char file_name_buff[1024] = {'\0'};
	char output[MAX_HASH_LEN] = {'\0'};
	
	snprintf(file_name_buff, sizeof(file_name_buff), "%s%s", fs_mount_path, sym_path);
    log_debug("symlink path : %s", file_name_buff);
    retval = getSymLinkValue(file_name_buff, version);
    if( retval == 0 ) {
        log_info("Target file path for symlink %s is %s",sym_path,file_name_buff);

        /*How the process works:
        1. Concatenate source path and target path
        2. Store that content into char * buffer
        3. Pass those to SHA function.(Output to char output passed to the function)
        4. Return the Output string.
        */
		snprintf(hash_str, MAX_LEN, "%s%s", sym_path, file_name_buff);
		generateStrHash(output, hash_str, hash_type);
		
		fprintf(fq,"<Symlink Path=\"%s\">",sym_path);
		fprintf(fq,"%s</Symlink>", output);
        log_info("Symlink : %s Hash Measured : %s",sym_path,output);
    }
}
