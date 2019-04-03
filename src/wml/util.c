/*
 * util.c
 *
 *  Created on: 28-May-2018
 *      Author: Arvind Rawat
 */

#ifdef __linux__
#include <unistd.h>
#endif

#include "crypt.h"
#include "util.h"

#ifdef _WIN32
typedef struct _REPARSE_DATA_BUFFER {
	ULONG  ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG  Flags;
			WCHAR  PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR  PathBuffer[1];
		} MountPointReparseBuffer;
		struct {
			UCHAR DataBuffer[1];
		} GenericReparseBuffer;
	};
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;
#endif

#ifdef _WIN32
/*
*ISLINK(): check whether passed path is link or not
*@path : pointer to path
*return : return 0, if path is link otherwise 1. If error occured it will return negative value
*/
int ISLINK(char *path) {
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;
	int islink = -1;
	hFind = FindFirstFile(path, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		log_error("FindFirstFile failed (%ld)", GetLastError());
		return islink;
	}

	log_debug("FOUND FILE : %s", FindFileData.cFileName);
	log_debug("File Attributes : %ld", FindFileData.dwFileAttributes);
	if (FindFileData.dwFileAttributes == FILE_ATTRIBUTE_REPARSE_POINT) {
		log_debug("file contains reparse point ...");
		islink = 0;
	}
	else if (FindFileData.dwFileAttributes == FILE_ATTRIBUTE_ARCHIVE || FindFileData.dwFileAttributes == 33) {
		log_debug("file contains directory reparse point ...");
		islink = 0;
	}
	else if (FindFileData.dwReserved0 == IO_REPARSE_TAG_SYMLINK) {
		log_debug("file is a symbolic link to file ...");
		islink = 0;
	}
	else if (FindFileData.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT) {
		log_debug("this file is JUNCTION ...");
		islink = 0;
	}

	return islink;
}

/*
*readlink(): read target of link passed
*@path: path of the file whose target link we want
*@target_buf : char * buffer for target, if target buff is not long enough to store it reallocates memory for it,
*@target_buf_size : size of char * buffer passed
*retur : if successfull size of target in terms of char, else return negative value in case of error
*/
int readlink(char *path, char *target_buf, int target_buf_size) {
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;
	hFind = FindFirstFile(path, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		log_error("FindFirstFile failed (%ld)", GetLastError());
		return -1;
	}
	else {
		log_debug("FOUND FILE : %s", FindFileData.cFileName);
		if (FindFileData.dwFileAttributes == FILE_ATTRIBUTE_REPARSE_POINT) {
			log_debug("file contains reparse point ...");
		}
		else if (FindFileData.dwFileAttributes == FILE_ATTRIBUTE_ARCHIVE) {
			log_debug("file contains directory reparse point ...");
		}
		else if (FindFileData.dwReserved0 == IO_REPARSE_TAG_SYMLINK) {
			log_debug("file is a symbolic link to file ...");
		}
		else if (IO_REPARSE_TAG_MOUNT_POINT == FindFileData.dwReserved0) {
			log_debug("this file is JUNCTION ...");
		}
		log_debug("File Attributes : %ld", FindFileData.dwFileAttributes);
		HANDLE target_handle = CreateFile(path, FILE_GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL, NULL);
		if (target_handle == INVALID_HANDLE_VALUE) {
			log_error("couldn't get handle to file");
			return -2;
		}
		int req_size = 32767 + 8;
		char *_buffer;
		_buffer = (char *)malloc(sizeof(wchar_t)* req_size + sizeof(REPARSE_DATA_BUFFER));
		if (_buffer == NULL) {
			log_error("Can't allocate memory for _buffer");
			CloseHandle(target_handle);
			return -3;
		}
		REPARSE_DATA_BUFFER *reparse_buffer;
		reparse_buffer = (REPARSE_DATA_BUFFER *)(_buffer);
		DWORD reparse_buffer_read_size = 0;
		DeviceIoControl(target_handle, FSCTL_GET_REPARSE_POINT, NULL, 0, reparse_buffer, sizeof(REPARSE_DATA_BUFFER) + req_size, &reparse_buffer_read_size, NULL);
		WCHAR *w_complete_path_pname = NULL, *w_complete_path_sname = NULL;
		char *complete_path_pname = NULL, *complete_path_sname = NULL;
		int clength = -1, wlength = -1;
		if (reparse_buffer->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
			//its a symbolic link
			log_debug("unparsed length : %d", reparse_buffer->Reserved);
			if (reparse_buffer->SymbolicLinkReparseBuffer.Flags == 0) {
				log_debug("absolute path : length : %ld", reparse_buffer->SymbolicLinkReparseBuffer.Flags);
			}
			else {
				log_debug("relative path : length : %ld", reparse_buffer->SymbolicLinkReparseBuffer.Flags);
			}
			wlength = reparse_buffer->SymbolicLinkReparseBuffer.PrintNameLength / sizeof(WCHAR) + 1;
			w_complete_path_pname = (WCHAR *)malloc(sizeof(WCHAR) * wlength);
			if (w_complete_path_pname == NULL) {
				log_error("Can't allocate memory for w_complete_path_pname");
				target_buf_size = -3;
				goto return_target_link;
			}
			strncpy_s(w_complete_path_pname, wlength, reparse_buffer->SymbolicLinkReparseBuffer.PathBuffer + (reparse_buffer->SymbolicLinkReparseBuffer.PrintNameOffset / sizeof(WCHAR)),
				reparse_buffer->SymbolicLinkReparseBuffer.PrintNameLength / sizeof(WCHAR) + 1);
			log_debug("wide char Path : %s", w_complete_path_pname);
			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_pname, wlength, 0, 0, 0, 0);
			complete_path_pname = (char *)malloc(sizeof(CHAR)* clength);
			if (complete_path_pname == NULL) {
				log_error("Can't allocate memory for complete_path_pname");
				target_buf_size = -3;
				goto return_target_link;
			}
			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_pname, wlength, complete_path_pname, clength, 0, 0);
			if (clength == 0) {
				log_error("conversion from wchar to char fails");
				target_buf_size = -1;
				goto return_target_link;
			}
			log_debug("char path print name : %s", complete_path_pname);

			//appending unparsed path
			if (strnlen_s(target_buf, target_buf_size) > 0) {
				int target_buf_length = strnlen_s(complete_path_pname, clength) + (strnlen_s(path, MAX_LEN) - reparse_buffer->Reserved);
				if (target_buf_length > target_buf_size) {
					target_buf = realloc(target_buf, target_buf_length);
					target_buf_size = target_buf_length;
				}
				if (target_buf == NULL) {
					target_buf_size = -3;
					goto return_target_link;
				}
				//target_buf = (char *)malloc(target_buf_length * sizeof(char));
				strcpy_s(target_buf, target_buf_size, complete_path_pname);
				strcat_s(target_buf, target_buf_size, (path + (strnlen_s(path, MAX_LEN) - reparse_buffer->Reserved)));
				goto return_target_link;
			}

			//extract name from substitutestring
			wlength = reparse_buffer->SymbolicLinkReparseBuffer.SubstituteNameLength;
			w_complete_path_sname = (WCHAR *)malloc(sizeof(WCHAR)*wlength);
			if (w_complete_path_sname == NULL) {
				log_error("Can't allocate memory for w_complete_path_sname");
				target_buf_size = -3;
				goto return_target_link;
			}
			strncpy_s(w_complete_path_sname, wlength, reparse_buffer->SymbolicLinkReparseBuffer.PathBuffer + (reparse_buffer->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(WCHAR)),
				reparse_buffer->SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(WCHAR) + 1);

			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_sname, wlength, 0, 0, 0, 0);
			complete_path_sname = (char *)malloc(sizeof(CHAR) * clength);
			if (complete_path_sname == NULL) {
				log_error("can't allocate memory for sustitute string name");
				target_buf_size = -3;
				goto return_target_link;
			}
			memset(complete_path_sname, 0, clength);
			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_sname, wlength, complete_path_sname, clength, 0, 0);
			if (clength == 0) {
				log_error("conversion from wchar to char failed");
				if (strnlen_s(complete_path_pname, clength) == 0) {
					target_buf_size = -3;
					goto return_target_link;
				}
			}
			log_debug("char path substitute name : %s", complete_path_sname);

			//need to remove \\?\ from path
			int target_buf_length = strnlen_s(complete_path_sname, clength) + (strnlen_s(path, MAX_LEN) - reparse_buffer->Reserved);
			if (target_buf_length > target_buf_size) {
				target_buf = realloc(target_buf, target_buf_length);
				target_buf_size = target_buf_length;
			}
			if (target_buf == NULL) {
				target_buf_size = -3;
				goto return_target_link;
			}
			//target_buf = (char *)malloc(target_buf_length * sizeof(char));
			if (strstr(complete_path_sname, "\\\\?\\") != NULL) {
				// if it contains windows convention of preceding "\\?\" in path
				strcpy_s(target_buf, target_buf_size, &complete_path_sname[4]);
			}
			else {
				//if its a relative path
				strcpy_s(target_buf, target_buf_size, complete_path_sname);
			}
			strcat_s(target_buf, target_buf_size, (path + (strnlen_s(path, MAX_LEN) - reparse_buffer->Reserved)));
			log_debug("after adding unparsed path : %s", target_buf);
		}
		else if (reparse_buffer->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
			// its junction or mount point
			log_debug("unparsed length : %d", reparse_buffer->Reserved);
			wlength = reparse_buffer->MountPointReparseBuffer.PrintNameLength / sizeof(WCHAR) + 1;
			w_complete_path_pname = (WCHAR *)malloc(sizeof(WCHAR) * wlength);
			if (w_complete_path_pname == NULL) {
				log_error("Can't allocate memory for w_complete_path_pname");
				target_buf_size = -3;
				goto return_target_link;
			}
			strncpy_s(w_complete_path_pname, wlength, reparse_buffer->MountPointReparseBuffer.PathBuffer + (reparse_buffer->MountPointReparseBuffer.PrintNameOffset / sizeof(WCHAR)),
				reparse_buffer->MountPointReparseBuffer.PrintNameLength / sizeof(WCHAR) + 1);
			log_debug("wide char Path : %s", w_complete_path_pname);

			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_pname, wlength, 0, 0, 0, 0);
			if (clength > target_buf_size) {
				target_buf = realloc(target_buf, clength);
				target_buf_size = clength;
			}
			//complete_path_pname = (char *)malloc(sizeof(CHAR)* clength);
			if (target_buf == NULL) {
				target_buf_size = -3;
				goto return_target_link;
			}
			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_pname, wlength, target_buf, clength, 0, 0);
			if (clength == 0) {
				log_error("conversion from wchar to char fails");
				target_buf_size = -1;
				goto return_target_link;
			}
			log_debug("char path print name : %s", target_buf);
			if (strnlen_s(target_buf, target_buf_size) > 0) {
				goto return_target_link;
			}
			//extract name from substitutestring
			wlength = reparse_buffer->MountPointReparseBuffer.SubstituteNameLength;
			w_complete_path_sname = (WCHAR *)malloc(sizeof(WCHAR)*wlength);
			if (w_complete_path_sname == NULL) {
				log_error("Can't allocate memory for w_complete_path_sname");
				target_buf_size = -3;
				goto return_target_link;
			}
			strncpy_s(w_complete_path_sname, wlength, reparse_buffer->MountPointReparseBuffer.PathBuffer + (reparse_buffer->MountPointReparseBuffer.SubstituteNameOffset / sizeof(WCHAR)),
				reparse_buffer->MountPointReparseBuffer.SubstituteNameLength / sizeof(WCHAR) + 1);

			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_sname, wlength, 0, 0, 0, 0);
			if (clength > target_buf_size) {
				target_buf = realloc(target_buf, clength);
				target_buf_size = clength;
			}
			//complete_path_sname = (char *)malloc(sizeof(CHAR) * clength);
			if (target_buf == NULL) {
				log_error("reallocation for memroy failed");
				target_buf_size = -3;
				goto return_target_link;
			}
			clength = WideCharToMultiByte(CP_OEMCP, WC_NO_BEST_FIT_CHARS, w_complete_path_sname, wlength, target_buf, clength, 0, 0);
			if (clength == 0) {
				log_error("conversion from wchar to char failed");
				target_buf_size = -2;
				goto return_target_link;
			}
			//remove \\?\ from target_buf
			if (strstr("\\\\?\\", target_buf) != NULL) {
				memmove_s(target_buf, target_buf_size, target_buf + 4, clength - 4);
			}
			log_debug("char path substitute name : %s", target_buf);

		}
		else{
			//this gives the complete path when path contains an junction in it
			int target_len = GetFinalPathNameByHandle(target_handle, target_buf, target_buf_size, VOLUME_NAME_DOS);
			if (target_len >= target_buf_size){
				target_buf = realloc(target_buf, target_len);
				target_buf_size = target_len;
				if (target_buf == NULL){
					log_error("can't reallocate memory for target buff");
					target_buf_size = -3;
					goto return_target_link;
				}
				target_len = GetFinalPathNameByHandle(target_handle, target_buf, target_buf_size, VOLUME_NAME_DOS);
			}
			//remove \\?\ from target
			if (strstr("\\\\?\\", target_buf) != NULL) {
				memmove_s(target_buf, target_buf_size, target_buf + 4, target_len - 3);
			}
			log_debug("size of target : %d & target of link is : %s", target_len, target_buf);
		}
	return_target_link:
		if (_buffer) {
			free(_buffer);
		}
		if (w_complete_path_pname) {
			free(w_complete_path_pname);
		}
		if (w_complete_path_sname) {
			free(w_complete_path_sname);
		}
		if (complete_path_pname) {
			free(complete_path_pname);
		}
		if (complete_path_sname){
			free(complete_path_sname);
		}
		CloseHandle(target_handle);
		return target_buf_size;
	}
}
#endif

/*
* getSymLinkValue:
* @path : path of the file/symbolic link
*
* Returns the actual value for the symbolic link provided as input
*/
int getSymLinkValue(char *path, int version) {
	char symlinkpath[512];
    char sympathroot[512];
#ifdef _WIN32
	// Check if the file path is a symbolic link
	if (ISLINK(path) == 0) {
		// If symbolic link doesn't exists read the path its pointing to
		int len = readlink(path, symlinkpath, sizeof(symlinkpath));
		if (len < 0) {
			log_error("Error occured in reading link");
			return -1;
		}
		log_debug("Symlink %s points to %s", path, symlinkpath);

		// If the path is starting with ":" and 'fs_mount_path' is not appended
		if (((strstr(symlinkpath, ":") - symlinkpath) == 1) && (strstr(symlinkpath, fs_mount_path) == NULL)) {
			snprintf(sympathroot, len, "%s%s", fs_mount_path, symlinkpath + 2);
			log_debug("Absolute symlink path %s points to %s", symlinkpath, sympathroot);
		}
		else {
			char* last_backslash = strrchr(path, '\\');
			if (last_backslash) {
				*last_backslash = '\0';
			}
			snprintf(sympathroot, len, "%s%s%s", path, "\\", symlinkpath);
			log_debug("Relative symlink path %s points to %s", symlinkpath, sympathroot);
		}

		strcpy_s(path, strnlen_s(sympathroot, len) + 1, sympathroot);
		if(version == 2) {
            	    strcpy_s(path, MAX_LEN, symlinkpath);
		} else {
	    	    return getSymLinkValue(path, version);
		}
	}
	else {
		log_error("Not a valid Symlink - %s", path);
		return -1;
	}
#elif __linux__
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
	} else {
	    return getSymLinkValue(path, version);
	}
    }
	else {
		log_error("Not a valid Symlink - %s", path);
		return -1;
	}
#endif
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
#ifdef _WIN32
	strtok_s(dhash, delim, &next_token);
#elif __linux__
	strtok_s(dhash,&dhash_max,delim,&next_token);
#endif
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
#ifdef _WIN32
	snprintf(Cmd_Str, sizeof(Cmd_Str), "Powershell \"Get-ChildItem -recurse '%s' | Where-Object { $_.FullName -cmatch '%s$'.replace('\\','\\\\') } | Foreach-Object { Write-Output $_.FullName.remove(0, %d) }\"", bPath, mPath, slen);
#elif __linux__
	snprintf(Cmd_Str, sizeof(Cmd_Str), "find \"%s\" -regex \"%s\" -type %c | sed -r 's/.{%d}//'", bPath, mPath, file_type, slen);
#endif
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
#ifdef _WIN32
		slen = slen - 1;
		if (strcmp(include, "") != 0 && strcmp(exclude, "") != 0)
			snprintf(Cmd_Str, sizeof(Cmd_Str), "Powershell \"Get-ChildItem '%s' | Where-Object {! $_.PSIsContainer}"
			" | Where-Object { $_.FullName.remove(0, %d) -cmatch '%s' -and $_.FullName.remove(0, %d) -cnotmatch '%s' }"
			" | Foreach-Object { Write-Output $_.FullName.remove(0, %d).replace('\\','/') } | Sort-Object\"",
			dir_name_buff, slen, include, slen, exclude, slen);
		else if (strcmp(include, "") != 0)
			snprintf(Cmd_Str, sizeof(Cmd_Str), "Powershell \"Get-ChildItem '%s' | Where-Object {! $_.PSIsContainer}"
			" | Where-Object { $_.FullName.remove(0, %d) -cmatch '%s' }"
			" | Foreach-Object { Write-Output $_.FullName.remove(0, %d).replace('\\','/') } | Sort-Object\"",
			dir_name_buff, slen, include, slen);
		else if (strcmp(exclude, "") != 0)
			snprintf(Cmd_Str, sizeof(Cmd_Str), "Powershell \"Get-ChildItem '%s' | Where-Object {! $_.PSIsContainer}"
			" | Where-Object { $_.FullName.remove(0, %d) -cnotmatch '%s' }"
			" | Foreach-Object { Write-Output $_.FullName.remove(0, %d).replace('\\','/') } | Sort-Object\"",
			dir_name_buff, slen, exclude, slen);
		else
			snprintf(Cmd_Str, sizeof(Cmd_Str), "Powershell \"Get-ChildItem '%s' | Where-Object {! $_.PSIsContainer}"
			" | Foreach-Object { Write-Output $_.FullName.remove(0, %d).replace('\\','/') } | Sort-Object\"",
			dir_name_buff, slen);
#elif __linux__
		if(strcmp(include,"") != 0 && strcmp(exclude,"") != 0 )
			snprintf(Cmd_Str, sizeof(Cmd_Str), "find \"%s\" -maxdepth 1 ! -type d | sed -r 's/.{%d}//' | grep -E  \"%s\" | grep -vE \"%s\" | LANG=C sort",dir_name_buff, slen, include, exclude);
		else if(strcmp(include,"") != 0)
			snprintf(Cmd_Str, sizeof(Cmd_Str), "find \"%s\" -maxdepth 1 ! -type d | sed -r 's/.{%d}//' | grep -E  \"%s\" | LANG=C sort",dir_name_buff, slen, include);
		else if(strcmp(exclude,"") != 0)
			snprintf(Cmd_Str, sizeof(Cmd_Str), "find \"%s\" -maxdepth 1 ! -type d | sed -r 's/.{%d}//' | grep -vE \"%s\" | LANG=C sort",dir_name_buff, slen, exclude);
		else
			snprintf(Cmd_Str, sizeof(Cmd_Str), "find \"%s\" -maxdepth 1 ! -type d | sed -r 's/.{%d}//' | LANG=C sort",dir_name_buff, slen);
#endif
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
