/*
 * measurement.h
 *
 *  Created on: 28-May-2018
 *      Author: Arvind Rawat
 */

#ifndef MEASUREMENT_H_
#define MEASUREMENT_H_

#ifdef _WIN32
#ifdef WML_BUILD
#define WML_DLLPORT __declspec (dllexport)
#else
#define WML_DLLPORT __declspec (dllimport)
#endif
#elif __linux__
#define WML_DLLPORT
#endif

WML_DLLPORT char* measure(char *manifest_xml, char *mount_path);

#endif /* MEASUREMENT_H_ */
