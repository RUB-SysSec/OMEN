/* 
 * errorHandler.h
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 *
 * Implements a linked-list to store any Error or Warning that may occur during
 * the execution of any OMEN-application. There are functions at the disposal to
 * add a new Error to the list, print all errors as well as to clear all errors.
 *
 * Usage:- Create a new MPW_Error_Handler using errorHandler_new()
 *       - Add a new Error to the linked list using errorHandler_push(), giving
 *         an initialised MPW_Error_Handler, an Error Type and an Error Message
 *       - Print out all Errors of a given MPW_Error_Handler using
 *         errorHandler_print()
 *       - Free any allocated memory of a given MPW_Error_Handler using
 *         errorHandler_clear()
 *
 */

#pragma once

#ifndef ERROR_HANDLER_H_
#define ERROR_HANDLER_H_

#define WARNING_LIMIT 49999

#include "common.h"

/* 
 * Used to identify an error.
 */
enum errorTypes
{ errorType_Unspecified_Error = 0,  // Type for an unknown Error
  errorType_Error = 1,          // Error (-> abort application)
  errorType_Warning = 2
};                              // Warning (can be ignored)

void errorHandler_init (bool verbose);
void errorHandler_print (enum errorTypes error, const char *const fmt, ...);
bool errorHandler_errorOccurred ();
void errorHandler_finalize ();

#endif /* ERROR_HANDLER_H_ */
