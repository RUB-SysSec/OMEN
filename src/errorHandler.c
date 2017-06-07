/*
 * errorHandler.c
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 */

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "errorHandler.h"
#include "common.h"

bool verboseFlag = false;
bool errorOccurred = false;

void errorHandler_init (bool verbose)
{
  verboseFlag = verbose;
}

void errorHandler_print (enum errorTypes error, const char *const fmt, ...)
{
  errorOccurred = true;
  if (verboseFlag)
  {

    va_list arglist;

    va_start (arglist, fmt);

    va_end (arglist);

    switch (error)
    {
    case errorType_Unspecified_Error:
      fprintf (stderr, "%s", "UNKNOWN ERROR: ");
      break;
    case errorType_Error:
      fprintf (stderr, "%s", "ERROR: ");
      break;
    case errorType_Warning:
      fprintf (stderr, "%s", "WARNING: ");
      break;
    }

    vfprintf (stderr, fmt, arglist);

    va_end (arglist);
  }
}

bool errorHandler_errorOccurred ()
{
  return errorOccurred;
}

void errorHandler_finalize ()
{
  if (errorOccurred && !verboseFlag)
  {
    fprintf (stderr, "%s", "WARNING: Either errors or warnings occured. Enable print warnings to see these.\n");
  }
}
