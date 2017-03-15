/* 
 * evalPW.c
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <time.h>
#include <string.h>
#include <getopt.h>

#include "cmdlineEvalPW.h"
#include "common.h"
#include "evalPW.h"
#include "commonStructs.h"
#include "errorHandler.h"
#include "nGramReader.h"

struct filename_struct *glbl_filenamesIn = NULL;
struct alphabet_struct *glbl_alphabet = NULL;
struct nGram_struct *glbl_nGramLevel = NULL;

char glbl_maxLevel = MAX_LEVEL;
char *glbl_password = NULL;
bool glbl_verboseMode = false;
struct gengetopt_args_info glbl_args_info;

int main (int argc, char **argv)
{
  // let's call our cmdline parser
  if (cmdline_parser (argc, argv, &glbl_args_info) != 0)
  {
    printf ("failed parsing command line arguments\n");
    exit (EXIT_FAILURE);
  }
  // set exit_routine so thats automatically called
  atexit (exit_routine);

  initialize ();

  if (!evaluate_arguments (&glbl_args_info))
    exit (1);

  if (!apply_settings ())
    exit (1);

  if (glbl_verboseMode)
    print_settings ();

  if (!run_evaluation ())
    exit (1);

  exit (EXIT_SUCCESS);
}

void initialize ()
{
  // initializing and setting default values for all global parameters

  // initialize filenames struct
  struct_filenames_initialize (&glbl_filenamesIn);
  // allocate content and copy default values
  struct_filenames_allocateDefaults (glbl_filenamesIn);

  // initialize alphabet struct
  struct_alphabet_initialize (&glbl_alphabet);
  // allocate content and copy default values
  struct_alphabet_allocateDefaults (glbl_alphabet);

  // initialize countArray struct
  struct_nGrams_initialize (&glbl_nGramLevel);
}

// exit routine, frees any allocated memory (for global variables)
void exit_routine ()
{
  // free all pointer using the CHECKED_FREE operation (defined in common.h)
  // count arrays
  struct_nGrams_free (&glbl_nGramLevel);
  // alphabet
  struct_alphabet_free (&glbl_alphabet);
  // filenames
  struct_filenames_free (&glbl_filenamesIn);
  CHECKED_FREE (glbl_password);

  print_timestamp ("End:");

  // check if an error occurred, print out all errors and clear errList
  // TODO print errors:
  cmdline_parser_free (&glbl_args_info);  // release allocated memory
}                               // exit_routine

// evaluates command line parameters
bool evaluate_arguments (struct gengetopt_args_info *args_info)
{
  bool result = true;

  errorHandler_init (args_info->printWarnings_flag);

  if (args_info->config_given)
  {
    result &= changeFilename (&(glbl_filenamesIn->cfg), FILENAME_MAX, "config", args_info->config_arg);
  }

  if (args_info->verbose_flag)
  {
    glbl_verboseMode = true;
  }

  if (errorHandler_errorOccurred ())
  {
    return false;
  }

  if (strlen (args_info->pw_arg) > MAX_PASSWORD_LENGTH)
  {
    errorHandler_print (errorType_Error, "The password should not be longer then %i characters.\n", MAX_PASSWORD_LENGTH);
    return false;
  }
  // allocate memory and copy filename
  glbl_password = (char *) malloc (sizeof (char) * strlen (args_info->pw_arg) + 1);
  if (glbl_password == NULL)
  {
    printf ("Error: Out of Memory\n");
    return false;
  }
  strcpy (glbl_password, args_info->pw_arg);

  return result;
}                               // evaluate_arguments

bool apply_settings ()
{
  if (!read_inputFiles (glbl_nGramLevel, glbl_alphabet, glbl_filenamesIn, &glbl_maxLevel))
    return false;
  return true;
}

// prints the selected parameters
void print_settings ()
{
  printf ("Starting password evaluator\n");
  print_settings_default (stdout, glbl_nGramLevel->sizeOf_N, glbl_alphabet, glbl_filenamesIn, glbl_maxLevel, false);
  printf (" - password to evaluate: %s\n", glbl_password);
  putchar ('\n');
  print_timestamp ("Start:");
}

bool run_evaluation ()
{
  int length = strlen (glbl_password);
  int level = 0;
  int position = 0;

  if (length < glbl_nGramLevel->sizeOf_N - 1)
  {
    errorHandler_print (errorType_Error, "The password to be evaluated is to short.\n");
    return false;
  }
  get_positionFromNGram (&position, glbl_password, glbl_nGramLevel->sizeOf_N - 1, glbl_alphabet->sizeOf_alphabet, glbl_alphabet->alphabet);
  printf ("%i", glbl_nGramLevel->iP[position]);
  level -= glbl_nGramLevel->iP[position];
  for (size_t i = 1; i <= (length - glbl_nGramLevel->sizeOf_N); i++)
  {
    get_positionFromNGram (&position, glbl_password + i, glbl_nGramLevel->sizeOf_N, glbl_alphabet->sizeOf_alphabet, glbl_alphabet->alphabet);
    printf (" + %i", -glbl_nGramLevel->cP[position]);
    level -= glbl_nGramLevel->cP[position];
  }
  printf (" = %i (overall level)\n", level);
  return true;
}
