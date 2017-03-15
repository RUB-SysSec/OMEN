/* 
 * alphabetCreator.c
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <getopt.h>

#include "cmdlineAlphabetCreator.h"
#include "common.h"
#include "alphabetCreator.h"
#include "errorHandler.h"

bool write_frequency ();

char *glbl_filenameAlphabet = NULL;
char *glbl_filenameInput = NULL;
char *glbl_filenameOutput = NULL;

FILE *glbl_FP_input = NULL;
FILE *glbl_FP_output = NULL;

int glbl_alphabetSize = 72;
char *glbl_alphabetBase = NULL;
int64_t glbl_charCount[256];

bool glbl_writeFrequency = true;
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
    exit (EXIT_FAILURE);

  if (!apply_settings ())
    exit (EXIT_FAILURE);
  print_settings ();
  if (!run_creation ())
    exit (EXIT_FAILURE);
  if (glbl_writeFrequency)
  {
    if (!write_frequency ())
      exit (EXIT_FAILURE);
  }
  if (!write_newAlphabet ())
    exit (EXIT_FAILURE);

  exit (EXIT_SUCCESS);
}

void initialize ()
{
  memset (glbl_charCount, 0, sizeof (int) * 256);
}

// exit routine, frees any allocated memory (for global variables)
void exit_routine ()
{
  CHECKED_FREE (glbl_filenameAlphabet);
  CHECKED_FREE (glbl_filenameInput);
  CHECKED_FREE (glbl_filenameOutput);
  CHECKED_FREE (glbl_alphabetBase);

  if (glbl_FP_input != NULL)
  {
    fclose (glbl_FP_input);
    glbl_FP_input = NULL;
  }
  if (glbl_FP_output != NULL)
  {
    fclose (glbl_FP_output);
    glbl_FP_output = NULL;
  }

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

  if (args_info->size_given)
  {
    glbl_alphabetSize = args_info->size_arg;
  }

  if (args_info->alphabet_given)
  {
    result &= changeFilename (&glbl_filenameAlphabet, FILENAME_MAX, "alphabet", args_info->alphabet_arg);
  }

  if (args_info->output_given)
  {
    result &= changeFilename (&glbl_filenameOutput, FILENAME_MAX, "output", args_info->output_arg);
  }

  if (args_info->frequency_flag)
  {
    glbl_writeFrequency = true;
  }

  if (errorHandler_errorOccurred ())
    return false;

  // allocate memory and copy filename
  glbl_filenameInput = (char *) malloc (sizeof (char) * strlen (args_info->pwList_arg) + 1);
  if (glbl_filenameInput == NULL)
  {
    printf ("Error: Out of Memory\n");
    return false;
  }
  strcpy (glbl_filenameInput, args_info->pwList_arg);

  return result;
}                               // evaluate_arguments

bool apply_settings ()
{
  // open input file pointer
  if (glbl_filenameInput == NULL)
  {
    errorHandler_print (errorType_Error, "No input file given.\n");
    return false;
  }
  else
  {
    if (!open_file (&glbl_FP_input, glbl_filenameInput, NULL, "r"))
    {
      errorHandler_print (errorType_Error, "Can't open input file.\n");
      return false;
    }
  }
  // open output file
  if (glbl_filenameOutput == NULL)
  {
    if (!open_file (&glbl_FP_output, "new.alphabet", NULL, "w"))
    {
      errorHandler_print (errorType_Error, "Can't open output file.\n");
      return false;
    }
  }
  else
  {
    if (!open_file (&glbl_FP_output, glbl_filenameOutput, ".alphabet", "w"))
    {
      errorHandler_print (errorType_Error, "Can't open output file.\n");
      return false;
    }
  }
  // read base alphabet
  if (glbl_filenameAlphabet != NULL)
  {
    FILE *fp_alphabet = NULL;
    char line[256 + 1];
    int lineLength;

    if (!open_file (&fp_alphabet, glbl_filenameAlphabet, NULL, "r"))
    {
      errorHandler_print (errorType_Error, "Can't open base alphabet file.\n");
      return false;
    }
    if (fgets (line, 256, fp_alphabet))
    {
      if (!str_allocCpy (&glbl_alphabetBase, line))
      {
        errorHandler_print (errorType_Error, "Can't read base alphabet file.\n");
        if (fp_alphabet != NULL)
        {
          fclose (fp_alphabet);
          fp_alphabet = NULL;
        }
        return false;
      }
      lineLength = strlen (glbl_alphabetBase);
      if (lineLength >= glbl_alphabetSize)
      {
        errorHandler_print (errorType_Error, "Base alphabet larger then alphabet size.\n");
        return false;
      }
      for (size_t i = 0; i < lineLength; i++)
        glbl_charCount[(int) glbl_alphabetBase[i]] = -1;
    }
    if (fp_alphabet != NULL)
    {
      fclose (fp_alphabet);
      fp_alphabet = NULL;
    }
  }
  glbl_charCount[(int) '\n'] = -1;
  glbl_charCount[(int) '\r'] = -1;
  glbl_charCount[(int) '\t'] = -1;
  glbl_charCount[(int) ' '] = -1;

  return true;
}

// prints the selected parameters
void print_settings ()
{
  printf ("Starting alphabet creation\n");
  if (glbl_alphabetBase != NULL)
    printf (" - based on the alphabet: %s\n", glbl_alphabetBase);

  if (glbl_filenameInput != NULL)
    printf (" - input password list: %s\n", glbl_filenameInput);

  if (glbl_filenameOutput != NULL)
    printf (" - output alphabet: %s\n", glbl_filenameOutput);
  else
    printf (" - output alphabet: new.alphabet\n");

  printf (" - size of the new alphabet: %i\n", glbl_alphabetSize);

  if (glbl_writeFrequency)
    printf (" - compute and write frequency (charFrequency.txt)\n");

  putchar ('\n');
  print_timestamp ("Start:");
}

bool run_creation ()
{
  char curLine[MAX_LINE_LENGTH + 1];  // current line
  int lineLength = 0;           // current line length

  while (fgets (curLine, MAX_LINE_LENGTH, glbl_FP_input))
  {
    lineLength = strlen (curLine);
    if (curLine[lineLength - 1] == '\n')
    {
      curLine[lineLength - 1] = '\0';
      lineLength--;
    }

    for (size_t i = 0; i < lineLength; i++)
    {
      if (curLine[i] < 0)
      {
        errorHandler_print (errorType_Warning, "Unknown Character.\n");
      }
      else
      {
        if (glbl_charCount[(unsigned char) curLine[i]] != -1)
          glbl_charCount[(unsigned char) curLine[i]]++;
      }
    }
  }
  return true;
}

bool write_newAlphabet ()
{
  int maxPos = 0;
  int baseLen = 0;

  if (glbl_alphabetBase != NULL)
  {
    fprintf (glbl_FP_output, "%s", glbl_alphabetBase);
    baseLen = strlen (glbl_alphabetBase);
  }

  for (size_t i = baseLen; i < glbl_alphabetSize; i++)
  {
    maxPos = 0;
    for (size_t j = 0; j < 256; j++)
      if (glbl_charCount[j] > glbl_charCount[maxPos])
        maxPos = j;
    fprintf (glbl_FP_output, "%c", (char) maxPos);
    glbl_charCount[maxPos] = -1;
  }
  return true;
}

bool write_frequency ()
{
  double freq = 0.0;
  int64_t sumTotal = 0;
  int tmp_charCount[256];
  int maxPos = 0;

  FILE *charFreq = NULL;

  if (!open_file (&charFreq, "charFrequency.txt", NULL, "w"))
  {
    errorHandler_print (errorType_Error, "Can't open base charFreq file.\n");
    return false;
  }

  for (size_t i = 0; i < 256; i++)
  {
    sumTotal += glbl_charCount[i];
    tmp_charCount[i] = glbl_charCount[i];
  }

  for (size_t i = 0; i < 256; i++)
  {
    maxPos = 0;
    for (size_t j = 0; j < 256; j++)
      if (tmp_charCount[j] > tmp_charCount[maxPos])
        maxPos = j;
    freq = (double) tmp_charCount[maxPos] / (double) sumTotal;
    fprintf (charFreq, "%lu & %c & %.3f%%\n", i + 1, (char) maxPos, freq * 100);
    tmp_charCount[maxPos] = -1;
  }
  return true;
}
