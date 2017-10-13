/*
 * createNG.c
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <time.h>
#include <getopt.h>
#include <string.h>
#include <math.h>

#include "cmdlineCreateNG.h"
#include "common.h"
#include "commonStructs.h"
#include "createNG.h"
#include "smoothing.h"

// == global variables ==
// all global pointer should be freed in the exit_routine()

// struct for nGram, initalProb and length array for counts
nGram_struct *glbl_nGramCount = NULL;
uint64_t glbl_countSums[ARRAY_TYPES_COUNT] = { 0, 0, 0, 0 };  // access via the arrayType-enum (arrayType_nGram = 0, arrayType_initialProb, arrayType_endProb, arrayType_length)

// These global variables can be (or must be) set by command line arguments
// the default values are set in initializes() (if any)

// struct for filename of all output files (nGram, initialProb, length and config)
struct filename_struct *glbl_filenames = NULL;  // each should not be larger then [FILENAME_MAX - MAX_ATTACHMENT_LENGTH]

// Alphabet and size of Alphabet
struct alphabet_struct *glbl_alphabet = NULL;

char glbl_maxLevel = MAX_LEVEL;

// Modes:
bool glbl_verboseFileMode = false;  // write additional information to output files (the actual nGrams are written to the files as well)
bool glbl_verboseMode = false;  // print information to stdout during run time
bool glbl_countedPasswordList = false;  // if TRUE the password list read is interpreted as counted one
bool glbl_storeWarnings = false;  // if TRUE all occurring warnings are saved to HD

struct gengetopt_args_info glbl_args_info;

int main (int argc, char *argv[])
{
  // let's call our cmdline parser
  if (cmdline_parser (argc, argv, &glbl_args_info) != 0)
  {
    printf ("failed parsing command line arguments\n");
    exit (EXIT_FAILURE);
  }
  // set exit_routine so thats automatically called
  atexit (exit_routine);

  // initialize global parameters
  initialize ();

  // evaluate given arguments
  if (!evaluate_arguments (&glbl_args_info))
  {
    exit (1);
  }

  // print selected mode and filenames
  if (glbl_verboseMode)
    print_settings_createNG (stdout);

  // run nGram creation
  if (!run_creation ())
    exit (1);

  exit (EXIT_SUCCESS);
}                               // main

// initializes the values with their defaults values
void initialize ()
{
  // set time stamp
  set_timestampWithDiff (stdout, false, false);
  // setting default values for all global parameters

  // initialize, allocate and copy default values for filenames struct
  struct_filenames_initialize (&glbl_filenames);
  struct_filenames_allocateDefaults (glbl_filenames);

  // initialize, allocate and copy default values for alphabet struct
  struct_alphabet_initialize (&glbl_alphabet);
  struct_alphabet_allocateDefaults (glbl_alphabet);

  // initialize and allocate nGram struct
  struct_nGrams_initialize (&glbl_nGramCount);
  struct_nGrams_allocate (glbl_nGramCount, glbl_alphabet);

  // initialize smoothing functions
  smoo_initialize ();
}                               // initialize

// exit routine, frees any allocated memory (for global variables)
void exit_routine ()
{
  if (exit_status != -1)
  {                             // -1 = exit after printing help text
    if (glbl_verboseMode)
    {
      // print timestamp
      set_timestampWithDiff (stdout, glbl_verboseMode, true);
    }

    switch (exit_status)
    {
    case 0:                    // success
      if (glbl_verboseMode)
        puts ("Status: done");
      break;
    default:                   // error
      printf ("Status: aborted(%i)\n", exit_status);
      break;
    }
  }

  // count arrays
  struct_nGrams_free (&glbl_nGramCount);
  // alphabet
  struct_alphabet_free (&glbl_alphabet);
  // filenames
  struct_filenames_free (&glbl_filenames);

  errorHandler_finalize ();
  cmdline_parser_free (&glbl_args_info);  // release allocated memory
}                               // exit_routine

// evaluates command line parameters
bool evaluate_arguments (struct gengetopt_args_info *args_info)
{
  bool dateSuffix = false;      // TRUE, if the current date and time should be appended to the filenames
  bool nGramChanges = false;    // TRUE, if the size of the nGram arrays must be adjusted
  char *prefix = NULL;          // Temporary variable storing a possible prefix
  char *suffix = NULL;          // Temporary variable storing a possible suffix

  bool result = true;

  // set wether to print warnings or not
  errorHandler_init (args_info->printWarnings_flag);

  if (args_info->cPout_given)
  {
    result &= changeFilename (&(glbl_filenames->cP), (FILENAME_MAX - MAX_ATTACHMENT_LENGTH), "condProb", args_info->cPout_arg);
  }

  if (args_info->iPout_given)
  {
    result &= changeFilename (&(glbl_filenames->iP), (FILENAME_MAX - MAX_ATTACHMENT_LENGTH), "initalProb", args_info->iPout_arg);
  }

  if (args_info->ePout_given)
  {
    result &= changeFilename (&(glbl_filenames->eP), (FILENAME_MAX - MAX_ATTACHMENT_LENGTH), "endProb", args_info->ePout_arg);
  }

  if (args_info->lenout_given)
  {
    result &= changeFilename (&(glbl_filenames->len), (FILENAME_MAX - MAX_ATTACHMENT_LENGTH), "length", args_info->lenout_arg);
  }

  if (args_info->config_given)
  {
    result &= changeFilename (&(glbl_filenames->cfg), FILENAME_MAX, "config", args_info->config_arg);
  }

  if (args_info->prefix_given)
  {
    if (!str_allocCpy (&prefix, args_info->prefix_arg))
    {
      errorHandler_print (errorType_Error, "Out of Memory\n");
      return false;
    }
  }

  if (args_info->suffix_given)
  {
    if (!str_allocCpy (&suffix, args_info->suffix_arg))
    {
      errorHandler_print (errorType_Error, "Out of Memory\n");
      return false;
    }
  }

  if (args_info->datefix_flag)
  {
    dateSuffix = true;
  }

  if (args_info->ngram_given)
  {
    glbl_nGramCount->sizeOf_N = args_info->ngram_arg;
    nGramChanges = true;
  }

  if (args_info->maxLevel_given)
  {
    glbl_maxLevel = args_info->maxLevel_arg;
  }

  if (args_info->alphabet_given)
  {
    // try to copy the new alphabet
    if (!str_allocCpy (&(glbl_alphabet->alphabet), args_info->alphabet_arg))
    {
      errorHandler_print (errorType_Error, "Out of Memory\n");
      return false;
    }
    // set the size of the new alphabet
    glbl_alphabet->sizeOf_alphabet = strlen (args_info->alphabet_arg);
    nGramChanges = true;
  }

  if (args_info->fAlphabet_given)
  {
    result &= alphabetFromFile (&(glbl_alphabet->alphabet), &(glbl_alphabet->sizeOf_alphabet), args_info->fAlphabet_arg);
    nGramChanges = true;
  }

  if (args_info->smoothing_given)
  {
    if (smoo_readInput (args_info->smoothing_arg))
      result &= changeFilename (&(glbl_filenames->smoo), (FILENAME_MAX - MAX_ATTACHMENT_LENGTH), "smoothing", args_info->smoothing_arg);
  }

  if (args_info->verbose_flag)
  {
    glbl_verboseMode = true;
  }

  if (args_info->verboseFile_flag)
  {
    glbl_verboseFileMode = true;
  }

  if (args_info->withCount_flag)
  {
    glbl_countedPasswordList = true;
  }

  if (!result)
  {
    return result;
  }

  if (!append_prefixSuffix (&prefix, &suffix, dateSuffix, glbl_filenames))
  {
    errorHandler_print (errorType_Error, "Out of Memory\n");
    return false;
  }
  // if the alphabet or the size of N has been changed, nGram and initalProb have to be reallocated
  if (nGramChanges)
    struct_nGrams_allocate (glbl_nGramCount, glbl_alphabet);

  // allocate memory and copy filename
  glbl_filenames->pwList = (char *) malloc (sizeof (char) * strlen (args_info->iPwdList_arg));
  if (glbl_filenames->pwList == NULL)
  {
    errorHandler_print (errorType_Error, "Out of Memory\n");
    return false;
  }
  strcpy (glbl_filenames->pwList, args_info->iPwdList_arg);

  return result;
}                               // evaluate_arguments

// main process, calls all read and write functions
bool run_creation ()
{
  // read ip counts, n-grams and pwd length from in-file
  if (!evaluate_inputFile (glbl_filenames->pwList))
    return false;

  // write config file
  if (!write_config ((glbl_filenames->cfg)))
    return false;

  // write NG counts and NG levels to disk
  if (!write_array ((glbl_filenames->cP), arrayType_conditionalProb))
    return false;

  // write iP count and levels to disk
  if (!write_array ((glbl_filenames->iP), arrayType_initialProb))
    return false;

  // write eP count and levels to disk
  if (!write_array ((glbl_filenames->eP), arrayType_endProb))
    return false;

  // write password length count and levels to disk
  if (!write_array ((glbl_filenames->len), arrayType_length))
    return false;

  return true;
}                               // run_creation

/* (intern function) Adds the length of the given line to the global array length. */
void adjust_length (int length, // the length of the current line
                    int count)  // the count of the current password (1 if the counted mode is disabled)
{
  if (length >= MAX_PASSWORD_LENGTH)
  {
    count = 1;
    length = MAX_PASSWORD_LENGTH - 1;
  }
  glbl_countSums[arrayType_length] += count;
  (glbl_nGramCount->len)[length] += count;
}                               // (intern) adjust_length

/* (intern function) Determines the first (n-1)-gram of the current line and increases the correlated value in the global array initialProb (increasing the count of this (n-1)-gram). */
void adjust_initialProb (const char *curPassword, // the current password
                         int count, // the count of the current password (1 if the counted mode is disabled)
                         int lineNumber)  // the current line of the input file (for a formatted error message)
{
  int position = 0;

  if (get_positionFromNGram (&position, curPassword, (glbl_nGramCount->sizeOf_N) - 1, (glbl_alphabet->sizeOf_alphabet), (glbl_alphabet->alphabet)))
  {
    glbl_countSums[arrayType_initialProb] += count;
    (glbl_nGramCount->iP)[position] += count;
  }
  else
  {                             // (unknown symbol occurred)... set a warning
    errorHandler_print (errorType_Warning, "IP in line %i contains an unknown symbol and will be ignored.\n", lineNumber);
  }
}                               // (intern) adjust_initialProb

/* (intern function) Determines all n-gram of the current line and increases the correlated values in the global array ngram (increasing the count of these n-gram). */
void adjust_nGram (const char *curPassword, // the current password
                   int length,  // the length of the current line
                   int count,   // the count of the current password (1 if the counted mode is disabled)
                   int lineNumber)  // the current line of the input file (for a formatted error message)
{
  int position = 0;
  bool unknownSymbol = false;

  // loop over current Line to get all n-grams
  for (size_t i = 0; i < length - ((glbl_nGramCount->sizeOf_N) - 1); i++)
  {
    // printf("%s\n", curLine+i);
    if (get_positionFromNGram (&position, curPassword + i, (glbl_nGramCount->sizeOf_N), (glbl_alphabet->sizeOf_alphabet), (glbl_alphabet->alphabet)))
    {
      // printf("%i / %i\n", position, glbl_nGramCounts->sizeOf_nG);
      glbl_countSums[arrayType_conditionalProb] += count;
      (glbl_nGramCount->cP)[position] += count;
    }
    else
    {
      unknownSymbol = true;
    }
  }
  if (unknownSymbol)
  {                             // (unknown symbol occurred)... set a warning
    errorHandler_print (errorType_Warning, "nGram(s) in line %i contains an unknown symbol and will be ignored.\n", lineNumber);
  }
}                               // (intern) adjust_nGram

/* (intern function) Determines the last (n-1)-gram of the current line and increases the correlated value in the global array endProb (increasing the count of this (n-1)-gram). */
void adjust_endProb (const char *curPassword, // the current password
                     int length,  // the length of the current line
                     int count, // the count of the current password (1 if the counted mode is disabled)
                     int lineNumber)  // the current line of the input file (for a formatted error message)
{
  int position = 0;
  int i = length - ((glbl_nGramCount->sizeOf_N) - 1); // start index of the last N-1 chars

  if (get_positionFromNGram (&position, curPassword + i, (glbl_nGramCount->sizeOf_N) - 1, (glbl_alphabet->sizeOf_alphabet), (glbl_alphabet->alphabet)))
  {
    glbl_countSums[arrayType_endProb] += count;
    (glbl_nGramCount->eP)[position] += count;
  }
  else
  {                             // (unknown symbol occurred)... set a warning
    errorHandler_print (errorType_Warning, "EP in line %i contains an unknown symbol and will be ignored.\n", lineNumber);
  }
}                               // (intern) adjust_endProb

/* (intern function) returns TRUE and sets @line to the current line of @fp if the line dosen't exceed the line buffer. Any line that exceeds will be skipped (and a warning will be set). Returns false if eof is reached. */
bool get_nextLine (char line[MAX_LINE_LENGTH + 1], int *lineNumber, FILE * fp)
{
  static bool skipLine = false;

  while (fgets (line, MAX_LINE_LENGTH, fp))
  {
    // if the line is to long (no new line token and NOT at the end of the file [eof]) -> continue
    if (line[strlen (line) - 1] != '\n' && !feof (fp))
    {
      skipLine = true;
    }
    // line got a '\n' but has exceeded the buffer in a previous call of this function
    else if (skipLine)
    {
      // ... set a warning
      (*lineNumber)++;
      skipLine = false;

      errorHandler_print (errorType_Warning, "Line %i has exceeded the line buffer and will be ignored.\n", *lineNumber);
    }
    else
    {
      (*lineNumber)++;
      return true;
    }
  }
  return false;
}                               // (intern) get_nextLine

// evaluates given input file setting the count arrays accordingly
bool evaluate_inputFile (const char *filenameIn)
{
  FILE *fp = NULL;              // pointer on input file
  char curLine[MAX_LINE_LENGTH + 1];  // current line
  char curPassword[MAX_LINE_LENGTH + 1];
  int lineLength = 0;           // current line length
  int lineNumber = 0;           // counts the number of lines read
  int passwordCount = 1;        // the count of the current Password (for countedPaswordList mode)

  // open file and check file
  if (!(open_file (&fp, filenameIn, NULL, "r")))
  {
    return false;
  }

  // reset arrays
  memset ((glbl_nGramCount->cP), 0, (glbl_nGramCount->sizeOf_cP) * sizeof (int));
  memset ((glbl_nGramCount->iP), 0, (glbl_nGramCount->sizeOf_iP) * sizeof (int));
  memset ((glbl_nGramCount->eP), 0, (glbl_nGramCount->sizeOf_eP) * sizeof (int));
  memset ((glbl_nGramCount->len), 0, (glbl_nGramCount->sizeOf_len) * sizeof (int));

  // till the end of file (or if reading successfull...)
  while (get_nextLine (curLine, &lineNumber, fp))
  {
    // if the given file has counted passwords
    if (glbl_countedPasswordList)
    {                           // read counted password
      char curCount[MAX_LINE_LENGTH + 1];

      sscanf (curLine, "%s %s", curCount, curPassword); // this cuts '\n' if any
      passwordCount = atoi (curCount);
      // reject entry if count isn't formated correctly
      if (passwordCount <= 0)
      {
        // ... set a warning and continue with next line
        errorHandler_print (errorType_Warning, "Can't evaluate the counts in line %i.\n", lineNumber);
        continue;
      }
      lineLength = strlen (curPassword);
    }
    else
    {                           // read uncounted password
      strcpy (curPassword, curLine);
      lineLength = strlen (curPassword);
      // check for newline and cut it out ...
      if (curPassword[lineLength - 1] == '\n')
      {
        curPassword[lineLength - 1] = '\0';
        lineLength--;
      }
    }
    if (lineLength < (glbl_nGramCount->sizeOf_N) - 1)
    {
      errorHandler_print (errorType_Warning, "Line %i has not enough characters and will be ignored.\n", lineNumber);
    }
    else if (lineLength >= MAX_PASSWORD_LENGTH)
    {
      errorHandler_print (errorType_Warning, "Line %i has to many characters and will be ignored.\n", lineNumber);
    }
    else
    {
      adjust_length (lineLength, passwordCount);
      adjust_initialProb (curPassword, passwordCount, lineNumber);
      if (lineLength >= (glbl_nGramCount->sizeOf_N))
      {
        adjust_nGram (curPassword, lineLength, passwordCount, lineNumber);
      }
      else
      {
        errorHandler_print (errorType_Warning, "Line %i has not enough characters. Only initial probability will be calculated.\n", lineNumber);
      }
      adjust_endProb (curPassword, lineLength, passwordCount, lineNumber);
    }
  }

  // clean up
  if (fp != NULL)
  {
    fclose (fp);
    fp = NULL;
  }

  return true;
}                               // evaluate_InputFile

/* (intern functions) writes header information into the given file @fp, adding the @title into the header the stored information are alphabet, sizeOf_N and other factors header syntax: # name value \n */
void write_headerToFile (char *title, FILE * fp)
{
  struct tm *ptr;
  time_t lt;

  lt = time (NULL);
  ptr = localtime (&lt);

  fprintf (fp, "### %s for input file <%s> ", title, glbl_filenames->pwList);
  fprintf (fp, "on %s", asctime (ptr));
  fprintf (fp, "### with the following settings:\n");
  fprintf (fp, "# -alphabet %s\n", (glbl_alphabet->alphabet));
  fprintf (fp, "# -alphabetsize %i \n", (glbl_alphabet->sizeOf_alphabet));
  fprintf (fp, "# -ngram %i \n", (glbl_nGramCount->sizeOf_N));
  fprintf (fp, "# -maxLevel %i \n", (glbl_maxLevel));
  fprintf (fp, "# -verbose %i \n", glbl_verboseFileMode);
  smoo_printSelection (fp, true);
}                               // (intern) write_header_ToFile

/* (intern function) Writes all counts and level in @nGramArray (array with a size of @sizeOf_nGramArray) into the FILE fp. The levels are calculated from @nGramArray, using the smoothing function defined by @smooFunct. The function is able to write the counts into a file regardlessly of nGram Size! The @writeMode should be set accordingly to the verbose-mode. */
bool write_arrayToFile (const int *nGramArray,  // containing the nGrams
                        int sizeOf_nGramArray,  // size of the given array
                        int sizeOf_N, // must be equal to the nGram-size of the nGrams stored in array
                        unsigned long long int totalSum,  // total sum of all counts in the given array
                        enum writeModes writeMode,  // write Mode - numeric, nGram or nonVerbose
                        SMOOTHING_CALLER (smoothingCaller), // selected smoothing function (pointer to one smothingCaller)
                        FILE * fp_count,  // file pointer (must point to an opened file) for count
                        FILE * fp_level)  // file pointer (must point to an opened file) for level
{
  char nGram[sizeOf_N];         // current nGram determined by get_nGramFromPosition
  char level;                   // level calculated depending on smooth function

  nGram[sizeOf_N] = '\0';

  // write according to write mode
  switch (writeMode)
  {
  case writeMode_nGram:        // write actual nGrams as well
    for (size_t i = 0; i < sizeOf_nGramArray; i++)
    {
      // get the actual nGram based on the current position to print to the file
      get_nGramFromPosition (nGram, i, sizeOf_N, (glbl_alphabet->sizeOf_alphabet), (glbl_alphabet->alphabet));
      // smooth the level using the current smoothing function
      smoothingCaller (&level, i, nGramArray, sizeOf_nGramArray, sizeOf_N, (glbl_alphabet->sizeOf_alphabet), glbl_maxLevel, totalSum);
      fprintf (fp_level, "%i\t%s\n", level, nGram);
      fprintf (fp_count, "%i\t%s\n", nGramArray[i], nGram);
    }
    break;
  case writeMode_numeric:      // write array index as well
    for (size_t i = 0; i < sizeOf_nGramArray; i++)
    {
      smoothingCaller (&level, i, nGramArray, sizeOf_nGramArray, sizeOf_N, (glbl_alphabet->sizeOf_alphabet), glbl_maxLevel, totalSum);
      fprintf (fp_level, "%i\t%lu\n", level, i + 1);
      fprintf (fp_count, "%i\t%lu\n", nGramArray[i], i + 1);
    }
    break;
  default:                     // writeMode_nonVerbose or any other, just write level
    for (size_t i = 0; i < sizeOf_nGramArray; i++)
    {
      smoothingCaller (&level, i, nGramArray, sizeOf_nGramArray, sizeOf_N, (glbl_alphabet->sizeOf_alphabet), glbl_maxLevel, totalSum);
      fprintf (fp_level, "%i\n", level);
    }
    break;
  }

  if (fp_count != NULL && ferror (fp_count))
    return false;
  if (fp_level != NULL && ferror (fp_level))
    return false;

  return true;
}                               // (intern) write_arrayToFile

// writes config inot given file
bool write_config (const char *filenameConfig)
{
  FILE *fp = NULL;

  if (!(open_file (&fp, filenameConfig, NULL, "w")))
  {
    errorHandler_print (errorType_Error, "file not found %s\n", filenameConfig);
    return false;
  }

  // write default header
  write_headerToFile ("Config", fp);
  // write additional information
  fprintf (fp, "# -cpout %s \n", (glbl_filenames->cP));
  fprintf (fp, "# -ipout %s \n", (glbl_filenames->iP));
  fprintf (fp, "# -epout %s \n", (glbl_filenames->eP));
  fprintf (fp, "# -lenout %s\n", (glbl_filenames->len));
  fprintf (fp, "# -input %s\n", (glbl_filenames->pwList));
  if ((glbl_filenames->smoo) != NULL)
    fprintf (fp, "# -smoo %s\n", (glbl_filenames->smoo));

  if (fp != NULL)
  {
    fclose (fp);
    fp = NULL;
  }

  return true;
}                               // write_config

// writes array of given type into given file
bool write_array (const char *filename, enum arrayTypes arrayType)
{
  FILE *fp_count = NULL;
  FILE *fp_level = NULL;
  enum writeModes writeMode = writeMode_nonVerbose;

  // open files
  if (!(open_file (&fp_level, filename, DEFAULT_FILE_ATTACHMENT_LEVEL, "w")))
  {
    errorHandler_print (errorType_Error, "file not found %s\n", filename);
    return false;
  }
  if (glbl_verboseFileMode)
  {
    if (!(open_file (&fp_count, filename, DEFAULT_FILE_ATTACHMENT_COUNT, "w")))
    {
      errorHandler_print (errorType_Error, "file not found %s\n", filename);
      return false;
    }
  }

  switch (arrayType)
  {
  case arrayType_conditionalProb:
    // if verboseMode is active, set writeMode accordingly and write header to files
    if (glbl_verboseFileMode)
    {
      write_headerToFile ("CP-COUNTS", fp_count);
      write_headerToFile ("CP-LEVELS", fp_level);
      writeMode = writeMode_nGram;
    }
    write_arrayToFile ((glbl_nGramCount->cP), (glbl_nGramCount->sizeOf_cP), (glbl_nGramCount->sizeOf_N), glbl_countSums[arrayType_conditionalProb], writeMode, smoo_selection.nG, fp_count, fp_level);

    break;
  case arrayType_initialProb:
    // if verboseMode is active, set writeMode accordingly and write header to files
    if (glbl_verboseFileMode)
    {
      write_headerToFile ("IP-COUNTS", fp_count);
      write_headerToFile ("IP-LEVELS", fp_level);
      writeMode = writeMode_nGram;
    }
    write_arrayToFile ((glbl_nGramCount->iP), (glbl_nGramCount->sizeOf_iP), (glbl_nGramCount->sizeOf_N) - 1, glbl_countSums[arrayType_initialProb], writeMode, smoo_selection.iP, fp_count, fp_level);
    break;
  case arrayType_endProb:
    // if verboseMode is active, set writeMode accordingly and write header to files
    if (glbl_verboseFileMode)
    {
      write_headerToFile ("EP-COUNTS", fp_count);
      write_headerToFile ("EP-LEVELS", fp_level);
      writeMode = writeMode_nGram;
    }

    write_arrayToFile ((glbl_nGramCount->eP), (glbl_nGramCount->sizeOf_eP), (glbl_nGramCount->sizeOf_N) - 1, glbl_countSums[arrayType_endProb], writeMode, smoo_selection.eP, fp_count, fp_level);
    break;
  case arrayType_length:
    // if verboseMode is active, set writeMode accordingly and write header to count file
    if (glbl_verboseFileMode)
    {
      write_headerToFile ("LN-COUNTS", fp_count);
      write_headerToFile ("LN-LEVELS", fp_level);
      writeMode = writeMode_numeric;
    }
    // write header and levels to file
    write_arrayToFile ((glbl_nGramCount->len), (glbl_nGramCount->sizeOf_len), 1, glbl_countSums[arrayType_length], writeMode, smoo_selection.len, fp_count, fp_level);
    break;

  default:
    errorHandler_print (errorType_Error, "Unknown array type.\n");
    if (fp_count != NULL)
    {
      fclose (fp_count);
      fp_count = NULL;
    }
    if (fp_level != NULL)
    {
      fclose (fp_level);
      fp_level = NULL;
    }
    return false;
  }

  // clean up
  if (fp_count != NULL)
  {
    fclose (fp_count);
    fp_count = NULL;
  }
  if (fp_level != NULL)
  {
    fclose (fp_level);
    fp_level = NULL;
  }
  return true;
}                               // write_array

// prints the selected parameters
void print_settings_createNG (FILE * fp)
{
  if (fp == stdout)
    fprintf (fp, "\nStarting createNG with the following settings:\n");

  if (glbl_countedPasswordList)
    fprintf (fp, " - counted password list\n");
  else
    fprintf (fp, " - not counted password list (use -u to read a counted password list)\n");

  if ((glbl_args_info.printWarnings_flag))
    fprintf (fp, " - print warnings\n");
  else
    fprintf (fp, " - hide warnings (use -w to print warnings)\n");

  if (glbl_storeWarnings)
    fprintf (fp, " - store warnings (createError.log)\n");

  print_settings_default (fp, glbl_nGramCount->sizeOf_N, glbl_alphabet, glbl_filenames, glbl_maxLevel, glbl_verboseFileMode);
  smoo_printSelection (fp, false);
  fprintf (fp, "\n");
}                               // print_selectedMode

// changes alphabet to one read from file filename
bool alphabetFromFile (char **alphabet, int *sizeOf_alphabet, const char *filename)
{
  FILE *fp = NULL;
  char curLine[MAX_LINE_LENGTH + 1];

  // check the length of the filename
  if (strlen (filename) > FILENAME_MAX)
  {
    errorHandler_print (errorType_Error, "The Filename of any input file should not be longer then %i characters.\n", FILENAME_MAX);
    return false;
  }
  // open file and check file
  fp = fopen (filename, "r");
  if (!fp)
  {
    errorHandler_print (errorType_Error, "Unable to open alphabet file.\n");
    return false;
  }
  // if reading successfull...
  if (fgets (curLine, MAX_LINE_LENGTH, fp) != NULL)
  {
    // delete newline if any
    if (curLine[strlen (curLine) - 1] == '\n')
      curLine[strlen (curLine) - 1] = 0;

    // reallocate memory for new size and copy content
    if (!str_allocCpy (alphabet, curLine))
    {
      printf ("Error: Out of Memory\n");
      if (fp != NULL)
      {
        fclose (fp);
        fp = NULL;
      }
      return false;
    }

    // adjust size of the new alphabet
    *sizeOf_alphabet = strlen (*alphabet);  // +1 ?
  }
  else                          // fgets(curLine, 1024, fp) == NULL
  {
    errorHandler_print (errorType_Error, "Unable to read alphabet file (file maybe empty)\n");
    return false;
  }

  if (fp != NULL)
  {
    fclose (fp);
    fp = NULL;
  }

  return true;
}

// append prefix and/or suffixes
bool append_prefixSuffix (char **prefix, char **suffix, bool dateSuffix, filename_struct * filenames)
{
  if (*prefix != NULL)
  {
    // try to append prefix...
    if (!str_appendPrefix (&(filenames->cP), *prefix) ||  // append to nGram
        !str_appendPrefix (&(filenames->iP), *prefix) ||  // append to initialProb
        !str_appendPrefix (&(filenames->eP), *prefix) ||  // append to endProb
        !str_appendPrefix (&(filenames->len), *prefix) || // append to length
        !str_appendPrefix (&(filenames->cfg), *prefix))
    {                           // append to config
      // ... if it fails, free allocated memory of prefix...
      free (*prefix);
      *prefix = NULL;
      // ... and suffix
      CHECKED_FREE (*suffix);
      return false;
    }
    free (*prefix);
    *prefix = NULL;
  }
  if (*suffix != NULL)
  {
    // try to append...
    if (!str_appendSuffix (&(filenames->cP), *suffix) ||  // append to nGram
        !str_appendSuffix (&(filenames->iP), *suffix) ||  // append to initalProb
        !str_appendSuffix (&(filenames->eP), *suffix) ||  // append to endProb
        !str_appendSuffix (&(filenames->len), *suffix) || // append to length
        !str_appendSuffix (&(filenames->cfg), *suffix))
    {                           // append to config
      // ... if it fails, free allocated memory
      free (*suffix);
      *suffix = NULL;
      return false;
    }
    free (*suffix);
    *suffix = NULL;
  }
  if (dateSuffix)
  {
    char timeStr[15];           // 9: date(YY-MM-DD_), 5: time(HH_MM), 1: (\0)

    // generate formated time string
    get_formatedTime (&timeStr);
    // try to append suffix ...
    if (!str_appendSuffix (&(filenames->cP), timeStr) ||  // append to nGram
        !str_appendSuffix (&(filenames->iP), timeStr) ||  // append to initalProb
        !str_appendSuffix (&(filenames->eP), timeStr) ||  // append to endProb
        !str_appendSuffix (&(filenames->len), timeStr) || // append to length
        !str_appendSuffix (&(filenames->cfg), timeStr))
    {                           // append to config
      return false;
    }
  }

  return true;
}
