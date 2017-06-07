/*
 * enumNG.c
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 */

#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "attackSimulator.h"
#include "boosting.h"
#include "cmdlineEnumNG.h"
#include "common.h"
#include "commonStructs.h"
#include "enumNG.h"
#include "errorHandler.h"
#include "nGramReader.h"
#include "smoothing.h"

// nGram array for the level
nGram_struct *glbl_nGramLevel = NULL; // struct for nGram, initalProb and length array for the level

// nGram_struct *glbl_nGramLevel_user = NULL; // same as above for usernameMode

// alphabet
alphabet_struct *glbl_alphabet = NULL;  // struct containing the current alphabet and alphabet size

// filenames (shouldn't be larger then [FILENAME_MAX])
filename_struct *glbl_filenames = NULL; // struct for filename of all input files (conditionalProb, initialProb, length and config)
char *glbl_filenameTestingSet = NULL; // filename of the file containing the testing set
char *glbl_filenameUsername = NULL; // file that contains username<space>passwords

// sorted lastGram, iP and length structs:
sortedLastGram_struct *glbl_sortedLastGram = NULL;  // stores lastGrams sorted by level and position
sortedIP_struct *glbl_sortedIP = NULL;  // stores iP sorted by level
sortedLength_struct *glbl_sortedLength = NULL;  // stores length sorted by level

// defines modification for the lengths level (used for the struct_fill_sortedLength function)
// default value (-1/0.0) equals disabled length-level-set/-factor
int glbl_lengthLevelSet = -1;   // set all length level to this value before applieing the length level factor
float glbl_lengthLevelFactor = 0.0; // add length times this factor to each length level

char glbl_maxLevel = MAX_LEVEL;

// attempt counter, storing maximum attempts and attempts done
uint64_t glbl_attemptsCount = 0;  // counts amounts of attempts (extern, declared in enumNG.h)
uint64_t glbl_attemptsMax = DEFAULT_MAX_ATTEMPTS; // defines maximum amount of attempts (modify using [-m int])
uint64_t glbl_progressStep = (uint64_t) (DEFAULT_MAX_ATTEMPTS / 100);

// modes (set by arguments [-argument])
bool glbl_simulatedAttMode = false; // start a simulated attack and print results to the graph-file [-s <filename>]
bool glbl_usernameMode = false; // usermode activated (TODO: implement username mode) [-u <filename>]
bool glbl_verboseFileMode = false;  // write a file containing all cracked PWs [-F]
bool glbl_verboseMode = false;  // printout information about settings [-v]
bool glbl_pipeMode = false;     // printout generated to stdout only (printing nothing else!) [-p]
bool glbl_ignoreEPMode = false; // ignore endProbs [-E]
bool glbl_endlessMode = false;  // ignore endProbs [-e]
bool glbl_optimizedLengthMode = false;
bool glbl_alphaBoostingMode = false;  // enumerates passwords using boosting

unsigned int glbl_fixedLenght = 0;  // if fixedLength != 0 -> only create PWs of this length

// file pointer
char glbl_resultsFolder[256] = { '\0' };

FILE *glbl_FP_generatedPasswords = NULL;  // generated PWs (based on selected mode either all or only cracked ones are stored)

// information stored in the log
uint64_t glbl_createdLengths[MAX_PASSWORD_LENGTH];  // counts length of the created PWs (extern, declared in enumNG.h)

// control variable to avoid segmentation faults during log file creation
bool glbl_inputFiles_read = false;  // is set to true if the input files have been read successful

int glbl_boostPwdCount = 0;     // saves current line in password file
FILE *glbl_boostTestSetFile = NULL; // filedescriptor to file with passwords (one per line) that should be guessed.

struct gengetopt_args_info glbl_args_info;

int main (int argc, char **argv)
{
  // let's call our cmdline parser
  if (cmdline_parser (argc, argv, &glbl_args_info) != 0)
  {
    printf ("failed parsing command line arguments\n");
    exit (EXIT_FAILURE);
  }
  // set exit_routine so that it will be automatically called at the end of the application
  atexit (exit_routine);

  // initialize global parameters
  initialize ();

  // evaluate given arguments
  if (!evaluate_arguments (&glbl_args_info))
  {
    exit (EXIT_FAILURE);
  }

  // read the input files and apply all other settings
  if (!apply_settings ())
  {
    exit (EXIT_FAILURE);
  }

  // check if boosting
  if (glbl_alphaBoostingMode && glbl_simulatedAttMode)
  {
    if (!boostingMode ())
    {
      exit (EXIT_FAILURE);
    }
  }
  else if (glbl_alphaBoostingMode && glbl_pipeMode)
  {
    if (!boost_allHints ())
    {
      exit (EXIT_FAILURE);
    }

    // generate sorted arrays
    if (!sort_ngrams ())
    {
      errorHandler_print (errorType_Error, "Failed to sort ngrams\n");
      exit (EXIT_FAILURE);
    }

    // run password creation
    if (glbl_fixedLenght != 0)
    {
      run_enumeration_fixedLenghts ();
    }
    else if (glbl_optimizedLengthMode)
    {
      run_enumeration_optimizedLengths ();
    }
    else
    {
      run_enumeration ();
    }
  }
  else
  {                             // run normal password enumeration
    // generate sorted arrays
    if (!sort_ngrams ())
    {
      errorHandler_print (errorType_Error, "Failed to sort ngrams\n");
      exit (EXIT_FAILURE);
    }

    // run password creation
    if (glbl_fixedLenght != 0)
    {
      run_enumeration_fixedLenghts ();
    }
    else if (glbl_optimizedLengthMode)
    {
      run_enumeration_optimizedLengths ();
    }
    else
    {
      run_enumeration ();
    }
  }

  exit (EXIT_SUCCESS);
}

void initialize ()
{
  // set stdout to autoflush
  setvbuf (stdout, NULL, _IONBF, 0);
  setvbuf (stderr, NULL, _IONBF, 0);

  // set signal handler for sigint to handle user input during runtime
  struct sigaction sigIntHandler;

  sigIntHandler.sa_handler = sigint_handler;
  sigemptyset (&sigIntHandler.sa_mask);
  sigIntHandler.sa_flags = 0;

  sigaction (SIGINT, &sigIntHandler, NULL);

  // set time stamp
  set_timestampWithDiff (stdout, false, false);

  // create the result folder
  create_resultFolder ();

  // initializing and setting default values for all global parameters

  // initialize filenames struct
  struct_filenames_initialize (&glbl_filenames);
  // allocate content and copy default values
  struct_filenames_allocateDefaults (glbl_filenames);

  // initialize alphabet struct
  struct_alphabet_initialize (&glbl_alphabet);
  // allocate content and copy default values
  struct_alphabet_allocateDefaults (glbl_alphabet);

  // initialize countArray struct
  struct_nGrams_initialize (&glbl_nGramLevel);
  // struct_initialize_nGrams(&glbl_nGramLevel_user);

  // initialize default smoothing (to be able to access smoothing information)
  smoo_initialize ();
}                               // initialize

// exit routine, frees any allocated memory (for global variables)
void exit_routine ()
{
  if (exit_status != -1)
  {                             // -1 = exit after printing help text
    // and log file to HD (filename: log/<date>.log)
    bool logSuccessful = print_log ();

    // print results
    if (glbl_verboseMode)
    {
      // print timestamp
      set_timestampWithDiff (stdout, glbl_verboseMode, true);

      // print report
      print_report_enumNG (stdout);
      if (logSuccessful)
      {
        printf ("Log file successfully created.\n\n");
      }
      else
      {
        errorHandler_print (errorType_Error, "Unable to create the log file.\n\n");
      }
    }
    switch (exit_status)
    {
    case 0:                    // success
      if (glbl_verboseMode)
      {
        printf ("Status: done\n");
      }
      break;
    default:                   // error
      printf ("Status: aborted(%i)\n", exit_status);
      break;
    }
  }

  // free all pointer using the CHECKED_FREE
  // and struct_free operation (defined in commonStructs.h)

  // level and count arrays
  struct_nGrams_free (&glbl_nGramLevel);
  // struct_nGrams_free(&glbl_nGramLevel_user);

  // alphabet
  struct_alphabet_free (&glbl_alphabet);
  // filenames
  struct_filenames_free (&glbl_filenames);
  CHECKED_FREE (glbl_filenameTestingSet) CHECKED_FREE (glbl_filenameUsername)
    // sorted arrays
    struct_sortedLastGram_free (glbl_maxLevel, &glbl_sortedLastGram);
  struct_sortedIP_free (glbl_maxLevel, &glbl_sortedIP);
  struct_sortedLength_free (&glbl_sortedLength);

  // free testing set (if simulated attack mode is active)
  if (glbl_simulatedAttMode)
  {
    simAtt_freeTestingSet ();
  }

  // close global file pointer
  if (glbl_FP_generatedPasswords != NULL)
  {
    fclose (glbl_FP_generatedPasswords);
    glbl_FP_generatedPasswords = NULL;
  }

  // close boost password test set file
  if (glbl_boostTestSetFile != NULL)
  {
    fclose (glbl_boostTestSetFile);
    glbl_boostTestSetFile = NULL;
  }

  errorHandler_finalize ();
  cmdline_parser_free (&glbl_args_info);  // release allocated memory
}                               // exit_routine

// evaluates command line parameters
bool evaluate_arguments (struct gengetopt_args_info *args_info)
{
  bool result = true;

  errorHandler_init (args_info->printWarnings_flag);

  if (args_info->username_given)
  {
    result &= changeFilename (&glbl_filenameUsername, FILENAME_MAX, "username", args_info->username_arg);
    glbl_usernameMode = true;
  }

  if (args_info->simAtt_given)
  {
    result &= changeFilename (&glbl_filenameTestingSet, FILENAME_MAX, "password", args_info->simAtt_arg);
    glbl_simulatedAttMode = true;
  }

  if (args_info->pipeMode_flag)
  {
    glbl_pipeMode = true;
  }

  if (args_info->llFactor_given)
  {
    glbl_lengthLevelFactor = args_info->llFactor_arg;
    if (glbl_lengthLevelFactor < 0 || glbl_lengthLevelFactor > 10)
    {
      errorHandler_print (errorType_Error, "The minimum value for the level length factor is %.3f, the maximum %.3f (it is %.3f)\n", 0.0, 10.0, args_info->llFactor_arg);
      result = false;
    }
  }

  if (args_info->llSet_given)
  {
    glbl_lengthLevelSet = args_info->llSet_arg;
  }

  if (args_info->optimizedLS_flag)
  {
    glbl_optimizedLengthMode = true;
  }

  if (args_info->fixedLength_given)
  {
    glbl_fixedLenght = args_info->fixedLength_arg;
  }

  if (args_info->maxattempts_given)
  {
    glbl_attemptsMax = args_info->maxattempts_arg;
    // check if the value is in the allowed range
    if (glbl_attemptsMax < 1 || glbl_attemptsMax > MAX_MAX_ATTEMPTS)
    {
      errorHandler_print (errorType_Error, "The minimum value for the %s n should be %i, the maximum %" PRIu64 "\n", "maxAttempts", 1, (uint64_t) MAX_MAX_ATTEMPTS);
      return false;
    }
    glbl_progressStep = (uint64_t) (glbl_attemptsMax / 100);
  }

  if (args_info->endless_flag)
  {
    glbl_endlessMode = true;
  }

  if (args_info->ignoreEP_flag)
  {
    glbl_ignoreEPMode = true;
  }

  if (args_info->verbose_flag)
  {
    glbl_verboseMode = true;
  }

  if (args_info->verboseFile_flag)
  {
    glbl_verboseFileMode = true;
  }

  if (args_info->config_given)
  {
    result &= changeFilename (&(glbl_filenames->cfg), FILENAME_MAX, "config", args_info->config_arg);
  }

  // if username mode was set
  if (glbl_usernameMode)
  {
    // TODO: implement username mode
  }

  // check if both of alpha and hint file are given
  if ((args_info->alpha_given && !args_info->hint_given) || (!args_info->alpha_given && args_info->hint_given))
  {
    fprintf (stderr, "ERROR:\tThe alpha and hint arguments require each other.\n");
    return false;
  }
  else if (args_info->alpha_given && args_info->hint_given)
  {
    glbl_alphaBoostingMode = true;
  }
  return result;
}                               // evaluate_arguments

// reads all needed input files and fills the sorted arrays
bool apply_settings ()
{
  // read input files
  if (!read_inputFiles (glbl_nGramLevel, glbl_alphabet, glbl_filenames, &glbl_maxLevel))
  {
    // TODO print help here?
    return false;
  }
  if ((glbl_filenames->smoo) != NULL)
  {
    if (!smoo_readInput (glbl_filenames->smoo))
    {
      return false;
    }
  }

  // if pipeMode is not active...
  if (!glbl_pipeMode)
  {
    // .. try to create the basic result file
    if (!open_file (&glbl_FP_generatedPasswords, glbl_resultsFolder, "/createdPWs.txt", "w"))
    {
      errorHandler_print (errorType_Error, "Unable to create result file\n");
      return false;
    }

    // ... and if simulated attack mode is active ...
    if ((glbl_simulatedAttMode) && (!glbl_alphaBoostingMode))
    {
      int output_cycle = (int) (glbl_attemptsMax / DEFAULT_OUTPUT_CYCLE_FACTOR);

      if (output_cycle == 0)
      {
        output_cycle = 1;
      }
      // ... try to generate testing set based on input file
      if (!simAtt_generateTestingSet (glbl_filenameTestingSet, glbl_resultsFolder, output_cycle))
      {
        errorHandler_print (errorType_Error, "Unable to create testing Set (source: %s)\n", glbl_filenameTestingSet);
        return false;
      }
    }
  }
  else
  {                             // pipe mode active
    glbl_FP_generatedPasswords = stdout;
    glbl_verboseMode = false;
    glbl_simulatedAttMode = false;
  }

  return true;
}

bool sort_ngrams ()
{

  int initialBuffer = 1;        // buffer for the dynamic sorted arrays

  // print selected mode and filenames
  if (glbl_verboseMode)
  {
    print_settings_enumNG (stdout);
  }

  // initialize sorted nGram struct
  struct_sortedLastGram_initialize (glbl_maxLevel, &glbl_sortedLastGram, glbl_nGramLevel->sizeOf_N, glbl_alphabet->sizeOf_alphabet, initialBuffer);
  // initialize sortedIP struct
  struct_sortedIP_initialize (glbl_maxLevel, &glbl_sortedIP, initialBuffer);
  // initialize sortedLength struct
  struct_sortedLength_initialize (&glbl_sortedLength);

  // sort the given nGram array
  struct_sortedLastGram_fill (glbl_maxLevel, glbl_sortedLastGram, glbl_nGramLevel->cP, glbl_nGramLevel->sizeOf_cP, glbl_nGramLevel->sizeOf_N, glbl_alphabet->sizeOf_alphabet);
  // sort the given iP array
  struct_sortedIP_fill (glbl_maxLevel, glbl_sortedIP, glbl_nGramLevel->iP, glbl_nGramLevel->sizeOf_iP);
  // sort given length array
  struct_sortedLength_fill (glbl_sortedLength, glbl_nGramLevel->len, (glbl_nGramLevel->sizeOf_N), glbl_lengthLevelFactor, glbl_lengthLevelSet);

  // input files have been successfully read
  glbl_inputFiles_read = true;

  return true;
}                               // apply_settings

/* (intern functions) progress_bar Functions to print and update a printed progress bar during an run through with an active verbose mode. - progress_init: initialize progress bar - progress_update: update the progress bar according to during status - progess_finish: set progress bar to final status */
void progress_init ()
{
  if (glbl_verboseMode && !glbl_endlessMode)
  {
    if (glbl_simulatedAttMode)
    {
      printf ("<-------------------->   0 %% created (0.0 %% cracked)");
    }
    else
    {
      printf ("<-------------------->   0 %% created");
    }
  }
}

void progress_update ()
{
  static uint64_t counter = 0;  // counter to perform one step
  static int progress = 1;      // steps taken
  static char progressBar[21] = "===================="; // progress done
  static char progressBlank[21] = "--------------------"; // progress open

  if (glbl_verboseMode && !glbl_endlessMode)
  {
    counter++;
    if (counter == glbl_progressStep)
    {
      counter = 0;
      if (glbl_simulatedAttMode)
      {
        printf ("\r<%s%s> %3i %% created (%.1f %% cracked)", progressBar + (20 - (int) (progress / 5)), progressBlank + (int) (progress / 5), progress, glbl_crackedRatio * 100);
      }
      else
      {
        printf ("\r<%s%s> %3i %% created", progressBar + (20 - (int) (progress / 5)), progressBlank + (int) (progress / 5), progress);
      }
      progress++;
    }
  }
}

void progress_finish ()
{
  if (glbl_verboseMode && !glbl_endlessMode)
  {
    if (glbl_simulatedAttMode)
    {
      printf ("\r<====================> 100 %% created (%.1f %% cracked)\n", glbl_crackedRatio * 100);
    }
    else
    {
      printf ("\r<====================> 100 %% created\n");
    }
  }
}                               // (intern) progress_bar

/* (intern function) Resets given levelChain (to given length) */
void reset_levelChain (int levelChain[MAX_PASSWORD_LENGTH + 1], int length)
{
  levelChain[0] = 0;
  for (size_t i = 1; i < length; i++)
  {
    levelChain[i] = 0;
  }
}                               // (intern) reset_levelChain

void print_levelChain (int levelChain[MAX_PASSWORD_LENGTH + 1], int length, FILE * fp)
{
  fprintf (fp, "%i", levelChain[0]);
  for (size_t j = 1; j < length; j++)
  {
    fprintf (fp, "-%i", levelChain[j]);
  }
  fprintf (fp, "\n");
}

// Main process: calculates levelChains and generates passwords
void run_enumeration ()
{
  int levelOverall = 0;         // counting the overall level
  int levelOverallMax = 0;      // max value for overall level (maxLevel-1) * MAX_LENGTH + lengthFactos
  int lengthIndex = 0;          // current max index in sortedLength array

  int level = 0;                // stores level for current length

  int levelChain[MAX_PASSWORD_LENGTH + 1];  // stores current levelChain

  bool newChain = true;         // true: create a new levelChain, false: create next one based on a given levelChain
  bool runCreation = true;      // control variable to break enumeration loop

  /* Length for leveChain and password The levelChain length differs from password length since iP uses one length for N-1 characters in the actual password (and EP uses 1 length in the levelChain as well). */
  int lengthLC = 0;             // length of the levelChain
  int lengthPW = 0;             // length of the actual Password

  int lengthLCModifier = 3 - glbl_nGramLevel->sizeOf_N; // N-3 if using endProbs, N-2 if not

  if (glbl_ignoreEPMode)
  {
    lengthLCModifier = 2 - glbl_nGramLevel->sizeOf_N;
  }

  // calculate max overall level
  levelOverallMax = (glbl_maxLevel - 1) * MAX_PASSWORD_LENGTH + (glbl_sortedLength->level[MAX_PASSWORD_LENGTH - 1]);

  progress_init ();

  while (runCreation)
  {
    // get max index of sorted lengths
    lengthIndex = struct_sortedLength_getMaxIndexForLevel (glbl_sortedLength, levelOverall);

    // for all lengths with current or smaller level ...
    for (size_t i = 0; i < lengthIndex; i++)
    {
      // get length
      lengthLC = glbl_sortedLength->length[i] + lengthLCModifier;
      lengthPW = glbl_sortedLength->length[i];

      // get actual level (overall level - level of current length)
      level = levelOverall - glbl_sortedLength->level[i];

      // reset levelChain
      reset_levelChain (levelChain, lengthLC);

      // new length & level -> new chain
      newChain = true;

      // get all levelChains for current length and level
      while (getNext_levelChain (levelChain, lengthLC, level, newChain))
      {
        newChain = false;

        // enumerate all PWs returns false if max attempts has been reached
        if (!enumerate_password (levelChain, lengthPW))
        {
          i = MAX_PASSWORD_LENGTH;  // jump out of lengthIndex loop
          runCreation = false;  // stop enumeration loop
          break;                // break levelChain loop
        }
      }
    }
    // increase overall level and check if max possible level is reached
    levelOverall++;
    if (levelOverall > levelOverallMax)
    {
      // no more levelChains, stop enumeration
      errorHandler_print (errorType_Warning, "All possible LevelChains have been created.\n");
      runCreation = false;
    }
  }
  progress_finish ();
}                               // run_enumeration

// modified enumeration for fixed length
void run_enumeration_fixedLenghts ()
{
  int level = 0;                // counting the overall level
  int levelMax = 0;             // max value for overall level (glbl_maxLevel-1) * MAX_LENGTH + lengthFactos

  int levelChain[MAX_PASSWORD_LENGTH + 1];  // stores current levelChain

  bool newChain = true;         // true: create a new levelChain, false: create next one based on a given levelChain
  bool runCreation = true;      // control variable to break enumeration loop

  /* Length for leveChain and password The levelChain length differs from password length since iP uses one length for N-1 characters in the actual password (and EP uses 1 length in the levelChain as well). */
  int lengthLC = 0;             // length of the levelChain
  int lengthPW = 0;             // length of the actual Password

  int lengthLCModifier = 3 - glbl_nGramLevel->sizeOf_N; // N-3 if using endProbs, N-2 if not

  if (glbl_ignoreEPMode)
  {
    lengthLCModifier = 2 - glbl_nGramLevel->sizeOf_N;
  }

  // set fixed lengths
  lengthLC = glbl_fixedLenght + lengthLCModifier;
  lengthPW = glbl_fixedLenght;

  // calculate max overall level
  levelMax = (glbl_maxLevel - 1) * lengthLC;

  progress_init ();

  while (runCreation)
  {
    // reset levelChain
    reset_levelChain (levelChain, lengthLC);

    // new level -> new chain
    newChain = true;

    while (getNext_levelChain (levelChain, lengthLC, level, newChain))
    {
      newChain = false;
      // enumerate_password returns false if max attempts has been reached
      if (!enumerate_password (levelChain, lengthPW))
      {
        runCreation = false;
        break;
      }
    }

    // increase level and check if max level has been reached
    level++;
    if (level > levelMax)
    {
      // no more levelChains, stop enumeration
      errorHandler_print (errorType_Warning, "All possible LevelChains have been created.\n");
      runCreation = false;
    }
  }

  progress_finish ();
}                               // run_enumeration_fixedLenghts()

// Main process: calculates levelChains and generates passwords
void run_enumeration_optimizedLengths ()
{
  // int level = 0; // stores level for current length
  int levelChain[MAX_PASSWORD_LENGTH + 1];  // stores current levelChain

  bool newChain = true;         // true: create a new levelChain, false: create next one based on a given levelChain
  bool runCreation = true;      // control variable to break enumeration loop

  // variables for old length scheduling
  int lenghtLevel[MAX_PASSWORD_LENGTH];
  double lengthCrackRate[MAX_PASSWORD_LENGTH];  // new
  int old_attemptsCount, old_crackedCount, cur_attemptsCount;
  int lengthsReachedMax = 0;

  /* Length for leveChain and password The levelChain length differs from password length since iP uses one length for N-1 characters in the actual password (and EP uses 1 length in the levelChain as well). */
  int lengthLC = 0;             // length of the levelChain
  int lengthPW = 0;             // length of the actual Password

  int lengthLCModifier = 3 - glbl_nGramLevel->sizeOf_N; // N-3 if using endProbs, N-2 if not

  if (glbl_ignoreEPMode)
  {
    lengthLCModifier = 2 - glbl_nGramLevel->sizeOf_N;
  }

  for (size_t i = 0; i < MAX_PASSWORD_LENGTH; i++)
  {
    lenghtLevel[i] = 0;
    lengthCrackRate[i] = 1;     // schedule each at least once...
  }
  lengthCrackRate[0] = 0;

  progress_init ();
  while (runCreation)
  {
    // find "best" length to schedule..
    lengthPW = 0;
    for (size_t i = glbl_nGramLevel->sizeOf_N; i < MAX_PASSWORD_LENGTH; i++)
    {
      if (lengthCrackRate[i] > lengthCrackRate[lengthPW])
      {
        lengthPW = i;
      }
    }
    lengthLC = lengthPW + lengthLCModifier;

    // store old cracked and attempt counts
    old_attemptsCount = glbl_attemptsCount;
    old_crackedCount = glbl_crackedCount;

    // reset levelChain
    reset_levelChain (levelChain, lengthLC);

    // new length and/or level -> new chain
    newChain = true;

    // get all levelChains for current length and level
    while (getNext_levelChain (levelChain, lengthLC, lenghtLevel[lengthPW], newChain))
    {
      newChain = false;

      // enumerate all PWs returns false if max attempts has been reached
      if (!enumerate_password (levelChain, lengthPW))
      {
        runCreation = false;    // stop enumeration loop
        break;                  // break levelChain loop
      }
    }
    // adjust crack rate
    cur_attemptsCount = (glbl_attemptsCount - old_attemptsCount);
    if (cur_attemptsCount == 0)
    {
      cur_attemptsCount = 1;
    }
    lengthCrackRate[lengthPW] = (float) (glbl_crackedCount - old_crackedCount) / (float) (cur_attemptsCount);
    if (lengthCrackRate[lengthPW] < 0.0000001)  // should not get too small
    {
      lengthCrackRate[lengthPW] = 0.0000001;
    }

    if (lengthCrackRate[lengthPW] >= 1) // should not get too large
    {
      lengthCrackRate[lengthPW] = 0.999999;
    }

    if (lenghtLevel[lengthPW] >= ((glbl_maxLevel - 1) * lengthPW))
    {                           // reached highest supported level
      errorHandler_print (errorType_Warning, "All possible LevelChains for length %i have been created.\n", lengthPW);
      lengthCrackRate[lengthPW] = 0;  // prevent it from getting scheduled again
      lengthsReachedMax++;
    }
    else
    {
      lenghtLevel[lengthPW]++;
    }

    if (lengthsReachedMax >= MAX_PASSWORD_LENGTH)
    {
      // no more levelChains, stop enumeration
      errorHandler_print (errorType_Warning, "All possible LevelChains have been created.\n");
      runCreation = false;
    }
  }

  progress_finish ();
}                               // run_enumeration

/* (intern faction) Recursively generates a levelChain for the given length and level. Returns true if a levelChain could be created or false if not. */
bool generate_levelChain_2ndToLast_recursive (int levelChain[MAX_PASSWORD_LENGTH], int depth, int lengthMax, int levelCur, int levelMax, bool newChain)
{
  // if last int for levelChain is reached ...
  if (depth == (lengthMax - 1))
  {
    // the last int must be the rest of levelMax
    levelChain[lengthMax - 1] = levelMax - levelCur;
    // and should not be larger then global maximum level
    if (levelChain[lengthMax - 1] > (glbl_maxLevel - 1))
    {
      return false;             // reject generated levelChain
    }

    // accept generated levelChain
    return true;
  }
  else
  {                             // if depth < (length-1)
    // get max possible level, but do not exceed global maximum level
    int level = levelMax - levelCur;

    if (level > (glbl_maxLevel - 1))
    {
      level = (glbl_maxLevel - 1);
    }

    // proceed from previous set level
    for (; levelChain[depth] <= level; levelChain[depth]++)
    {
      // call recursive function to determine next int
      if (generate_levelChain_2ndToLast_recursive (levelChain, depth + 1, lengthMax, levelCur + levelChain[depth], levelMax, newChain))
      {
        return true;
      }
      // reset all others
      levelChain[depth + 1] = 0;
    }
  }
  return false;
}                               // (intern) generate_levelChain_2ndToLast_recursive

// set levelChain to the next one
bool getNext_levelChain (int levelChain[MAX_PASSWORD_LENGTH], int length, int levelMax, bool newChain)
{
  // since any single level can not be larger then 10:
  int level = levelMax;

  if (level > (glbl_maxLevel - 1))
    level = glbl_maxLevel - 1;

  // check, if the chain is possible
  if (levelMax > (glbl_maxLevel - 1) * length)
    return false;

  // if no new chain should be created;
  if (!newChain)
    levelChain[length - 2]++;   // increase second last to avoid doublets

  // for each level <= levelMax (or 10)
  for (; levelChain[0] <= level; levelChain[0]++)
  {
    // call recursive function to determine 2nd to Last int for the levelChain with maxLevel
    if (generate_levelChain_2ndToLast_recursive (levelChain, 1, length, levelChain[0], levelMax, newChain))
      return true;
    // reset levelChain
    levelChain[1] = 0;
  }
  return false;
}                               // getNext_levelChains

/* (intern function) Handles a enumerated password based on the selected mode, i.e.: - if simulatedAttMode is active, the PW is checked against the testing set - if pipeMode is active, the PW is printed to stdout - in defaultMode the PW is added to the password file Returns false if as many passwords as glbl_attemptsMax have been created. */
bool handle_createdPassword (int passwordAsInt[MAX_PASSWORD_LENGTH], int levelChain[MAX_PASSWORD_LENGTH], int length)
{
  char passwordAsChar[length + 1];

  // create the corresponding password as char
  for (size_t i = 0; i < length; i++)
  {
    get_charAtPosition (passwordAsChar + i, passwordAsInt[i], glbl_alphabet->alphabet, glbl_alphabet->sizeOf_alphabet);
  }
  passwordAsChar[length] = '\0';

  // adjust counter
  glbl_attemptsCount++;
  glbl_createdLengths[length - 1]++;

  // if simulated attack mode is active...
  if (glbl_alphaBoostingMode)
  {
    if (glbl_simulatedAttMode)
    {
      if (simAtt_boostCheckCandidate (passwordAsChar, length))
      {
        if (glbl_verboseFileMode)
        {
          fprintf (glbl_FP_generatedPasswords, "%s, %" PRIu64 "\n", passwordAsChar, glbl_attemptsCount);
        }
        return false;           // return false here means: we are finished with enumerating
      }
    }
    else
    {
      // pipe or normal mode (glbl_FP_generatedPasswords is set to stdout in pipeMode)
      fprintf (glbl_FP_generatedPasswords, "%s\n", passwordAsChar); // just add the generated password to the file/stdout
    }
  }
  else if (glbl_simulatedAttMode)
  {
    // ...check candidate (and print it to file if verboseFileMode is active)
    if (simAtt_checkCandidate (passwordAsChar, length) && glbl_verboseFileMode)
    {
      // ... and print any cracked PW (if verboseFileMode is active)
      // fprintf(glbl_FP_generatedPasswords, "%s\n", passwordAsChar);
      // ... for analysis, prints the guess attempts
      fprintf (glbl_FP_generatedPasswords, "%s, %" PRIu64 "\n", passwordAsChar, glbl_attemptsCount);
    }
  }
  else
  {
    // pipe or normal mode (glbl_FP_generatedPasswords is set to stdout in pipeMode)
    fprintf (glbl_FP_generatedPasswords, "%s\n", passwordAsChar); // just add the generated password to the file/stdout
  }

  // print the progress (if verboseMode is active)
  progress_update ();

  // if endlessMode is deactivated and current attempts equals max attempts, end run through
  if (!glbl_endlessMode && glbl_attemptsCount == glbl_attemptsMax)
    return false;

  // else continue run through
  return true;
}                               // (intern) handle_password

/* (intern function) Recursively generates all passwords based on the current levelChain and the previous password characters. If a password has been found, enumerate_password_handleCandidate is used to evaluate the password based on the selected mode Returns false if as many passwords as glbl_attemptsMax have been created. */
bool enumerate_password_recursivly (int passwordAsInt[MAX_PASSWORD_LENGTH], int levelChain[MAX_PASSWORD_LENGTH], int lengthCur, int lengthMax)
{
  int position = 0;
  int level = 0;

  // get position of the mGram
  get_positionFromNGramAsInt (&position, passwordAsInt + (lengthCur - (glbl_nGramLevel->sizeOf_N - 1)), (glbl_nGramLevel->sizeOf_N - 1), glbl_alphabet->sizeOf_alphabet);

  /* get current level from the levelChain (need to be adjusted by sizeOf_N since iP take 1 level from levelChain, but N-1 characters in the Password) */
  level = levelChain[lengthCur - (glbl_nGramLevel->sizeOf_N - 2)];

  // length of new PW equals max length
  if (lengthCur == lengthMax)
  {
    // check if the level match the endProp
    if (!glbl_ignoreEPMode)
    {
      if (level != glbl_nGramLevel->eP[position])
        return true;
    }
    return handle_createdPassword (passwordAsInt, levelChain, lengthCur);
  }
  else
  {                             // lengthCur != lengthMax
    // for each lastGram with current @level and @position
    for (size_t i = 0; i < (glbl_sortedLastGram[level].indexCur)[position]; i++)
    {
      // add lastGram as int to the PW
      passwordAsInt[lengthCur] = (glbl_sortedLastGram[level].lastGrams)[position][i];
      // call recursive function with length + 1
      if (!enumerate_password_recursivly (passwordAsInt, levelChain, lengthCur + 1, lengthMax))
        return false;
    }
    return true;
  }
}                               // (intern) enumerate_password_recursivly

// generates passwords based on the given levelChain and length
bool enumerate_password (int levelChain[MAX_PASSWORD_LENGTH], int lengthMax)
{
  int passwordAsInt[MAX_PASSWORD_LENGTH];

  memset (passwordAsInt, 0, sizeof (passwordAsInt));

  int iP_level = levelChain[0]; // the first level of the levelChain is for the initialProb
  int lengthCur = (glbl_nGramLevel->sizeOf_N - 1);  // the initial lengths equals the size of N - 1 (size of the initialProb)

  // for each initialProb with the given @iP_level
  for (size_t i = 0; i < glbl_sortedIP[iP_level].indexCur; i++)
  {
    // set the first (sizeOf_N - 1) int according to the position stored in sortedIp
    get_nGramAsIntFromPosition (passwordAsInt, glbl_sortedIP[iP_level].iP[i], (glbl_nGramLevel->sizeOf_N - 1), glbl_alphabet->sizeOf_alphabet);
    // call the recursive function
    if (!enumerate_password_recursivly (passwordAsInt, levelChain, lengthCur, lengthMax))
      return false;
  }
  return true;
}                               // enumerate_password_iP

// creates a new result folder
void create_resultFolder ()
{
  struct stat st;

  if (stat ("results", &st) != 0)
  {                             // check if folder results exist else..
    mkdir ("results", S_IRWXO | S_IRWXG | S_IRWXU); // create folder results
  }

  snprintf (glbl_resultsFolder, sizeof (glbl_resultsFolder), "results/");
}

// prints the selected parameters
void print_settings_enumNG (FILE * fp)
{
  if (fp == stdout)
    fprintf (fp, "\nStarting enumNG with the following settings:\n");

  if (glbl_fixedLenght != 0)
    fprintf (fp, " - fixedLength (%i)\n", glbl_fixedLenght);
  else if (glbl_optimizedLengthMode)
    fprintf (fp, " - optimized length scheduling\n");
  else
  {
    if (glbl_lengthLevelSet != -1)
      fprintf (fp, " - lengthLevelSet (%i)\n", glbl_lengthLevelSet);
    else
      fprintf (fp, " - lengthProbs\n");

    fprintf (fp, " - lengthLevelFactor (%.3f)\n", glbl_lengthLevelFactor);
  }
  if (glbl_ignoreEPMode)
    fprintf (fp, " - ignoreEPMode\n");

  if (!glbl_endlessMode)
    fprintf (fp, " - maxAttempts: %" PRIu64 "\n", glbl_attemptsMax);
  else
    fprintf (fp, " - endlessMode\n");

  if (glbl_simulatedAttMode)
    fprintf (fp, " - simulatedAttack (target: %s)\n", glbl_filenameTestingSet);
  else
    fprintf (fp, " - normalMode\n");
  print_settings_default (fp, glbl_nGramLevel->sizeOf_N, glbl_alphabet, glbl_filenames, glbl_maxLevel, glbl_verboseFileMode);
  smoo_printSelection (fp, false);
  fprintf (fp, "\n");
}

// prints the selected parameters
void print_report_enumNG (FILE * fp)
{
  if (glbl_endlessMode)         // if endlessMode is active
    fprintf (fp, "\nResults: \ncreated: %" PRIu64 "\n", glbl_attemptsCount);  // ... just print created count
  else
    fprintf (fp, "\nResults: \ncreated: %" PRIu64 " of %" PRIu64 "\n", glbl_attemptsCount, glbl_attemptsMax);

  if (glbl_simulatedAttMode)
    print_simulatedAttackResults (fp, false);
  fprintf (fp, "\n");
}                               // print_report

// prints a log file
bool print_log ()
{
  FILE *fp = NULL;              // file pointer to log file

  // generate log-file name and open file
  if (!open_file (&fp, glbl_resultsFolder, "/log.txt", "w"))
    return false;

  // write result to log file
  fprintf (fp, "=== log file for enumNG ===\n");
  switch (exit_status)
  {
  case 0:
    fprintf (fp, "-> run through successful\n\n");
    break;
  default:
    fprintf (fp, "-> run through failed (exit_status: %i)\n\n", exit_status);
    break;
  }

  // print timestamp (start, end and elpased time)
  set_timestampWithDiff (fp, true, true);

  // if the input files have been successfully read ...
  if (glbl_inputFiles_read)
  {
    int endGram_count[glbl_maxLevel];

    memset (endGram_count, 0, glbl_maxLevel * sizeof (int));
    // ... print settings
    fprintf (fp, "\n== Settings ==\n");
    print_settings_enumNG (fp);
    // ... print sorted arrays (if not in boosting mode, than these are different for each password..)
    if (!glbl_alphaBoostingMode)
    {
      fprintf (fp, "\n== Sorted arrays ==\n");

      fprintf (fp, "lastGram (level - count):\n");
      for (size_t i = 0; i < glbl_maxLevel; i++)
      {
        int count = 0;

        for (size_t j = 0; j < glbl_sortedLastGram[i].sizeOf_mGram; j++)
          count += glbl_sortedLastGram[i].indexCur[j];
        fprintf (fp, "%2zu - %9i\n", i, count);
      }
      fprintf (fp, "\ninitial Prob (level - count):\n");
      for (size_t i = 0; i < glbl_maxLevel; i++)
        fprintf (fp, "%2zu - %9i\n", i, glbl_sortedIP[i].indexCur);

      // print endGram count (need calculation first):
      fprintf (fp, "\nend Prob (level - count):\n");
      for (size_t i = 0; i < glbl_nGramLevel->sizeOf_eP; i++)
        endGram_count[(glbl_nGramLevel->eP[i])]++;
      for (size_t i = 0; i < glbl_maxLevel; i++)
        fprintf (fp, "%2zu - %9i\n", i, endGram_count[i]);

      fprintf (fp, "\nlength (length - level):\n");
      for (size_t i = 0; i < MAX_PASSWORD_LENGTH - glbl_sortedLength->lengthMin; i++)
        fprintf (fp, "%2i - %3i\n", glbl_sortedLength->length[i], glbl_sortedLength->level[i]);
    }

    // ... and print the results
    if (glbl_simulatedAttMode)
    {
      fprintf (fp, "\n== Simulated attack mode ==\n");
      fprintf (fp, "TestingSet file: '%s'\n", glbl_filenameTestingSet);
      fprintf (fp, "created: %" PRIu64 " of %" PRIu64 "\n", glbl_attemptsCount, glbl_attemptsMax);
      print_simulatedAttackResults (fp, true);
    }
    else
    {                           // glbl_simulatedAttMode == false
      if (glbl_pipeMode)
        fprintf (fp, "\n== Password pipe mode ==\n");
      else
        fprintf (fp, "\n== Password creator mode ==\n");
      fprintf (fp, "\ncreated: %" PRIu64 " of %" PRIu64 "\n", glbl_attemptsCount, glbl_attemptsMax);
      fprintf (fp, "\nlengths of the created passwords (length - created)\n");
      for (size_t i = glbl_nGramLevel->sizeOf_N; i < MAX_PASSWORD_LENGTH; i++)
        fprintf (fp, "%2zu - %9" PRIu64 "\n", i + 1, glbl_createdLengths[i]);
    }
  }

  // close log file
  if (fp != NULL)
  {
    fclose (fp);
    fp = NULL;
  }
  return true;
}                               // print_log

// ctrl-c handler
void sigint_handler (int s)
{
  if (glbl_verboseMode)
  {
    fprintf (stderr, "\nExiting ok...\n");
  }
  exit (2);
}

bool boost_allHints ()
{
  int alpha_count = 0;
  int *alphas = read_alphas (glbl_args_info.alpha_arg, &alpha_count);

  if (alphas == NULL)
  {
    errorHandler_print (errorType_Error, "Unable to read alpha file \"%s\".\n", glbl_args_info.alpha_arg);
    return false;
  }

  // read all hints, one line per iteration
  char **hints = read_hints (glbl_args_info.hint_arg, alpha_count, glbl_boostPwdCount);

  while (hints != NULL)
  {
    // boost corresponding ngrams in line
    boost (glbl_nGramLevel, glbl_alphabet, alphas, hints, alpha_count, glbl_args_info.boostEP_flag);
    glbl_boostPwdCount++;

    for (int i = 0; i < alpha_count; i++)
    {
      free (hints[i]);
    }
    free (hints);
    hints = NULL;

    // and read next hint line
    hints = read_hints (glbl_args_info.hint_arg, alpha_count, glbl_boostPwdCount);
  }

  free (alphas);
  // glbl_boostTestSetFile is closed in exit_routine
  return true;
}

bool boostingMode ()
{
  int alpha_count = 0;
  int *alphas = read_alphas (glbl_args_info.alpha_arg, &alpha_count);

  if (alphas == NULL)
  {
    errorHandler_print (errorType_Error, "Unable to read alpha file \"%s\".\n", glbl_args_info.alpha_arg);
    return false;
  }
  save_level (glbl_nGramLevel);

  int output_cycle = (int) (glbl_attemptsMax / DEFAULT_OUTPUT_CYCLE_FACTOR);

  if (output_cycle == 0)
  {
    output_cycle = 1;
  }
  simAtt_boostInit (glbl_resultsFolder, output_cycle);

  glbl_boostTestSetFile = fopen (glbl_filenameTestingSet, "r");

  while (read_password (glbl_boostTestSetFile))
  {

    char **hints = read_hints (glbl_args_info.hint_arg, alpha_count, glbl_boostPwdCount);

    if (hints == NULL)
    {
      errorHandler_print (errorType_Error, "Unable to read hint for current password number %d.\n", glbl_boostPwdCount);
      exit (EXIT_FAILURE);
    }
    boost (glbl_nGramLevel, glbl_alphabet, alphas, hints, alpha_count, glbl_args_info.boostEP_flag);

    // generate sorted arrays
    if (!sort_ngrams ())
    {
      for (int i = 0; i < alpha_count; i++)
      {
        free (hints[i]);
      }
      free (hints);
      fclose (glbl_boostTestSetFile);
      free_saved_level ();
      free (alphas);
      exit (EXIT_FAILURE);
    }

    // run password creation
    if (glbl_fixedLenght != 0)
    {
      run_enumeration_fixedLenghts ();
    }
    else if (glbl_optimizedLengthMode)
    {
      run_enumeration_optimizedLengths ();
    }
    else
    {
      run_enumeration ();
    }
    printf ("%lu\n", glbl_attemptsCount);
    glbl_attemptsCount = 0;

    glbl_boostPwdCount++;
    deboost (glbl_nGramLevel);

    // sorted arrays
    struct_sortedLastGram_free (glbl_maxLevel, &glbl_sortedLastGram);
    struct_sortedIP_free (glbl_maxLevel, &glbl_sortedIP);
    struct_sortedLength_free (&glbl_sortedLength);
    for (int i = 0; i < alpha_count; i++)
    {
      free (hints[i]);
    }
    free (hints);
  }

  // glbl_boostTestSetFile is closed in exit_routine
  free_saved_level ();
  free (alphas);
  return true;
}
