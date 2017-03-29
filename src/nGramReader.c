/*
 * nGramReader.c
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>

#include "nGramReader.h"
#include "common.h"
#include "commonStructs.h"

/* (intern function) reads config file and sets the different structs */
bool read_config (struct nGram_struct *nGrams, struct alphabet_struct *alphabet, struct filename_struct *filenames, char *maxLevel, const char *filenameConfig)
{
  FILE *fp = NULL;              // file pointer
  char curLine[MAX_LINE_LENGTH] = ""; // current line
  char argName[MAX_LINE_LENGTH] = ""; // header argument name
  char argValue[MAX_LINE_LENGTH] = "";  // header argument value
  bool nGramChanges = false;
  bool success = true;

  if (!(open_file (&fp, filenameConfig, NULL, "r")))
  {
    fprintf (stderr, "ERROR: Could not open file (%s)\n", filenameConfig);
    return false;
  }

  while (fgets (curLine, sizeof (curLine) - 1, fp) != NULL)
  {
    sscanf (curLine, "# -%s %s", argName, argValue);
    /*
     * known header options:
     * alphabet %s
     * alphabetsize %i
     * ngram %i
     * leveladjustment %i
     * ngramout %s
     * ipout %s
     * epout %s
     * lenout %s
     */
    if (strcmp (argName, "alphabet") == 0)
    {
      if (!str_allocCpy (&(alphabet->alphabet), argValue))
      {
        printf ("Error:Out of Memory\n");
        success = false;
        break;
      }
    }
    else if (strcmp (argName, "alphabetsize") == 0)
    {
      (alphabet->sizeOf_alphabet) = atoi (argValue);
      if ((alphabet->sizeOf_alphabet) == 0)
      {
        fprintf (stderr, "ERROR: Bad Header (size of alphabet)\n");
        success = false;
        break;
      }
      nGramChanges = true;
    }
    else if (strcmp (argName, "ngram") == 0)
    {
      (nGrams->sizeOf_N) = atoi (argValue);
      if ((nGrams->sizeOf_N) < 1 || (nGrams->sizeOf_N) > 5)
      {
        fprintf (stderr, "ERROR: Bad Header (size of n)\n");
        success = false;
        break;
      }
      nGramChanges = true;
    }
    else if (strcmp (argName, "maxLevel") == 0)
    {
      int config_maxlevel = (char) atoi (argValue);

      if ((*maxLevel) < 2 || (*maxLevel) > 101)
      {
        fprintf (stderr, "ERROR: Bad Header (max level)\n");
        success = false;
        break;
      }
      *maxLevel = config_maxlevel;
    }
    else if (strcmp (argName, "cpout") == 0)
    {
      if (!str_allocCpy (&(filenames->cP), argValue))
      {
        printf ("Error:Out of Memory\n");
        success = false;
        break;
      }
    }
    else if (strcmp (argName, "ipout") == 0)
    {
      if (!str_allocCpy (&(filenames->iP), argValue))
      {
        printf ("Error:Out of Memory\n");
        success = false;
        break;
      }
    }
    else if (strcmp (argName, "epout") == 0)
    {
      if (!str_allocCpy (&(filenames->eP), argValue))
      {
        printf ("Error:Out of Memory\n");
        success = false;
        break;
      }
    }
    else if (strcmp (argName, "lenout") == 0)
    {
      if (!str_allocCpy (&(filenames->len), argValue))
      {
        printf ("Error:Out of Memory\n");
        success = false;
        break;
      }
    }
    else if (strcmp (argName, "input") == 0)
    {
      if (!str_allocCpy (&(filenames->pwList), argValue))
      {
        printf ("Error:Out of Memory\n");
        success = false;
        break;
      }
    }
    else if (strcmp (argName, "smoo") == 0)
    {
      if (!str_allocCpy (&(filenames->smoo), argValue))
      {
        printf ("Error:Out of Memory\n");
        success = false;
        break;
      }
    }
  }                             // end of file reached
  if (fp != NULL)
  {
    fclose (fp);
    fp = NULL;
  }

  if (!success)
    return false;

  // if the alphabet or the size of N has been changed, nGram and initalProb have to be reallocated
  if (nGramChanges)
    struct_nGrams_allocate (nGrams, alphabet);

  return true;
}                               // (intern) read_config

/* (intern function) skips the header of given fp */
bool skip_header (FILE * fp)
{
  char curLine[MAX_LINE_LENGTH];  // current line
  int lineCount = 0;            // counts lines of header to increase skipping time after the first

  if (lineCount > 0)
  {
    for (size_t i = 0; i < lineCount; i++)
    {
      if (fgets (curLine, sizeof (curLine) - 1, fp) == NULL)
      {
        // fgets returns NULL to indicate EOF
        return false;
      }
    }

    return true;
  }

  while (fgets (curLine, sizeof (curLine) - 1, fp) != NULL)
  {
    // if a line not beginning with '#' is reached...
    if (curLine[0] != '#')
    {
      // reset file pointer and return
      fseek (fp, -(long) strlen (curLine), SEEK_CUR);
      return true;
    }
    lineCount++;
  }                             // end of file reached or any other reading error

  return false;
}                               // (intern) skip_header

/* (intern function) reads any level file assigning the read values to the given levelArray */
bool read_level (int *levelArray, const int sizeOf_Array, FILE * fp)
{
  char curLine[MAX_LINE_LENGTH];  // current line
  int curValue;                 // current value

  // read header
  if (!skip_header (fp))
    return false;

  // read data
  for (size_t i = 0; i < sizeOf_Array; i++)
  {
    if (fgets (curLine, sizeof (curLine) - 1, fp) != NULL)
    {                           // reading successfull
      // read first int from current line
      sscanf (curLine, "%d", &curValue);
      levelArray[i] = curValue;
    }
    else
      return false;
  }

  return true;
}

/* (intern function) reads any array from given file according to the arrayType */
bool read_array (struct nGram_struct * nGrams, struct alphabet_struct * alphabet, const char *filenameIn, const char *fileAttachment, enum arrayTypes arrayType)
{
  FILE *fp = NULL;              // file pointer
  bool readSuccessful = false;

  // open file
  if (!(open_file (&fp, filenameIn, fileAttachment, "r")))
  {
    fprintf (stderr, "ERROR: file not found %s\n", filenameIn);
    return false;
  }

  switch (arrayType)
  {
  case arrayType_conditionalProb:
    readSuccessful = read_level ((nGrams->cP), (nGrams->sizeOf_cP), fp);
    break;
  case arrayType_initialProb:
    readSuccessful = read_level ((nGrams->iP), (nGrams->sizeOf_iP), fp);
    break;
  case arrayType_endProb:
    readSuccessful = read_level ((nGrams->eP), (nGrams->sizeOf_eP), fp);
    break;
  case arrayType_length:
    readSuccessful = read_level ((nGrams->len), (nGrams->sizeOf_len), fp);
    break;
  default:
    readSuccessful = false;
    break;
  }

  if (fp != NULL)
  {
    fclose (fp);
    fp = NULL;
  }

  if (!readSuccessful)
  {
    fprintf (stderr, "ERROR: Something went wrong while reading information from file (%s) ...\n", filenameIn);
    return false;
  }
  return true;
}                               // (intern) read_array

// === public functions ===

// reads and evaluates all input files for enumNG
bool read_inputFiles (struct nGram_struct * nGrams, struct alphabet_struct * alphabet, struct filename_struct * filenames, char *maxLevel)
{
  // read config file
  if (!(read_config (nGrams, alphabet, filenames, maxLevel, filenames->cfg)))
    return false;

  // read nGram level
  if (!(read_array (nGrams, alphabet, filenames->cP, DEFAULT_FILE_ATTACHMENT_LEVEL, arrayType_conditionalProb)))
    return false;

  // read initialProb level
  if (!(read_array (nGrams, alphabet, filenames->iP, DEFAULT_FILE_ATTACHMENT_LEVEL, arrayType_initialProb)))
    return false;

  // read endProb level
  if (!(read_array (nGrams, alphabet, filenames->eP, DEFAULT_FILE_ATTACHMENT_LEVEL, arrayType_endProb)))
    return false;

  // read length level
  if (!(read_array (nGrams, alphabet, filenames->len, DEFAULT_FILE_ATTACHMENT_LEVEL, arrayType_length)))
    return false;

  return true;
}
