/* 
 * smoothing.c
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <math.h>

#include "common.h"
#include "smoothing.h"

// the (extern) smoo_selection
smoo_selection_struct smoo_selection;

/* 
 * Begin: additive smoothing
 * Simple +1 smoothing. Just add delta (= 1 default) to any n-Gram count and
 * adjust the denominator accordingly.
 * Allowed values:
 * -delta_<target>          delta value of additive smoothing
 * -levelAdjust_<target> level adjustment factor
 * both must have the target  "all", "IP", "NG", "EP" or "LN".
 * ("all" gets overwritten by specific values set)
 */
// variables needed for the additive smoothing
typedef struct smoo_additive_struct
{
  int delta[ARRAY_TYPES_COUNT];
  int levelAdjustFactor[ARRAY_TYPES_COUNT];
} smoo_additive_struct;

smoo_additive_struct smoo_additive_vars;

// (intern) initialize default values
void smoo_additive_init ()
{
  for (size_t i = 0; i < ARRAY_TYPES_COUNT; i++)
    smoo_additive_vars.delta[i] = 1;
  smoo_additive_vars.delta[arrayType_length] = 0;

  for (size_t i = 0; i < ARRAY_TYPES_COUNT; i++)
    smoo_additive_vars.levelAdjustFactor[i] = 250;
  smoo_additive_vars.levelAdjustFactor[arrayType_conditionalProb] = 2;
  smoo_additive_vars.levelAdjustFactor[arrayType_length] = 1;
}

// (intern) actual smoothing function for non conditional probabilities (IP, EP and LN)
void smoo_additive_funct_nonConditional (char *level, // level to be set
                                         int position,  // current position in given array
                                         const int *nGramArray, // current array
                                         int sizeOf_nGramArray, // size of given array
                                         int sizeOf_N,  // size of N
                                         int sizeOf_alphabet, // size of alphabet
                                         char maxLevel, // max level
                                         int sumTotal,  // sum of all elements in array
                                         int delta, // delta for additive smoothing
                                         int levelAdjustFactor) // factor to avoid to small level
{
  double curValue = (double) (nGramArray[position] + delta);

  // sumTotal += (sizeOf_nGramArray * delta);
  sumTotal += (sizeOf_alphabet * sizeOf_alphabet * delta);

  if (sumTotal == 0)
    sumTotal = 1;

  curValue = (double) (curValue) / (double) (sumTotal);

  curValue *= levelAdjustFactor;

  // curValue += 0.00000000001; // avoid -infinity for log10
  curValue += 0.0000000001;     // avoid -infinity for log
  if (curValue > 1)
    curValue = 1;

  *level = (char) (log (curValue));
  // invert sign
  *level *= -1;
  // if larger the max level, set to max level
  if (*level > (maxLevel - 1))
    *level = maxLevel - 1;
}

// (intern) actual smoothing function with conditional probabilities (NG)
void smoo_additive_funct_conditional (char *level,  // level to be set
                                      int position, // current position in given array
                                      const int *nGramArray,  // current array
                                      int sizeOf_nGramArray,  // size of given array
                                      int sizeOf_N, // size of N
                                      int sizeOf_alphabet,  // size of alphabet
                                      char maxLevel,  // max level
                                      int delta,  // delta for additive smoothing
                                      int levelAdjustFactor)  // factor to avoid to small level
{
  long sumTotal = 0;
  double curValue = (double) (nGramArray[position] + delta);
  int position_mGram = 0;

  // get position without the position of the last gram
  position_mGram = position - (position % sizeOf_alphabet);
  // calculate sum for condition probability
  for (size_t i = 0; i < sizeOf_alphabet; i++)
    sumTotal += nGramArray[position_mGram + i];

  // apply delta
  sumTotal += (sizeOf_alphabet * delta);

  if (sumTotal == 0)
    sumTotal = 1;

  curValue = (curValue) / (double) (sumTotal);

  curValue *= (double) levelAdjustFactor;

  // curValue += 0.0000000001; // avoid -infinity for log10
  curValue += 0.000000001;      // avoid -infinity for log
  if (curValue > 1)
    curValue = 1;

  *level = (char) (log (curValue));
  // invert sign
  *level *= -1;
  // if larger the max level, set to max level
  if (*level > (maxLevel - 1))
    *level = maxLevel - 1;
}

/* 
 * The additive smoothing supports a different levelAdjustFactor and delta
 * for each arrayType. These are a wrapper around the actual
 * smoothing function selecting thchare according parameter.
 */
// wrapper for iP
void smoo_additive_funct_iP (char *level, int position, const int *nGramArray, int sizeOf_nGramArray, int sizeOf_N, int sizeOf_alphabet, char maxLevel, int sumTotal)
{
  smoo_additive_funct_nonConditional (level, position, nGramArray, sizeOf_nGramArray, sizeOf_N, sizeOf_alphabet, maxLevel, sumTotal, smoo_additive_vars.delta[arrayType_initialProb], smoo_additive_vars.levelAdjustFactor[arrayType_initialProb]);
}

// wrapper for cP
void smoo_additive_funct_cP (char *level, int position, const int *nGramArray, int sizeOf_nGramArray, int sizeOf_N, int sizeOf_alphabet, char maxLevel, int sumTotal)
{
  smoo_additive_funct_conditional (level, position, nGramArray, sizeOf_nGramArray, sizeOf_N, sizeOf_alphabet, maxLevel, smoo_additive_vars.delta[arrayType_conditionalProb], smoo_additive_vars.levelAdjustFactor[arrayType_conditionalProb]);
}

// wrapper for eP
void smoo_additive_funct_eP (char *level, int position, const int *nGramArray, int sizeOf_nGramArray, int sizeOf_N, int sizeOf_alphabet, char maxLevel, int sumTotal)
{
  smoo_additive_funct_nonConditional (level, position, nGramArray, sizeOf_nGramArray, sizeOf_N, sizeOf_alphabet, maxLevel, sumTotal, smoo_additive_vars.delta[arrayType_endProb], smoo_additive_vars.levelAdjustFactor[arrayType_endProb]);
}

// wrapper for length
void smoo_additive_funct_len (char *level, int position, const int *nGramArray, int sizeOf_nGramArray, int sizeOf_N, int sizeOf_alphabet, char maxLevel, int sumTotal)
{
  smoo_additive_funct_nonConditional (level, position, nGramArray, sizeOf_nGramArray, sizeOf_N, sizeOf_alphabet, maxLevel, sumTotal, smoo_additive_vars.delta[arrayType_length], smoo_additive_vars.levelAdjustFactor[arrayType_length]);
}

// (intern) evaluate input file and set values
void smoo_additive_apply (FILE * fp)
{
  char curLine[MAX_LINE_LENGTH];  // current line
  char argName[MAX_LINE_LENGTH];  // header argument name
  char argValue[MAX_LINE_LENGTH]; // header argument value

  // set pointer to additive smoothing
  smoo_selection.iP = &smoo_additive_funct_iP;
  smoo_selection.nG = &smoo_additive_funct_cP;
  smoo_selection.eP = &smoo_additive_funct_eP;
  smoo_selection.len = &smoo_additive_funct_len;

  smoo_selection.type = smooType_additive;

  smoo_additive_init ();

  while (fgets (curLine, MAX_LINE_LENGTH, fp) != NULL)
  {
    sscanf (curLine, "-%s %s", argName, argValue);
    if (strcmp (argName, "levelAdjust_all") == 0)
    {
      int levelAdjustFactor = atoi (argValue);

      if (levelAdjustFactor < 0)
        levelAdjustFactor = 0;
      for (size_t i = 0; i < ARRAY_TYPES_COUNT; i++)
        smoo_additive_vars.levelAdjustFactor[i] = levelAdjustFactor;
    }
    else if (strcmp (argName, "levelAdjust_IP") == 0)
    {
      smoo_additive_vars.levelAdjustFactor[arrayType_initialProb] = atoi (argValue);
      if (smoo_additive_vars.levelAdjustFactor[arrayType_initialProb] < 0)
        smoo_additive_vars.levelAdjustFactor[arrayType_initialProb] = 0;
    }
    else if (strcmp (argName, "levelAdjust_EP") == 0)
    {
      smoo_additive_vars.levelAdjustFactor[arrayType_endProb] = atoi (argValue);
      if (smoo_additive_vars.levelAdjustFactor[arrayType_endProb] < 0)
        smoo_additive_vars.levelAdjustFactor[arrayType_endProb] = 0;
    }
    else if (strcmp (argName, "levelAdjust_CP") == 0)
    {
      smoo_additive_vars.levelAdjustFactor[arrayType_conditionalProb] = atoi (argValue);
      if (smoo_additive_vars.levelAdjustFactor[arrayType_conditionalProb] < 0)
        smoo_additive_vars.levelAdjustFactor[arrayType_conditionalProb] = 0;
    }
    else if (strcmp (argName, "levelAdjust_LN") == 0)
    {
      smoo_additive_vars.levelAdjustFactor[arrayType_length] = atoi (argValue);
      if (smoo_additive_vars.levelAdjustFactor[arrayType_length] < 0)
        smoo_additive_vars.levelAdjustFactor[arrayType_length] = 0;
    }
    else if (strcmp (argName, "delta_all") == 0)
    {
      int delta = atoi (argValue);

      if (delta < 0)
        delta = 0;
      for (size_t i = 0; i < ARRAY_TYPES_COUNT; i++)
        smoo_additive_vars.delta[i] = delta;
    }
    else if (strcmp (argName, "delta_IP") == 0)
    {
      smoo_additive_vars.delta[arrayType_initialProb] = atoi (argValue);
      if (smoo_additive_vars.delta[arrayType_initialProb] < 0)
        smoo_additive_vars.delta[arrayType_initialProb] = 0;
    }
    else if (strcmp (argName, "delta_EP") == 0)
    {
      smoo_additive_vars.delta[arrayType_endProb] = atoi (argValue);
      if (smoo_additive_vars.delta[arrayType_endProb] < 0)
        smoo_additive_vars.delta[arrayType_endProb] = 0;
    }
    else if (strcmp (argName, "delta_CP") == 0)
    {
      smoo_additive_vars.delta[arrayType_conditionalProb] = atoi (argValue);
      if (smoo_additive_vars.delta[arrayType_conditionalProb] < 0)
        smoo_additive_vars.delta[arrayType_conditionalProb] = 0;
    }
    else if (strcmp (argName, "delta_LN") == 0)
    {
      smoo_additive_vars.delta[arrayType_length] = atoi (argValue);
      if (smoo_additive_vars.delta[arrayType_length] < 0)
        smoo_additive_vars.delta[arrayType_length] = 0;
    }
  }                             // end of file reached
}

// (intern) print selected values
void smoo_additive_print (FILE * fp, char *commentSign)
{
  fprintf (fp, "additive\n");

  // print delta values
  fprintf (fp, "%s\t- delta:\n%s\t  -", commentSign, commentSign);
  for (size_t i = 0; i < ARRAY_TYPES_COUNT; i++)
    fprintf (fp, " %s: %i;", arrayType_names[i], smoo_additive_vars.delta[i]);

  // print level adjustment facotrs
  fprintf (fp, "\n%s\t- levelAdjustFactor:\n%s\t  -", commentSign, commentSign);
  for (size_t i = 0; i < ARRAY_TYPES_COUNT; i++)
    fprintf (fp, " %s: %i;", arrayType_names[i], smoo_additive_vars.levelAdjustFactor[i]);

  fprintf (fp, "\n");
}

// === public functions ===

// initialize the smoothing values setting them to default
void smoo_initialize ()
{
  smoo_selection.type = smooType_additive;
  // set pointer to default smoothing (additive)
  smoo_selection.iP = &smoo_additive_funct_iP;
  smoo_selection.nG = &smoo_additive_funct_cP;
  smoo_selection.eP = &smoo_additive_funct_eP;
  smoo_selection.len = &smoo_additive_funct_len;
  // and set all variables their default values
  smoo_additive_init ();
}                               // smoo_initialize

// evaluate given XML-file and apply settings accordingly
bool smoo_readInput (const char *filename)
{
  FILE *fp = NULL;
  char curLine[MAX_LINE_LENGTH];  // current line
  char argValue[MAX_LINE_LENGTH]; // current line

  // open read xml file
  fp = fopen (filename, "r");
  if (fp == NULL)
  {
    fprintf (stderr, "ERROR: file not found %s\n", filename);
    return false;
  }
  while (fgets (curLine, MAX_LINE_LENGTH, fp) != NULL)
  {
    sscanf (curLine, "%s", argValue);
    if (strcmp (argValue, "additive") == 0)
      smoo_additive_apply (fp);
    else if (strcmp (argValue, "old") == 0)
      // smoo_old_apply(fp);
      fprintf (stderr, "ERROR: Old smoothing function not available anymore\n");
    else
    {
      fprintf (stderr, "ERROR: Unknown smoothing function %s\n", argValue);
      if (fp != NULL)
      {
        fclose (fp);
        fp = NULL;
      }
      return false;
    }
  }                             // end of file reached
  if (fp != NULL)
  {
    fclose (fp);
    fp = NULL;
  }

  return true;
}                               // smoo_readInput

// print the selected array and its settings
void smoo_printSelection (FILE * fp, bool printAsComment)
{
  char *commentSign = "#";

  if (!printAsComment)
    commentSign = "\0";
  fprintf (fp, "%s - Selected smoothing: ", commentSign);
  switch (smoo_selection.type)
  {
  case smooType_additive:
    smoo_additive_print (fp, commentSign);
    break;
    // case smooType_old:
    // smoo_old_print(fp, commentSign);
    // break;
  default:
    fprintf (fp, "???\n");
    break;
  }
}                               // smoo_printSelection
