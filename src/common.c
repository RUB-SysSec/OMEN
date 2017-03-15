/* 
 * common.c
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include "common.h"
#include "commonStructs.h"
#include "errorHandler.h"

/* 
 * Abbreviations in common use:
 *    - len = length
 *    - nG = nGram
 *    - cP = conditional probabilities
 *    - iP = initial probabilities
 */

// needed for exit_routine
int exit_status;

// the name of each array
const char arrayType_names[ARRAY_TYPES_COUNT][3] = { "IP", "CP", "EP", "LN" };

// get the char in the given alphabet at given position
bool get_charAtPosition (char *c, int position, const char *alphabet, int sizeOf_alphabet)
{
  if (position >= sizeOf_alphabet)
  {
    *c = '\0';
    return false;
  }
  else
  {
    *c = alphabet[position];
    return true;
  }
}                               // get_charAtPosition

// get the position of given char c in the given alphabet
bool get_positionInAlphabet (int *position, char c, const char *alphabet, int sizeOf_alphabet)
{
  // returns pointer to first char c in alphabet or NULL
  char *ptr = (char *) strchr (alphabet, c);

  if (ptr != NULL)
  {
    // address of ptr minus address of alphabet equals position of char c in alphabet
    *position = (int) (ptr - alphabet);
    return true;
  }
  else
    return false;
}                               // get_positionInAlphabet

// sets @position based on @nGram
bool get_positionFromNGram (int *position, const char nGram[], int sizeOf_N, int sizeOf_alphabet, const char *alphabet)
{
  int charPosition;

  // reset position
  *position = 0;
  // count position for nGram in the array
  for (size_t i = 0; i < sizeOf_N; i++)
  {
    if (!get_positionInAlphabet (&charPosition, nGram[i], alphabet, sizeOf_alphabet))
      return false;
    // multiply charPosition (sizeOfN-1 times for first, sizeOfN-2 for second ...)
    for (size_t j = i; j < sizeOf_N - 1; j++)
      charPosition *= sizeOf_alphabet;
    *position += charPosition;
  }
  return true;
}                               // get_positionFromNGram

// returns position of integer nGram
void get_positionFromNGramAsInt (int *position, const int nGramAsInt[], int sizeOf_N, int sizeOf_alphabet)
{
  int position_tmp;

  // reset position
  *position = 0;
  for (size_t i = 0; i < sizeOf_N; i++)
  {
    position_tmp = nGramAsInt[i];
    for (size_t j = i; j < sizeOf_N - 1; j++)
      position_tmp *= sizeOf_alphabet;

    *position += position_tmp;
  }
}                               // get_positionFromNGramAsInt

// sets @nGram based on @position
void get_nGramFromPosition (char *nGram, int position, int sizeOf_N, int sizeOf_alphabet, const char *alphabet)
{
  int i;
  int charPosition;

  // the last char is just position % sizef_alphabet
  charPosition = position % sizeOf_alphabet;
  get_charAtPosition (nGram + (sizeOf_N - 1), charPosition, alphabet, sizeOf_alphabet);
  position -= charPosition;
  // for all chars except the last ...
  for (i = sizeOf_N - 2; i >= 0; i--)
  {
    // divide position by sizeOf_Alphabet
    position /= sizeOf_alphabet;
    // take rest as position for current char
    charPosition = position % sizeOf_alphabet;
    get_charAtPosition (nGram + i, charPosition, alphabet, sizeOf_alphabet);
    // subtract used charPosition from position
    position -= charPosition;
  }
}                               // get_nGramFromPosition

// returns nGram of position as integer
void get_nGramAsIntFromPosition (int *nGramAsInt, int position, int sizeOf_N, int sizeOf_alphabet)
{
  int i;
  int intPosition;

  // get position_lastGram
  // the last char is just position % sizef_alphabet
  intPosition = position % sizeOf_alphabet;
  nGramAsInt[sizeOf_N - 1] = intPosition;
  position -= intPosition;
  // for all chars except the last ...
  for (i = sizeOf_N - 2; i >= 0; i--)
  {
    // divide position by sizeOf_Alphabet
    position /= sizeOf_alphabet;
    // take rest as position for current char
    intPosition = position % sizeOf_alphabet;
    nGramAsInt[i] = intPosition;
    // subtract used charPosition from position
    position -= intPosition;
  }
}                               // get_nGramAsIntFromPosition

// allocates memory and copy a string
bool str_allocCpy (char **dest, const char *src)
{
  // reallocate memory
  *dest = (char *) realloc (*dest, sizeof (char) * strlen (src) + 1);
  // check allocation
  if (*dest == NULL)
  {
    return false;
  }

  // copy content
  strcpy (*dest, src);
  return true;
}                               // str_allocCpy

// appends a prefix to a string
bool str_appendPrefix (char **str, const char *prefix)
{
  char newStr[strlen (*str) + strlen (prefix) + 1];

  // append prefix
  snprintf (newStr, sizeof (newStr), "%s%s", prefix, *str);
  // realloc and copy
  return str_allocCpy (str, newStr);
}                               // str_appendPrefix

// appends a suffix to a string
bool str_appendSuffix (char **str, const char *suffix)
{
  char newStr[strlen (*str) + strlen (suffix) + 1];

  // append suffix
  snprintf (newStr, sizeof (newStr), "%s%s", *str, suffix);
  // realloc and copy
  return str_allocCpy (str, newStr);
}                               // str_appendSuffix

// replaces chars in a string
void str_replace (char *str, const char oldChar, const char newChar)
{
  for (size_t i = 0; i < strlen (str); i++)
    if (str[i] == oldChar)
    {
      str[i] = newChar;
    }
}                               // str_replace

// prints timestamp and title
void print_timestamp (const char *title)
{
  time_t lt = time (NULL);
  struct tm *ptr = localtime (&lt);

  printf ("%s\t%s", title, asctime (ptr));
}                               // print_timestamp

// prints timestamp and title with time different between now and the first time this function has been called
void set_timestampWithDiff (FILE * fp, bool printStamp, bool rePrintStartTime)
{
  static bool firstCall = true;
  static time_t startTime = 0;

  // if it's the first call of this function...
  if (firstCall)
  {
    // set the start time ...
    startTime = time (NULL);
    firstCall = false;
    if (printStamp)
      fprintf (fp, "\nStart:\t%s", ctime (&startTime));
  }
  else
  {                             // subsequent call
    // variables for formated elapsed time
    int secElapsed;
    int sec, min, hou;

    // end time
    time_t endTime = 0;

    // reprint the start time ? (e.g. for log file)
    if (rePrintStartTime && printStamp)
      fprintf (fp, "\nStart:\t%s", ctime (&startTime));

    // set and print current time
    endTime = time (NULL);
    if (printStamp)
      fprintf (fp, "End:\t%s", ctime (&endTime));

    // get time diff and extract hours, minutes and seconds
    secElapsed = (int) difftime (endTime, startTime);
    hou = (int) ((secElapsed / 60) / 60);
    min = (int) ((secElapsed / 60) % 60);
    sec = (int) (secElapsed % 60);

    // print elapsed time
    if (printStamp)
      fprintf (fp, "Elapsed time: %i hour(s), %i minute(s) and %i second(s)\n", hou, min, sec);
  }
}                               // set_timestampWithDiff

// creates a formated time string based on the current date and time
void get_formatedTime (char (*timeStr)[15])
{
  // time to generate a log file with timestamp
  time_t lt = time (NULL);
  struct tm *ptr = localtime (&lt);

  // generate formated time string
  strftime (*timeStr, sizeof (*timeStr), "%y-%m-%d_%H.%M", ptr);
}                               // get_formatedTime

// prints default information
void print_settings_default (FILE * fp, int sizeOf_N, alphabet_struct * alphabet, filename_struct * filenames, unsigned int maxLevel, bool verboseFileMode)
{
  if (verboseFileMode)
    fprintf (fp, " - VerboseFileMode\n");

  fprintf (fp, " - SizeOf_N: %i\n", sizeOf_N);
  fprintf (fp, " - maxLevel: %i\n", maxLevel);
  fprintf (fp, " - Filenames:\n");
  fprintf (fp, "\tinitial probabilities: '%s'\n", (filenames->iP));
  fprintf (fp, "\tconditional probabilities: '%s'\n", (filenames->cP));
  fprintf (fp, "\tend probabilities: '%s'\n", (filenames->eP));
  fprintf (fp, "\tlengths: '%s'\n", (filenames->len));
  fprintf (fp, "\tconfig: '%s'\n", (filenames->cfg));
  fprintf (fp, "\tinput: '%s'\n", (filenames->pwList));
  fprintf (fp, " - Alphabet: '%s'\n", (alphabet->alphabet));
  fprintf (fp, " - sizeOf_Alphabet: %i\n", (alphabet->sizeOf_alphabet));
}                               // print_settings_default

// opens given file adding given attachment
bool open_file (FILE ** fp, const char *filename, const char *attachment, const char *type)
{
  if (attachment != NULL)
  {
    char complFilename[strlen (filename) + strlen (attachment) + 1];

    // create filenames
    snprintf (complFilename, sizeof (complFilename), "%s%s", filename, attachment);
    // open file
    *fp = NULL;
    *fp = fopen (complFilename, type);
  }
  else
  {
    *fp = NULL;
    *fp = fopen (filename, type);
  }

  // check file pointer
  if ((*fp) == NULL)
  {
    fprintf (stderr, "ERROR: Could not open %s, errno: %d - \"%s\"\n", filename, errno, strerror (errno));
    return false;
  }

  return true;
}                               // open_file

// changes filename to optarg
bool changeFilename (char **filename, int maxFilenameSize, const char *valueName, const char *new_filename)
{
  // check the length of the filename
  if (strlen (new_filename) > (maxFilenameSize))
  {
    fprintf (stderr, "ERROR: The Filename of the %s file should not be longer then %i characters", valueName, maxFilenameSize);
    return false;
  }

  // reallocate memory for new ngram filename and copy content
  if (!str_allocCpy (filename, new_filename))
  {
    fprintf (stderr, "ERROR: Out of Memory\n");
    return false;
  }

  return true;
}                               // changeFilename
