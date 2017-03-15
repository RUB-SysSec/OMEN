/* 
 * common.h
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 *
 * Provides common functions that are used by nearly every module of the
 * application, e.g.:
 *   - functions to manipulate strings in various ways
 *   - function to open files
 *   - functions to calculate corresponding characters to a given alphabet
 *     position and vice versa
 * Provides basic #defines
 *
 */

#pragma once
#include <stdbool.h>

#include "commonStructs.h"
#include "defines.h"

// === common enums ===

/* 
 * Used by the read_array function.
 * It is used to determine the type of an given array.
 */
enum arrayTypes
{ arrayType_initialProb = 0,
  arrayType_conditionalProb = 1,
  arrayType_endProb = 2,
  arrayType_length = 3,
};

// the count of all different array types
#define ARRAY_TYPES_COUNT 4
// the names of each array
extern const char arrayType_names[ARRAY_TYPES_COUNT][3];

// === common functions ===

/* 
 *    Sets @position to the position of char @c in the given @alphabet.
 *    Returns FALSE if @c isn't a part of the alphabet.
 */
bool get_positionInAlphabet (int *position, char c, const char *alphabet, int sizeOf_alphabet);

/* 
 *  Sets @c to the char at @position in the given @alphabet.
 *  Returns FALSE if @position >= @sizeOf_alphabet.
 */
bool get_charAtPosition (char *c, int position, const char *alphabet, int sizeOf_alphabet);

/* 
 *  Sets @position to the actual position of the given @nGram
 *  in an array storing nGrams with at least @sizeOfN characters.
 *  The calculation is based on the given @alphabet with a length
 *  of @szieOf_alphabet.
 *  Returns FALSE if @nGram contains an unknown symbol.
 */
bool get_positionFromNGram (int *position, const char nGram[], int sizeOf_N, int sizeOf_alphabet, const char *alphabet);

/* 
 *  Sets @position to the actual position of the given @nGramAsInt
 *  in an array storing the corresponding integer of a nGram with
 *  at least @sizeOfN characters.
 *  The calculation is based on the given length @szieOf_alphabet.
 */
void get_positionFromNGramAsInt (int *position, const int nGramAsInt[], int sizeOf_N, int sizeOf_alphabet);

/* 
 * Fills @nGram with the actual character according to the
 * given position @position, based on the given @alphabet
 * with a length of @szieOf_alphabet.
 * - @nGram must be able to store at least @sizeOf_N chars
 */
void get_nGramFromPosition (char *nGram, int position, int sizeOf_N, int sizeOf_alphabet, const char *alphabet);

/* 
 * Fills @nGramAsInt with the positions in the alphabet to
 * the corresponding nGram according to the given position
 * @position, based on the given @alphabet with a length of
 * @szieOf_alphabet.
 * - @nGramAsInt must be able to store at least @sizeOf_N ints
 */
void get_nGramAsIntFromPosition (int *nGramAsInt, int position, int sizeOf_N, int sizeOf_alphabet);

/* 
 * allocates (or reallocates) @*str and copies the c-string @src
 */
bool str_allocCpy (char **str, const char *src);

/* 
 * Appends the given @prefix to the given @str
 */
bool str_appendPrefix (char **str, const char *prefix);

/* 
 * Appends the given @suffix to given @str
 */
bool str_appendSuffix (char **str, const char *suffix);

/* 
 * Replaces all chars @oldChar in @str with @newChar
 */
void str_replace (char *str, const char oldChar, const char newChar);

/* 
 * Prints a time stamp with the given title
 */
void print_timestamp (const char *title);

/* 
 * Prints timestamp with time different between now and the first time
 * this function has been called (or just the timestamp, if it's the first time)
 * This function automatically prints a title in addition to the timestamp
 * ("Start:" at the first time and "End:" at every additional call)
 *  The information can be written to stdout or to a log-file (set by @fp)
 *  The startTime can be rewritten if @rePrintStartTime (including title). This
 *  is needed for a well formated log file.
 *  If @printStamp is FALSE, the timestamp (i.e. the start time) is just set
 *  an nothing is print out (needed for non-verboseMode)
 */
void set_timestampWithDiff (FILE * fp,  // write information to the given FILE (stdout or log-file)
                            bool printStamp,  // if FALSE the timestamp is just set and not printed
                            bool rePrintStartTime); // re prints the start time

/* 
 * Creates a formated string containing the current date and time. The string
 * is formated like this: "Year-Month-Day_Houre.Minute" with 2 digits each. Therefore
 * the given pointer to a c-string must be able to store at least 15 chars.
 */
void get_formatedTime (char (*timeStr)[15]);  // 15 = 9: date(YY-MM-DD_) + 5: time(HH.MM) + 1: (\0)

/* 
 * Prints default information.
 * The information can be written to stdout or to a log-file
 * (set by @fp)
 */
void print_settings_default (FILE * fp, // write information to the given FILE (stdout or log-file)
                             int sizeOf_N, alphabet_struct * alphabet,  // alphabet and alphabet length
                             filename_struct * filenames, // filenames for all in-/output files
                             unsigned int maxLevel, // selected max level
                             bool verboseFileMode); // is verboseFileMode active?

/* 
 *  Opens the file under the given @filename adding the @attachment.
 *  The file is opened with the rights given by @type.
 *  True is returned, if the file could be opened successful.
 *  If the file could not be opened, False is returned.
 *  (If none attachment should be added, NULL must be given as
 *   @attachment)
 */
bool open_file (FILE ** fp,     // file pointer
                const char *filename, // filename
                const char *attachment, // file attachment (or NULL)
                const char *type);  // write or read mode


/* 
 * Changes output filename for any given filename.
 * Reallocates memory for filename and copies content.
 * If the filename is to long, an error is set to the @errorHandler,
 * if the application runs out of memory, it will be aborted.
 */
bool changeFilename (char **filename, // pointer to the (old) filename
                     int maxFilenameSize, // max strlen of filename
                     const char *valueName, // name of the value (for an formated error message)
                     const char *new_filename);
