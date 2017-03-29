/*
 * createNG.h
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 *
 * Reads the input file and counts the occurring n-grams. The n-gram levels,
 * computed by smoothing - are stored in files, one for each n-gram type and one
 * for the lengths. createNG also generates a configuration file referred as
 * createConfig storing the used settings.
 *
 */

#include "common.h"
#include "errorHandler.h"
#include "smoothing.h"

/*
 * Used by the write_*ToFile functions.
 * - if writeMode is nonVerbose: only the counts and levels are written into the file
 * - if writeMode is numeric: the array index is written into the file as well
 * - if writeMode is nGram: the actual nGram is written into the file as well
 */
enum writeModes
{ writeMode_nonVerbose = 0,     // write only the counts and levels
  writeMode_numeric = 1,        // write the array index as well
  writeMode_nGram = 2           // write the actual nGram as well
};

// === intern functions ===
/*
 *     These functions are used to adjust the according array based on the given file or length:
 *     void adjust_length();
 *     void adjust_initialProb();
 *     void adjust_nGram();
 *     void adjust_endProb();
 *
 *     write functions:
 *     BOOL write_arrayToFile();  // writes given array to file (using the given smoothing function)
 *    void write_headerToFile(); // write the default header to given file
 */

// === public functions ===

/*
 *     initializes all global parameters, setting them to their default value
 *     !! this function must be called before any other operation !!
 */
void initialize ();

/*
 *  prints all Error-Messages (if any), clears the allocated memory of the
 *  global variables and ends the application
 *  the char* exit_msg is printed out on the command line
 *  !! this function is set via atexit() and automatically called at the end of the application!!
 */
void exit_routine ();

/*
 *     evaluates given command line arguments using the getopt-library
 *     there has to be at least 1 argument: the input filename
 *     additional arguments are evaluated in this method an the
 *     corresponding parameters are set
 *     returns TRUE, if the evaluation was successful
 */
bool evaluate_arguments (struct gengetopt_args_info *args_info);

/*
 *  main process: calls evaluate_InputFile and the Write-Methods
 *  returns TRUE, if the creation was successful (no Errors occurred)
 *  otherwise FALSE is returned and the occurred Errors can be viewed using
 *  the Error-Handler
 */
bool run_creation ();

/*
 *     evaluates the input file, reading the 3grams, initial probabilities and the pwd lengths
 *     and storing them in the associated global variables
 *     1. counts the occurrence of any n-gram in the input file (stored in glbl_nGramCount->nG)
 *     2. counts the initial probability (as (n-1)-gram, stored in glbl_nGramCount->iP)
 *     3. counts passwords length (max length SIZE_LENGTH_FIELD, stored in glbl_nGramCount->len)
 */
bool evaluate_inputFile (const char *filenameIn);

/*
 *     Writes header and additional information into the given file
 *     the additional information are chosen filenames
 *     header syntax:
 *         # name value \n
 *     This functions uses the intern function write_headerToFile()
 */
bool write_config (const char *filenameConfig);

/*
 *  Opens the given files and writes data according to the given
 *  @arrayType. This may be:
 *   - arrayType_nGram
 *     - arrayType_initialProb
 *     - arrayType_length
 *     This functions uses the intern function write_headerToFile() and
 *     write_arrayToFile().
 */
bool write_array (const char *filename, enum arrayTypes arrayType);

/*
 *     Prints the by arguments selected mode as well as the output and input filenames
 *     to the given file pointer @fp.
 */
void print_settings_createNG (FILE * fp);

/*
 * Sets @alphabet according to file under the filename @filename
 * and adjust @sizeOf_alphabet to the size of the new alphabet.
 * If there are problems opening or reading the file, an error
 * is set using the given @errorHandler.
 * If the application runs out of memory, it will be aborted.
 */
bool alphabetFromFile (char **alphabet, // pointer to the (old) alphabet
                       int *sizeOf_alphabet,  // pointer to the size of the (old) alphabet
                       const char *filename); // new alphabet

/*
 *  Appends any given @prefix, @suffix or the current date (if @dateSuffix is TRUE)
 *  as suffix to all output filenames.
 *  The allocated memory for the char* is freed by this function.
 */
bool append_prefixSuffix (char **prefix,  // prefix (NULL if none prefix should be set)
                          char **suffix,  // suffix (NULL if none prefix should be set)
                          bool dateSuffix,  // append current date
                          filename_struct * filenames); // filenames the pre-/suffixes should be append to
