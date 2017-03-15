/* 
 * nGramReader.h
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 *
 * Provides functions to read nGram and the according configuration from files
 * under the given filenames and store them in the given arrays.
 *
 */

#ifndef NGRAMREADER_H_
#define NGRAMREADER_H_

#include "common.h"
#include "commonStructs.h"

// === intern functions ===

/* 
 * // reads config file
 * BOOL read_config();
 *
 * // skips the header of given fp
 * BOOL skip_header();
 *
 * // reads any level file assigning the read values to the given levelArray
 * BOOL read_levelFromFile();
 *
 * // reads any count file assigning the read values to the given countArray
 * BOOL read_countFromFile();
 *
 * // reads any array from given file according to the arrayType
 * BOOL read_array();
 */

// === public funtions ===

/* 
 *     Reads all needed input files (levels for nGram and initalProb, count and levels for lengths)
 *  based on the config file that must be set in filenames, creating the filenames (attaching
 *  the default file ending) and sets the corresponding @nGrams and @alphabet variables using the
 *     other read function (read_ngramLevel, read_initialProbLevel, read_lengthLevel, read_lengthCount).
 *     Returns TRUE, if reading was successful.
 *     Otherwise any occurred error can be checked using the @errorHandler
 */
bool read_inputFiles (struct nGram_struct *nGrams,  // nGram arrays (must be initialized)
                      struct alphabet_struct *alphabet, // alphabet (must be initialized)
                      struct filename_struct *filenames,  // filenames (must contain a set config file name!)
                      char *maxLevel  // max level
  );

#endif /* NGRAMIO_H_ */
