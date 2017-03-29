/*
 * defines.h
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 */

#ifndef DEFINES_H__
#define DEFINES_H__
/*
 * DEBUG mode
 *     - 1: debug mode (print debug information to stdout)
 *     - 0: release mode (don't print any debug information)
 */
#define DEBUG 1

// === common defines ===

/*
 * clean operation, which checks, if the given is not NULL before calling free
 */
#define CHECKED_FREE(ptr) if (ptr != NULL) { free(ptr); ptr = NULL; }

/*
 *  Wrapper arround exit(int) to gain access to the exit status in the exit_routine
 */
extern int exit_status;

#define exit(x) (exit)(exit_status = (x));

/*
 * If given pointer equals NULL,
 * exit application printing an "Out of Memory" error
 */
#define EXIT_IF_NULL(ptr) if (ptr == NULL) { printf("Critical Error: Out of Memory\n"); exit(1); }

/*
 *  default names, attachment and lengths for the the output files
 */
// default output file for ngram
#define DEFALUT_FILENAME_CONDITIONALPROB "CP"
// default output file for inital probs
#define DEFAULT_FILENAME_INITIALPROB "IP"
// default output file for inital probs
#define DEFAULT_FILENAME_ENDPROB "EP"
// default output file for password lengths
#define DEFAULT_FILENAME_LENGTH "LN"
// define file attachment for level
#define DEFAULT_FILE_ATTACHMENT_LEVEL ".level"
// define file attachment for count
#define DEFAULT_FILE_ATTACHMENT_COUNT ".count"
// define default config filename
#define DEFAULT_FILENAME_CONFIG "createConfig"
// define file attachment for config
#define DEFAULT_FILE_ATTACHMENT_CONFIG ".cfg"
// defines the max length of output file attachment (max(DEFAULT_FILE_ATTACHMENT_LEVEL, DEFAULT_FILE_ATTACHMENT_COUNT))
#define MAX_ATTACHMENT_LENGTH     ((strlen(DEFAULT_FILE_ATTACHMENT_LEVEL) >= strlen(DEFAULT_FILE_ATTACHMENT_COUNT)) ? \
                                   strlen(DEFAULT_FILE_ATTACHMENT_LEVEL) : strlen(DEFAULT_FILE_ATTACHMENT_COUNT))

/*
 * alphabet, alphabet sizes and the corresponding nGram sizes
 */
// default alphabet
// #define DEFAULT_ALPHABET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!.*@-_$#<>()?"
#define DEFAULT_ALPHABET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!.*@-_$#<?"
// #define DEFAULT_ALPHABET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$&'()*,-./:;<=>?@[]^_ `{}~\"+\\%|"
// max size of a new alphabet (read from command line)
#define MAX_ALPHABET_SIZE 1024
// size of default alphabet
#define DEFAULT_ALPHABET_SIZE ((int)strlen(DEFAULT_ALPHABET))
// size of 2gram using default alphabet
#define DEFAULT_SIZE_2_GRAM (DEFAULT_ALPHABET_SIZE * DEFAULT_ALPHABET_SIZE)
// size of 3-gram using default alphabet
#define DEFAULT_SIZE_3_GRAM (DEFAULT_ALPHABET_SIZE * DEFAULT_ALPHABET_SIZE * DEFAULT_ALPHABET_SIZE)

/*
 *  password length and level bounds
 */
// maximum password length
#define MAX_PASSWORD_LENGTH 20
// maximum level
#define MAX_LEVEL 11            // 0, 1, ..., 9, 10
// maximum line length while reading input files
#define MAX_LINE_LENGTH 512

#endif
