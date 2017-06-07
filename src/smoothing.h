/*
 * smoothing.h
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 *
 * Used by createNG to apply a smoothing to the counted n-grams and compute the
 * level. The smoothing functions are stored as function pointer.
 *
 */

#ifndef SMOOTHING_H_
#define SMOOTHING_H_

#include <stdio.h>
#include "common.h"

/*
 * How to implement new smoothings:
 *
 * Every smoothing needs a own struct to store the different parameters
 * and the following function (the names are arbitrary):
 *  - smoo_name_init()  -> initializes the corresponding struct with its default values
 *  - smoo_name_funct_Type() -> actual smoothing function (one for each arrayType)
 *  - smoo_name_read()  -> evaluates given file, adjust struct values and sets smoo_selection accordingly
 *  - smoo_name_print() -> prints the name of the smoothing and the current values
 * The smoo_name_funct must be have the following parameters:
 * void smoo_name_funct( int* level,            // the value to be set
 *                               int position,              // the current position in the @nGramArray
 *                               const int *nGramArray, // target nGram array
 *                               int sizeOf_nGramArray, // size of the nGram array
 *                               int sizeOf_N,              // size of the nGram N
 *                               int sumTotal,               // sum of all elements in nGram array
 * Any arrayType has his own smoothing function!
 *
 * Besides these function, an enum correlated to the smoothing must be set in the enum smooTypes.
 * In addition the following public smoothing handler function must be adjusted:
 *     - smoo_initialize()     -> call the init function of each smoothing
 *     - smoo_readInput()        -> call the read function of the given smoothing
 *  - smoo_printSelection() -> prints the selected smoothing (based on the smoo_types enum)
 *
 *
 * The file should look like this:
 * name
 * -<variable>_<target> <value>
 *
 * The allowed tags should be added as commentary and added to the documentation!
 */

/* smoothing caller function structer & parameters. void smoo_fct ( char* level, int position // level to be set and current position in given array const char* array, int size_array, // current array and its size int size_N, int size_alphabet, int maxLevel, // size of N and alphabet and the max level int totalSum) // sum of all elements in array (only needed for non condition probabilites) */
#define SMOOTHING_CALLER(name) void (*name)(char *, int,       \
                                            const int *, int, \
                                            int, int, char,    \
                                            int)

/*
 * enum used to identify the selected smoothing function
 */
enum smooTypes
{ smooType_additive = 0 };      // additve smoothing (default)

/*
 * smoo_selection_struct stores the pointer to the selected smoothing functions.
 * It is declared as extern, so createNG can directly call the smoothing functions
 */
typedef struct smoo_selection_struct
{
  SMOOTHING_CALLER (iP);
  SMOOTHING_CALLER (eP);
  SMOOTHING_CALLER (nG);
  SMOOTHING_CALLER (len);

  enum smooTypes type;
} smoo_selection_struct;

extern smoo_selection_struct smoo_selection;

/*
 * Sets the variables of all smoothings to their default value.
 * The smoo_selection is set to the additve smoothing.
 */
void smoo_initialize ();

/*
 * Opens the given file, checks which smoothing has been
 * selected and calls the according read function.
 * The input file must be an file formated like explained above.
 * Sets an error and returns FALSE if something went wrong.
 */
bool smoo_readInput (const char *filename);

/*
 * Uses smoo_types enum to identify the selected array
 * and calls the according print function
 */
void smoo_printSelection (FILE * fp, bool printToConfig);

#endif /* SMOOTHING_H_ */
