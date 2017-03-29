/*
 * evalPW.h
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 *
 * Evaluates a given password based on the Markov-model created by createNG.
 *
 */

#ifndef EVALPW_H_
#define EVALPW_H_

#include "common.h"

/*
 * initializes all global parameters, setting them to their default value
 * !! this function must be called before any other operation !!
 */
void initialize ();

/*
 *  prints all Error-Messages (if any), clears the allocated memory of the
 *  global variables and ends the application
 *  the char* exit_msg is printed out on the command line
 *  !! this function is set via atexit() !!
 */
void exit_routine ();

/*
 * prints the by arguments selected mode as well as the output and input filenames
 */
void print_settings ();

/*
 * Evaluates given command line arguments using the getopt-library
 * there has to be at least 1 argument: the input filename
 * additional arguments are evaluated in this method an the
 * corresponding parameters are set
 * returns TRUE, if the evaluation was successful
 */
bool evaluate_arguments (struct gengetopt_args_info *args_info);

/*
 * Reads any needed input file using the nGramIO-functions and
 * sets all needed variables accordingly.
 * Returns TRUE on success and FALSE if something went wrong.
 */
bool apply_settings ();

/*
 * Evaluates the password given by command line argument and
 * prints the overall level.
 * Returns FALSE, if the password is to short.
 * Otherwise TRUE is returned.
 */
bool run_evaluation ();

#endif /* EVALPW_H_ */
