/*
 * alphabetCreator.h
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 */

#ifndef ALPHABETCREATOR_H_
#define ALPHABETCREATOR_H_

/*
 * initializes all global parameters, setting them to their default value
 * !! this function must be called before any other operation !!
 */
void initialize ();

/*
 *  prints all Error-Messages (if any), clears the allocated memory of the
 *  global variables and ends the application
 *  !! this function is set via atexit() !!
 */
void exit_routine ();

/*
 * prints the by arguments selected mode as well as the output and input filenames
 */
void print_settings ();

bool evaluate_arguments (struct gengetopt_args_info *args_info);

bool apply_settings ();

bool run_creation ();

bool write_newAlphabet ();

#endif /* ALPHABETCREATOR_H_ */
