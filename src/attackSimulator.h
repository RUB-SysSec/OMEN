/* 
 * attackSimulator.h
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 *
 * Used by enumNG to perform a simulated attack. Reads a list of plain-text
 * passwords, referred to as training set, and provides function to check, if a
 * certain password created by enumNG is part of the training set.
 *
 */

#ifndef ATTACKSIMULATOR_H_
#define ATTACKSIMULATOR_H_

extern uint64_t glbl_crackedCount;
extern float glbl_crackedRatio;

/* 
 * Generates a "testing set" based on the passwords found in the
 * given @filename. If an error occurs FALSE is returned.
 * The passwords of the "testing set" are stored in the global variable
 * "glbl_testingSet". One can check if a password is part of the "testing Set"
 * using the function find_testSetingPassword(password).
 */
bool simAtt_generateTestingSet (const char *filename, // filename to the file containing the testing set passwords
                                const char *resultFolder, // folder for the result files
                                int outputCycle); // every x crack try should be added to the graph

/* 
 * Frees any memory allocated by the attack simulator
 */
void simAtt_freeTestingSet ();

/* 
 * Checks if the "testing set" (glbl_testingSet) contains the given @password.
 * Returns TRUE, if the password is part of the testing set or false if not.
 */
bool simAtt_checkCandidate (const char *const password, // the password to be checked out
                            int length);  // the length of the password

/* 
 * This functions prints the results of a simulated attack
 * to the given file pointer (i.e. stdout or log-file).
 * If @additionalInfo is TRUE, the additional infomration will
 * be printed
 */
void print_simulatedAttackResults (FILE * fp, // stdout or log file
                                   bool additionalInfo);  // print additional information

bool simAtt_boostInit (const char *const resultFolder, int output_cycle);
void simAtt_boostNewPassword (const char *const password);
bool simAtt_boostCheckCandidate (const char *const password, int length);
#endif /* ATTACKSIMULATOR_H_ */
