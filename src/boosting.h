/*
 * boosting.h
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 */

#ifndef __BOOSTING_H__
#define __BOOSTING_H__

#include "commonStructs.h"

/*
 * Reads boosting factor alpha from file in return array.
 */
int *read_alphas (char *filename, int *alpha_count);

/*
 * Reads hints from file in return array.
 */
char **read_hints (char *filename, int alpha_count, int hint_count);

bool read_password (FILE * password_file);

void save_level (const nGram_struct * const nGrams);
void free_saved_level ();

void boost (nGram_struct * nGrams, const alphabet_struct * const alph, const int *const alphas, char **hints, int alpha_count, bool boost_ep);
void deboost (nGram_struct * nGrams);

#endif
