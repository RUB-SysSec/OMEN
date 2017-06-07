/*
 * boosting.c
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 */

#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "commonStructs.h"
#include "boosting.h"
#include "attackSimulator.h"

int *saved_iPs;
int *saved_cPs;
int *saved_ePs;

// http://stackoverflow.com/questions/2532425/
// Always add at least this many bytes when extending the buffer.
#define MIN_CHUNK 64

ssize_t readline (char **lineptr, size_t * n, FILE * stream)
{
  int CUR_MAX = MIN_CHUNK;
  int count = 0;
  int length = 0;

  // check if we should allocate memory for line, and if so, do so :)
  if ((*n == 0) || (*lineptr == NULL))
  {
    *lineptr = (char *) malloc (sizeof (char) * CUR_MAX); // allocate buffer.
    if (*lineptr == NULL)
    {
      return -1;
    }
    // else, get the amount of available memory
  }
  else
  {
    CUR_MAX = strlen (*lineptr);
  }

  // read line until newline or end of file char-by-char and store it in the lineptr
  char ch = 0;

  while ((ch != '\n') && (ch != EOF))
  {
    // if necessary, extend allocated memory by MIN_CHUNK bytes
    if (count == CUR_MAX)
    {
      CUR_MAX += MIN_CHUNK;
      *lineptr = (char *) realloc (*lineptr, sizeof (char) * CUR_MAX);  // re allocate memory.
      *n = CUR_MAX;
      if (*lineptr == NULL)
      {
        return -1;
      }
    }
    ch = fgetc (stream);        // read from stream.
    if (ch == EOF)
    {
      return -1;                // got EOF, thus no more lines to read
    }
    (*lineptr)[length] = ch;    // stuff in buffer.
    length++;
    count++;
  }

  // null terminate the whole line
  if (count + 1 <= CUR_MAX)
  {
    (*lineptr)[length] = '\0';
    // if necessary, allocate another byte for this
  }
  else
  {
    CUR_MAX++;
    *lineptr = (char *) realloc (*lineptr, sizeof (char) * CUR_MAX);  // re allocate memory.
    *n = CUR_MAX;
    if (*lineptr == NULL)
    {
      return -1;
    }
    (*lineptr)[length] = '\0';
  }

  // return the length of the line
  return count;
}

// parse alpha file into array
int *read_alphas (char *filename, int *alpha_count)
{
  int *boost_alphas = (int *) malloc (sizeof (int));

  (*alpha_count) = 1;
  char *line;
  size_t len = 0;

  // open alpha file
  FILE *alpha_file = fopen (filename, "r");

  if (alpha_file == NULL)
  {
    return NULL;
  }

  // read line from file
  if (readline (&line, &len, alpha_file) == -1)
  {
    free (line);
    fclose (alpha_file);
    return NULL;
  }

  // content of alpha_file is saved in line, therefore we can close it
  fclose (alpha_file);

  // split line by whitespace and save tokens as ints in boost_alphas
  char *alpha = strtok (line, "\t\n");

  while (alpha != NULL)
  {
    boost_alphas[(*alpha_count) - 1] = strtol (alpha, NULL, 10);
    alpha = strtok (NULL, "\t\n");
    // look ahead parser to increase array size
    if (alpha != NULL)
    {
      (*alpha_count)++;
      boost_alphas = (int *) realloc (boost_alphas, sizeof (int) * (*alpha_count));
    }
  }
  // free memory
  free (line);
  return boost_alphas;
}

char **read_hints (char *filename, int alpha_count, int hint_count)
{
  char *line;
  size_t len = 0;

  // open hint file
  FILE *hint_file = fopen (filename, "r");

  if (hint_file == NULL)
  {
    return NULL;
  }

  // skip first hint_count many lines
  for (int i = 0; i < hint_count; i++)
  {
    if (readline (&line, &len, hint_file) == -1)
    {
      free (line);
      fclose (hint_file);
      return NULL;
    }
    free (line);
  }

  // read line from file
  if (readline (&line, &len, hint_file) == -1)
  {
    free (line);
    fclose (hint_file);
    return NULL;
  }

  // hint is read, thus we can close file
  fclose (hint_file);

  char **hints = (char **) malloc (sizeof (char *) * alpha_count);

  // split line by comma and save tokens as strings in hints
  char *hint = strtok (line, "\t\n");
  int size = (strlen (hint) + 1) * sizeof (char);

  hints[0] = (char *) malloc (sizeof (char) * size);
  for (size_t i = 0; i < alpha_count; i++)
  {
    strcpy ((hints[i]), hint);
    hint = strtok (NULL, "\t\n");
    // look ahead parser to increase array size
    if (hint != NULL)
    {
      size = (strlen (hint) + 1) * sizeof (char);
      hints[i + 1] = (char *) malloc (sizeof (char) * size);
    }
  }

  // free memory
  free (line);
  return hints;
}

bool read_password (FILE * password_file)
{
  char *password_line;
  size_t len = 0;

  if (readline (&password_line, &len, password_file) == -1)
  {
    free (password_line);
    return false;
  }

  for (int i = 0; i < strlen (password_line); i++)
  {
    if (password_line[i] == '\n')
    {
      password_line[i] = '\0';
      break;
    }
  }

  printf ("%s, ", password_line);
  simAtt_boostNewPassword (password_line);
  free (password_line);
  return true;
}

void save_level (const nGram_struct * const nGrams)
{
  saved_iPs = (int *) malloc (sizeof (int) * nGrams->sizeOf_iP);
  saved_cPs = (int *) malloc (sizeof (int) * nGrams->sizeOf_cP);
  saved_ePs = (int *) malloc (sizeof (int) * nGrams->sizeOf_eP);

  memcpy (saved_iPs, nGrams->iP, nGrams->sizeOf_iP);
  memcpy (saved_cPs, nGrams->cP, nGrams->sizeOf_cP);
  memcpy (saved_ePs, nGrams->eP, nGrams->sizeOf_eP);
}

void free_saved_level ()
{
  free (saved_iPs);
  free (saved_cPs);
  free (saved_ePs);
}

void boost (nGram_struct * nGrams, const alphabet_struct * const alph, const int *const alphas, char **hints, int alpha_count, bool boost_ep)
{
  int *const iPs = nGrams->iP;
  int *const cPs = nGrams->cP;
  int *const ePs = nGrams->eP;
  const int ngram_size = nGrams->sizeOf_N;
  const int a_size = alph->sizeOf_alphabet;
  const char *const a = alph->alphabet;

  for (int i = 0; i < alpha_count; i++)
  {
    int ngram_pos;
    int alpha = alphas[i];
    char *const hint = hints[i];
    int hint_len = strlen (hint);

    // boost ip
    get_positionFromNGram (&ngram_pos, hint, ngram_size - 1, a_size, a);
    iPs[ngram_pos] = fmax (0, iPs[ngram_pos] - alpha);

    // boost ep
    if (boost_ep)
    {
      const char *const hint_ep = &(hint[hint_len - (ngram_size - 1)]);

      get_positionFromNGram (&ngram_pos, hint_ep, ngram_size - 1, a_size, a);
      ePs[ngram_pos] = fmax (0, ePs[ngram_pos] - alpha);
    }

    // boost cps
    int number_of_ngrams = hint_len - ngram_size + 1;

    for (int j = 0; j < number_of_ngrams; j++)
    {
      int ngram_pos;

      get_positionFromNGram (&ngram_pos, hint + j, ngram_size, a_size, a);
      cPs[ngram_pos] = fmax (0, cPs[ngram_pos] - alpha);
    }
  }
}

/*
 * undo the changes by boost()
 */
void deboost (nGram_struct * nGrams)
{
  memcpy (nGrams->iP, saved_iPs, nGrams->sizeOf_iP);
  memcpy (nGrams->cP, saved_cPs, nGrams->sizeOf_cP);
  memcpy (nGrams->eP, saved_ePs, nGrams->sizeOf_eP);
}
