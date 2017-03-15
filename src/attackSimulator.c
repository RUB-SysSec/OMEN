/* 
 * attackSimulator.c
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 */

// TODO: change this to c++ (allows to replace uthash with std::unordered_map

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <time.h>
#include <string.h>
#include "uthash.h"

#include "common.h"
#include "enumNG.h"
#include "attackSimulator.h"

// === Structures ===

typedef struct passwordSet_struct
{
  char id[50];                  // key
  int cracked;
  int count;                    // counts the number of occurrences of the password in the DB
  UT_hash_handle hh;            // makes this structure hashable
} passwordSet_struct;

// === Global Variables ===
// struct containing the testing set
passwordSet_struct *glbl_testingSet = NULL; // testingSet containing PWs for a simulated attack
uint64_t glbl_sizeOf_testingSet = 0;  // total number of passwords in the testing set

uint64_t glbl_crackedCount = 0; // Number of passwords cracked
uint64_t glbl_crackedLengths[MAX_PASSWORD_LENGTH];  // counting the lengths of the PWs that are also in the testingSet
float glbl_crackedRatio = 0.0;

FILE *glbl_FP_graphLengths = NULL;  // file pointer storing the length values
FILE *glbl_FP_graphCracked = NULL;  // file pointer storing the graph values
int glbl_outputCylce = 0;       // add every x created value to graph

/* (intern function) Returns the passwordSetStruct to the given @password if any or NULL */
passwordSet_struct *find_testSetPassword (const char *const password)
{
  passwordSet_struct *s;

  HASH_FIND_STR (glbl_testingSet, password, s); /* s: output pointer */
  return s;
}

/* (intern function) Adds the given @password to the global hashmap "glbl_testingSet" */
void add_testSetPassword (const char *const password)
{
  passwordSet_struct *s = NULL;

  // if the password already exists in the hashmap ...
  s = find_testSetPassword (password);
  if (s != NULL)
  {
    // ... only adjust the according counter
    s->count++;
    return;
  }
  else
  {                             // password doesn't exist in the hashmap ...
    // ... create and add a new entry
    s = (passwordSet_struct *) malloc (sizeof (passwordSet_struct));
    EXIT_IF_NULL (s) strncpy (s->id, password, 50);
    s->count = 1;
    s->cracked = 0;

    HASH_ADD_STR (glbl_testingSet, id, s);  /* id: name of key field */
  }
}

// generates a testing Set with the passwords found in the file filename
bool simAtt_generateTestingSet (const char *filename, const char *resultFolder, int outputCycle)
{
  FILE *fp = NULL;
  char curLine[MAX_LINE_LENGTH + 1];
  int length = 0;

  glbl_outputCylce = outputCycle;

  // open file
  if (!open_file (&fp, filename, NULL, "r"))
    return false;

  // read the whole file ...
  while (fgets (curLine, MAX_LINE_LENGTH, fp) != NULL)
  {
    length = strlen (curLine) - 1;
    // delete new line (if any)
    if (curLine[length] == '\n')
    {
      curLine[length] = '\0';
      length--;
    }
    // adjust the size counter
    glbl_sizeOf_testingSet++;
    // store the PW in the hashmap (or adjust existing PW count)
    add_testSetPassword (curLine);
  }
  // clean up
  if (fp != NULL)
  {
    fclose (fp);
    fp = NULL;
  }

  // open the cracked graph file
  if (!open_file (&glbl_FP_graphCracked, resultFolder, "/graphCracked.txt", "w"))
  {
    printf ("Error: Can't open graphCracked.txt\n");
    return false;
  }
  // open the lengths graph file
  if (!open_file (&glbl_FP_graphLengths, resultFolder, "/graphLength.txt", "w"))
  {
    printf ("Error: Can't open graphLength.txt\n");
    return false;
  }

  return true;
}

// free allocated memory
void simAtt_freeTestingSet ()
{
  passwordSet_struct *current, *tmp;

  HASH_ITER (hh, glbl_testingSet, current, tmp)
  {
    HASH_DEL (glbl_testingSet, current);  // delete; users advances to next
    free (current);             // optional- if you want to free
  }

  if (glbl_FP_graphCracked != NULL)
  {
    fclose (glbl_FP_graphCracked);
    glbl_FP_graphCracked = NULL;
  }
  if (glbl_FP_graphLengths != NULL)
  {
    fclose (glbl_FP_graphLengths);
    glbl_FP_graphLengths = NULL;
  }
}

// checks if given password is in the tesingSet
bool simAtt_checkCandidate (const char *const password, int length)
{
  bool crackSuccessful = false;
  passwordSet_struct *s = NULL;

  // try to find the given password in the hashmap ...
  s = find_testSetPassword (password);
  // if the password has been found ...
  if (s != NULL)
  {
    // check if it hasn't been cracked before ...
    if (s->cracked == 0)
    {
      // mark it as cracked and adjust all counter
      s->cracked = 1;
      glbl_crackedCount += s->count;
      glbl_crackedLengths[length - 1] += s->count;
      crackSuccessful = true;
    }
    else
      crackSuccessful = false;
  }

  // the cracked status after every 'x' attempt is added to the graph (x = glbl_outputCycle)
  if (glbl_attemptsCount % glbl_outputCylce == 0)
  {
    glbl_crackedRatio = ((float) glbl_crackedCount) / ((float) glbl_sizeOf_testingSet);
    fprintf (glbl_FP_graphCracked, "%" PRIu64 " %f\n", glbl_attemptsCount, glbl_crackedRatio);
    fprintf (glbl_FP_graphLengths, "%" PRIu64 " %i\n", glbl_attemptsCount, length);
    fflush (glbl_FP_graphCracked);
    fflush (glbl_FP_graphLengths);
  }

  if (glbl_crackedCount == glbl_sizeOf_testingSet)
  {
    glbl_crackedRatio = ((float) glbl_crackedCount) / ((float) glbl_sizeOf_testingSet);
    fprintf (glbl_FP_graphCracked, "%" PRIu64 " %f\n", glbl_attemptsCount, glbl_crackedRatio);
    fprintf (glbl_FP_graphLengths, "%" PRIu64 " %i\n", glbl_attemptsCount, length);
    fflush (glbl_FP_graphCracked);
    fflush (glbl_FP_graphLengths);
    exit (EXIT_SUCCESS);
  }

  return crackSuccessful;
}

bool simAtt_boostInit (const char *const resultFolder, int output_cycle)
{
  glbl_crackedCount = 0;
  glbl_sizeOf_testingSet = 0;
  glbl_outputCylce = output_cycle;
  // open the cracked graph file
  if (!open_file (&glbl_FP_graphCracked, resultFolder, "/graphCracked.txt", "w"))
  {
    printf ("Error: Can't open graphCracked.txt\n");
    return false;
  }
  // open the lengths graph file
  if (!open_file (&glbl_FP_graphLengths, resultFolder, "/graphLength.txt", "w"))
  {
    printf ("Error: Can't open graphLength.txt\n");
    return false;
  }
  return true;
}

void simAtt_boostNewPassword (const char *const password)
{
  glbl_sizeOf_testingSet++;
  add_testSetPassword (password);
}

bool simAtt_boostCheckCandidate (const char *const password, int length)
{
  bool result = false;
  passwordSet_struct *s = find_testSetPassword (password);

  if (s != NULL)
  {
    // password was successfully guessed
    glbl_crackedCount++;
    glbl_crackedLengths[length - 1]++;
    HASH_DEL (glbl_testingSet, s);
    free (s);

    result = true;
  }

  // the cracked status after every 'x' attempt is added to the graph (x = glbl_outputCycle)
  if (glbl_attemptsCount % glbl_outputCylce == 0)
  {
    glbl_crackedRatio = ((float) glbl_crackedCount) / ((float) glbl_sizeOf_testingSet);
    fprintf (glbl_FP_graphCracked, "%" PRIu64 " %f\n", glbl_attemptsCount, glbl_crackedRatio);
    fprintf (glbl_FP_graphLengths, "%" PRIu64 " %i\n", glbl_attemptsCount, length);
    fflush (glbl_FP_graphCracked);
    fflush (glbl_FP_graphLengths);
  }

  if (glbl_crackedCount == glbl_sizeOf_testingSet)
  {
    glbl_crackedRatio = ((float) glbl_crackedCount) / ((float) glbl_sizeOf_testingSet);
    fprintf (glbl_FP_graphCracked, "%" PRIu64 " %f\n", glbl_attemptsCount, glbl_crackedRatio);
    fprintf (glbl_FP_graphLengths, "%" PRIu64 " %i\n", glbl_attemptsCount, length);
    fflush (glbl_FP_graphCracked);
    fflush (glbl_FP_graphLengths);
  }
  return result;
}

// print the results of a simulated attack
void print_simulatedAttackResults (FILE * fp, bool additionalInfo)
{
  glbl_crackedRatio = ((float) glbl_crackedCount) / ((float) glbl_sizeOf_testingSet);
  fprintf (fp, "cracked: %" PRIu64 " of %" PRIu64 "(%.2f %%)\n", glbl_crackedCount, glbl_sizeOf_testingSet, glbl_crackedRatio * 100.0);

  // additional info are needed for the log file and shouldn't be printed to stdout
  if (additionalInfo)
  {
    int i;                      // loop variable

    // print results
    fprintf (fp, "\nlengths of the created passwords (length - created - cracked)\n");
    for (i = 2; i < MAX_PASSWORD_LENGTH; i++)
      fprintf (fp, "%2i - %9" PRIu64 " - %9" PRIu64 "\n", i + 1, glbl_createdLengths[i], glbl_crackedLengths[i]);
  }
}
