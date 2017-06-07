/*
 * commonStructs.c
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "commonStructs.h"

// === filename functions ===

// initializes given filenameStruct
void struct_filenames_initialize (filename_struct ** filenames)
{
  (*filenames) = (filename_struct *) malloc (sizeof (filename_struct));
  EXIT_IF_NULL ((*filenames));
  // set pointer to NULL and int to 0
  (*filenames)->cP = NULL;
  (*filenames)->iP = NULL;
  (*filenames)->eP = NULL;
  (*filenames)->len = NULL;
  (*filenames)->cfg = NULL;
  (*filenames)->pwList = NULL;
  (*filenames)->smoo = NULL;
}                               // struct_initialize_filenames

// frees given filenameStruct
void struct_filenames_free (filename_struct ** filenames)
{
  if ((*filenames) != NULL)
  {
    CHECKED_FREE ((*filenames)->cP);
    CHECKED_FREE ((*filenames)->iP);
    CHECKED_FREE ((*filenames)->eP);
    CHECKED_FREE ((*filenames)->len);
    CHECKED_FREE ((*filenames)->cfg);
    CHECKED_FREE ((*filenames)->pwList);
    CHECKED_FREE ((*filenames)->smoo);
    free (*filenames);
    *filenames = NULL;
  }
}                               // struct_free_filenames

// allocate default filenameStruct
void struct_filenames_allocateDefaults (filename_struct * filenames)
{
  // output filenames for nGram, initalProb and length
  if (!str_allocCpy (&(filenames->cP), DEFALUT_FILENAME_CONDITIONALPROB) || !str_allocCpy (&(filenames->iP), DEFAULT_FILENAME_INITIALPROB) || !str_allocCpy (&(filenames->eP), DEFAULT_FILENAME_ENDPROB) || !str_allocCpy (&(filenames->len), DEFAULT_FILENAME_LENGTH) || !str_allocCpy (&(filenames->cfg), DEFAULT_FILENAME_CONFIG))
  {
    printf ("Error: Out of Memory\n");
    exit (1);
  }
}                               // struct_allocateDefaults_filenames

// === alphabet functions ===

// initializes given alphabetStruct
void struct_alphabet_initialize (alphabet_struct ** alphabet)
{
  *alphabet = (alphabet_struct *) malloc (sizeof (alphabet_struct));
  EXIT_IF_NULL ((*alphabet));
  // set pointer to NULL and int to 0
  (*alphabet)->alphabet = NULL;
  (*alphabet)->sizeOf_alphabet = 0;
}                               // struct_initialize_alphabet

// frees given alphabetStruct
void struct_alphabet_free (alphabet_struct ** alphabet)
{
  if ((*alphabet) != NULL)
  {
    CHECKED_FREE ((*alphabet)->alphabet) free (*alphabet);
    *alphabet = NULL;
  }
}                               // struct_free_alphabet

// allocate default alphabetStruct
void struct_alphabet_allocateDefaults (alphabet_struct * alphabet)
{
  // alphabet and alphabet size
  if (!str_allocCpy (&(alphabet->alphabet), DEFAULT_ALPHABET))
  {
    printf ("Error: Out of Memory\n");
    exit (1);
  }
  (alphabet->sizeOf_alphabet) = DEFAULT_ALPHABET_SIZE;  // +1
}                               // struct_allocateDefaults_alphabet

// === nGrams functions ===

// initializes given nGramStruct
void struct_nGrams_initialize (nGram_struct ** nGrams)
{
  *nGrams = (nGram_struct *) malloc (sizeof (nGram_struct));
  EXIT_IF_NULL ((*nGrams));
  // set pointer to NULL and int to 0
  (*nGrams)->cP = NULL;
  (*nGrams)->iP = NULL;
  (*nGrams)->eP = NULL;
  (*nGrams)->len = NULL;
  (*nGrams)->sizeOf_cP = 0;
  (*nGrams)->sizeOf_iP = 0;
  (*nGrams)->sizeOf_len = 0;
  (*nGrams)->sizeOf_N = 0;
}                               // struct_initialize_nGrams

// frees given nGramStruct
void struct_nGrams_free (nGram_struct ** nGrams)
{
  if ((*nGrams) != NULL)
  {
    CHECKED_FREE ((*nGrams)->cP);
    CHECKED_FREE ((*nGrams)->iP);
    CHECKED_FREE ((*nGrams)->eP);
    CHECKED_FREE ((*nGrams)->len);
    free (*nGrams);
    (*nGrams) = NULL;
  }
}                               // struct_free_nGrams

/* (intern function) set the sizes based on the given alphabet size */
void set_sizesOf_nGrams (nGram_struct * nGrams, int sizeOf_alphabet)
{
  // init sizes
  (nGrams->sizeOf_iP) = 1;
  (nGrams->sizeOf_cP) = 1;
  (nGrams->sizeOf_len) = MAX_PASSWORD_LENGTH;

  // set sizes
  for (int i = 0; i < (nGrams->sizeOf_N) - 1; i++)
  {
    (nGrams->sizeOf_cP) *= sizeOf_alphabet;
    (nGrams->sizeOf_iP) *= sizeOf_alphabet;
  }
  (nGrams->sizeOf_cP) *= sizeOf_alphabet;

  (nGrams->sizeOf_eP) = (nGrams->sizeOf_iP);
}                               // (intern) set_sizesOf_nGrams

// allocates nGrams based on alphabetStruct and sizeOf_N
void struct_nGrams_allocate (nGram_struct * nGrams, alphabet_struct * alphabet)
{
  // if sizeOf_N is 0, set it to the default value
  if (nGrams->sizeOf_N == 0)
  {
    nGrams->sizeOf_N = 4;
  }

  // set the sizes
  set_sizesOf_nGrams (nGrams, alphabet->sizeOf_alphabet);

  // allocate (or reallocate) memory for nGram, initalProb, endProb and length arrays
  (nGrams->cP) = (int *) realloc ((nGrams->cP), sizeof (int) * (nGrams->sizeOf_cP));
  (nGrams->iP) = (int *) realloc ((nGrams->iP), sizeof (int) * (nGrams->sizeOf_iP));
  (nGrams->eP) = (int *) realloc ((nGrams->eP), sizeof (int) * (nGrams->sizeOf_eP));
  (nGrams->len) = (int *) realloc ((nGrams->len), sizeof (int) * (nGrams->sizeOf_len));

  // check allocation
  if ((nGrams->cP) == NULL || (nGrams->iP) == NULL || (nGrams->eP) == NULL || (nGrams->len) == NULL)
  {
    printf ("Error: Out of Memory\n");
    exit (1);
  }
}                               // struct_allocate_nGrams_createNG

// copy nGrams in src to dest
void struct_nGrams_copyArrays (nGram_struct * dest, nGram_struct * src)
{
  // copy int values
  (dest->sizeOf_N) = (src->sizeOf_N);
  (dest->sizeOf_cP) = (src->sizeOf_cP);
  (dest->sizeOf_iP) = (src->sizeOf_iP);
  (dest->sizeOf_eP) = (src->sizeOf_eP);
  (dest->sizeOf_len) = (src->sizeOf_len);

  // allocate memory and check allocation
  (dest->cP) = (int *) realloc ((dest->cP), sizeof (int) * (src->sizeOf_cP));
  (dest->iP) = (int *) realloc ((dest->iP), sizeof (int) * (src->sizeOf_iP));
  (dest->eP) = (int *) realloc ((dest->eP), sizeof (int) * (src->sizeOf_eP));
  (dest->len) = (int *) realloc ((dest->len), sizeof (int) * (src->sizeOf_len));
  if ((dest->cP) == NULL || (dest->iP) == NULL || (dest->eP) == NULL || (dest->len) == NULL)
  {
    printf ("Error: Out of Memory\n");
    exit (1);
  }
  // copy content
  memcpy ((dest->cP), (src->cP), sizeof (int) * (src->sizeOf_cP));
  memcpy ((dest->iP), (src->iP), sizeof (int) * (src->sizeOf_iP));
  memcpy ((dest->eP), (src->eP), sizeof (int) * (src->sizeOf_eP));
  memcpy ((dest->len), (src->len), sizeof (int) * (src->sizeOf_len));
}                               // struct_copy_nGrams_enumNG

// === sortedLastGram functions ===

// initializes given sortedLastGramStruct
void struct_sortedLastGram_initialize (int maxLevel, sortedLastGram_struct ** sortedLastGram, int sizeOf_N, int sizeOf_alphabet, int indexMax_default)
{
  // calculate sizeOf_mGram
  int sizeOf_lastGram = 1;

  for (int i = 0; i < sizeOf_N - 1; i++)
    sizeOf_lastGram *= sizeOf_alphabet;
  (*sortedLastGram) = (sortedLastGram_struct *) malloc (sizeof (sortedLastGram_struct) * maxLevel);
  EXIT_IF_NULL ((*sortedLastGram)) for (int i = 0; i < maxLevel; i++)
  {
    ((*sortedLastGram)[i].lastGrams) = NULL;
    ((*sortedLastGram)[i].indexCur) = NULL;
    ((*sortedLastGram)[i].indexMax) = NULL;
    ((*sortedLastGram)[i].lastGrams) = (int **) realloc (((*sortedLastGram)[i].lastGrams), sizeof (int *) * sizeOf_lastGram);
    ((*sortedLastGram)[i].indexCur) = (int *) realloc (((*sortedLastGram)[i].indexCur), sizeof (int) * sizeOf_lastGram);
    ((*sortedLastGram)[i].indexMax) = (int *) realloc (((*sortedLastGram)[i].indexMax), sizeof (int) * sizeOf_lastGram);
    if ((*sortedLastGram)[i].lastGrams == NULL || (*sortedLastGram)[i].indexCur == NULL || (*sortedLastGram)[i].indexMax == NULL)
    {
      printf ("Error: Out of Memory\n");
      exit (1);
    }
    (*sortedLastGram)[i].sizeOf_mGram = sizeOf_lastGram;
    for (int j = 0; j < sizeOf_lastGram; j++)
    {
      ((*sortedLastGram)[i].lastGrams)[j] = NULL;
      ((*sortedLastGram)[i].lastGrams)[j] = (int *) realloc (((*sortedLastGram)[i].lastGrams)[j], sizeof (int) * indexMax_default);
      ((*sortedLastGram)[i].indexCur)[j] = 0;
      ((*sortedLastGram)[i].indexMax)[j] = indexMax_default;
      // check reallocation
      EXIT_IF_NULL (((*sortedLastGram)[i].lastGrams)[j]) memset (((*sortedLastGram)[i].lastGrams)[j], 0, sizeof (int) * indexMax_default);
    }
  }
}                               // struct_initialize_sortedLastGram

// frees given sortedLastGramStruct
void struct_sortedLastGram_free (int maxLevel, sortedLastGram_struct ** sortedLastGram)
{
  if ((*sortedLastGram) != NULL)
  {
    for (int i = 0; i < maxLevel; i++)
    {
      if ((*sortedLastGram)[i].lastGrams != NULL)
      {
        for (int j = 0; j < (*sortedLastGram)[i].sizeOf_mGram; j++)
        {
          CHECKED_FREE (((*sortedLastGram)[i].lastGrams)[j]);
        }

        CHECKED_FREE (((*sortedLastGram)[i].indexCur));
        CHECKED_FREE (((*sortedLastGram)[i].indexMax));
        CHECKED_FREE (((*sortedLastGram)[i].lastGrams));
      }
    }
    CHECKED_FREE ((*sortedLastGram));
  }
}                               // struct_free_sortedLastGram

// fills the sortedLastGramStruct based on source
void struct_sortedLastGram_fill (int maxLevel, sortedLastGram_struct * sortedLastGram, int *source, int source_size, int sizeOf_N, int sizeOf_alphabet)
{
  // int k = 0;
  int level = 0;
  int position_mGram = 0;
  int position_lastGram = 0;
  int index = 0;
  int nGramAsInt[sizeOf_N];

  for (int i = 0; i < source_size; i++)
  {
    // get current level (at positive i)
    level = source[i];
    if (level > maxLevel - 1)
      level = maxLevel - 1;
    // get the nGram as int from the current position
    get_nGramAsIntFromPosition (nGramAsInt, i, sizeOf_N, sizeOf_alphabet);
    // the lastGram position equals the last char of nGram
    position_lastGram = nGramAsInt[sizeOf_N - 1];
    // get the position of the prior chars (all but the lastGram, the so called mGram)
    get_positionFromNGramAsInt (&position_mGram, nGramAsInt, sizeOf_N - 1, sizeOf_alphabet);

    // get current index for the mGram and add the lastGram
    index = (sortedLastGram[level]).indexCur[position_mGram];
    (sortedLastGram[level]).lastGrams[position_mGram][index] = position_lastGram;
    // increase current index and check, if a reallocation must be done
    (sortedLastGram[level]).indexCur[position_mGram]++;
    if ((sortedLastGram[level]).indexCur[position_mGram] == (sortedLastGram[level]).indexMax[position_mGram])
    {
      // k++;
      // double maximal index and reallocate
      (sortedLastGram[level]).indexMax[position_mGram] *= 2;
      (sortedLastGram[level]).lastGrams[position_mGram] = (int *) realloc ((sortedLastGram[level]).lastGrams[position_mGram], (sortedLastGram[level]).indexMax[position_mGram] * sizeof (int));
      // check allocation
      EXIT_IF_NULL ((sortedLastGram[level]).lastGrams[position_mGram]);
    }
  }
}                               // struct_fill_sortedLastGram

// === sorted iP functions ===

// initializes given sortedIPStruct
void struct_sortedIP_initialize (int maxLevel, sortedIP_struct ** sortedIP, int indexMax_default)
{
  (*sortedIP) = (sortedIP_struct *) malloc (sizeof (sortedIP_struct) * maxLevel);
  EXIT_IF_NULL ((*sortedIP));
  for (int i = 0; i < maxLevel; i++)
  {
    ((*sortedIP)[i].iP) = NULL;
    ((*sortedIP)[i].indexCur) = 0;
    ((*sortedIP)[i].indexMax) = indexMax_default;
    ((*sortedIP)[i].iP) = (int *) realloc (((*sortedIP)[i].iP), sizeof (int *) * indexMax_default);
    EXIT_IF_NULL (((*sortedIP)[i].iP));
    memset (((*sortedIP)[i].iP), 0, sizeof (int) * indexMax_default);
  }
}                               // struct_initialize_sortedIP

// frees given sortedIPStruct
void struct_sortedIP_free (int maxLevel, sortedIP_struct ** sortedIPStruct)
{
  if ((*sortedIPStruct) != NULL)
  {
    for (int i = 0; i < maxLevel; i++)
    {
      CHECKED_FREE ((*sortedIPStruct)[i].iP);
    }
    free ((*sortedIPStruct));
    (*sortedIPStruct) = NULL;
  }
}                               // struct_free_sortedIP

// fills the sortedIPStruct based on source
void struct_sortedIP_fill (int maxLevel, sortedIP_struct * sortedIP, int *source, int source_size)
{
  int level = 0;
  int index = 0;

  for (int i = 0; i < source_size; i++)
  {
    // get current level (at positive i)
    level = source[i];
    if (level > maxLevel - 1)
      level = maxLevel - 1;
    // safe current index (to increase readability)
    index = sortedIP[level].indexCur;
    // the current iP as int equals i
    sortedIP[level].iP[index] = i;
    // increase the index
    sortedIP[level].indexCur++;
    // if the index equals the maximum -> reallocate
    if (sortedIP[level].indexCur == sortedIP[level].indexMax)
    {
      sortedIP[level].indexMax *= 2;
      sortedIP[level].iP = (int *) realloc ((sortedIP[level].iP), sizeof (int) * sortedIP[level].indexMax);
      EXIT_IF_NULL (sortedIP[level].iP);
    }
  }
}                               // struct_fill_sortedIP

// === sorted length ===

// initializes given sortedLenghtStruct
void struct_sortedLength_initialize (sortedLength_struct ** sortedLength)
{
  (*sortedLength) = (sortedLength_struct *) malloc (sizeof (sortedLength_struct));
  EXIT_IF_NULL ((*sortedLength));
  (*sortedLength)->lengthMin = 0;
}                               // struct_initialize_sortedLength

// frees given sortedLenghtStruct
void struct_sortedLength_free (sortedLength_struct ** sortedLength)
{
  CHECKED_FREE ((*sortedLength));
}                               // struct_free_sortedLength

// fills the sortedLenghtStruct based on source, ignoring all lengthes < lengthMin
void struct_sortedLength_fill (sortedLength_struct * sortedLength, int *source, int lengthMin, float levelModifier, int levelSet)
{
  // set minimum length
  sortedLength->lengthMin = lengthMin;

  // copy needed length values (all > lengthMin)
  for (int i = 0; i < MAX_PASSWORD_LENGTH - lengthMin; i++)
  {
    // if level should be set to given value (ignoring computed level)
    if (levelSet != -1)
    {
      // set level (apply length scheduling)...
      sortedLength->level[i] = levelSet + (char) ((i + lengthMin) * levelModifier);
      // and that the according length
      sortedLength->length[i] = i + lengthMin;
    }
    else
    {
      // set level (apply length scheduling)...
      sortedLength->level[i] = source[i + lengthMin] + (char) ((i + lengthMin) * levelModifier);
      // and that the according length
      sortedLength->length[i] = i + lengthMin;
    }
  }

  // sort by level
  // TODO could need some optimization!
  int tmp;

  for (int i = 0; i < MAX_PASSWORD_LENGTH - lengthMin; i++)
    for (int j = i; j < MAX_PASSWORD_LENGTH - lengthMin; j++)
    {
      if (sortedLength->level[i] > sortedLength->level[j])
      {
        tmp = sortedLength->level[i];
        sortedLength->level[i] = sortedLength->level[j];
        sortedLength->level[j] = tmp;

        tmp = sortedLength->length[i];
        sortedLength->length[i] = sortedLength->length[j];
        sortedLength->length[j] = tmp;
      }
      else if (sortedLength->level[i] == sortedLength->level[j])
      {
        if (sortedLength->length[i] > sortedLength->length[j])
        {
          tmp = sortedLength->length[i];
          sortedLength->length[i] = sortedLength->length[j];
          sortedLength->length[j] = tmp;
        }
      }
    }
}                               // struct_fill_sortedLength

// returns max index for given level
int struct_sortedLength_getMaxIndexForLevel (sortedLength_struct * sortedLength, int level)
{
  static int index = 0;

  // this works since it begins at the static field @index
  // and therefore always checks the next possible lengths
  for (int i = index; i < MAX_PASSWORD_LENGTH - sortedLength->lengthMin; i++)
  {
    // if the level of the length at i is smaller or equal level...
    if (sortedLength->level[i] <= level)
      index++;                  // ...increase index
    else
      return index;             // ... return level
  }
  return index;
}                               // struct_getMaxIndexForLevel
