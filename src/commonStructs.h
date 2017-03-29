/*
 * commonStructs.h
 * @authors: Fabian Angelstorf, Franziska Juckel
 * @copyright: Horst Goertz Institute for IT-Security, Ruhr-University Bochum
 *
 * Encapsulate the different structs used by createNG and enumNG. Provides
 * functions memory management and fills the structs based on the input. OMEN
 * uses multiple structs to encapsulate filenames and n-gram arrays.
 *
 */

#ifndef COMMONSTRUCTS_H_
#define COMMONSTRUCTS_H_

#include "defines.h"

// TODO: rewrite this in c++ (allows easier optimizations)
// === common structs ===

/*
 * Encapsulates the input or output filenames for conditionalProb,
 * initalProb, length and config.
 */
typedef struct filename_struct
{
  char *cP;                     // filename for conditionalProb
  char *iP;                     // filename for initalProb
  char *eP;                     // filename for endProb
  char *len;                    // filename for length
  char *cfg;                    // filename for config
  char *pwList;                 // filename for a password list
  char *smoo;                   // filename for smoothing function
} filename_struct;

/*
 * Encapsulates the different nGram and length arrays
 * for the counts and the level as well as the size of
 * the nGram 'n'. The data is stored as follows:
 *  - length: The array index is the passwords length and the value is the corresponding count
 *     e. g. length[5] = 100 means that there where 100 passwords with a length of 5.
 *     - nGrams: The array index represents the different n-grams and the value the
 *     count or level of this n-gram
 *     e. g. cP[ pos1 * SIZE_ALPHABET + pos2] = count (for N = 2).
 */
typedef struct nGram_struct
{
  // arrays
  int *cP;                      // conditionalProb array
  int *iP;                      // initialProb array
  int *eP;                      // endProb array
  int *len;                     // length array
  // sizes of the arrays
  int sizeOf_cP;                // size of conditionalProb array (sizeOf_alpahabet^N)
  int sizeOf_iP;                // size of initialProp array (sizeOf_alpahabet^[N-1])
  int sizeOf_eP;                // size of endProp array (sizeOf_alpahabet^[N-1])
  int sizeOf_len;               // size of length array (default: SIZE_LENGTH_FIELD)

  int sizeOf_N;                 // size of the nGram 'n' (size of iP and eP equals sizeOf_N - 1)
} nGram_struct;

/*
 * Contains the alphabet as c-string an the size of this
 * alphabet.
 */
typedef struct alphabet_struct
{
  char *alphabet;               // actual alphabet
  int sizeOf_alphabet;          // strlen(alphabet) + 1
} alphabet_struct;

/*
 * Contains a 2 dimensional array @lastGram where any last gram is sorted by
 * the leading gram (the so called mGram). Once set, the 1st dimension equals
 * the first (n-1) of a cP and the 2nd dimension increases dynamically
 * (using @indexCur and @indexMax), pointing to the n's char of this nGram.
 * The struct is used to store the lastGrams sorted by level (using an array of
 * this struct with the dimension [MAX_LEVEL]).
 */
typedef struct sortedLastGram_struct
{
  int **lastGrams;              // lastGram by mGram (with m = (n-1))

  int sizeOf_mGram;             // 1st dimension of @lastGrams (equals amount of possible mGrams)
  int *indexCur;                // 2nd dimensions of @lastGrams (current value, increases dynamically)
  int *indexMax;                // max value for 2nd dimensions of @lastGrams ( (if indexCur == indexMax) -> reallocate lastGrams[i])
} sortedLastGram_struct;

/*
 * Contains a 1 dimensional array @iP where the 1st dimension increases dynamically
 * (using @indexCur and @indexMax), containing the position of the according initialProb.
 * The struct is used to store the iPs sorted by level (using an array of
 * this struct with the dimension [MAX_LEVEL]).
 */
typedef struct sortedIP_struct
{
  int *iP;                      // initialProbs

  int indexCur;                 // current index of the last iP (increases dynamically)
  int indexMax;                 // maximal index of iP( (if indexCur == indexMax) -> reallocate iP)
} sortedIP_struct;

/*
 * Contains two 1 dimensional arrays (@level and @length), which are correlated to each other.
 * The @length at index x has the level stored in @level at index x.
 * @lengthMin stores the minimum level which equals the sizeOf_N - 1 (there can be now PW
 * smaller then this!).
 */
typedef struct sortedLength_struct
{
  int level[MAX_PASSWORD_LENGTH]; // level of length at index x
  int length[MAX_PASSWORD_LENGTH];  // length of length at index x
  int lengthMin;                // minimum length (equals sizeOf_N - 1)
} sortedLength_struct;

// === struct function ===
/*
 * The functions allocate memory for the given struct and
 * set each value to NULL.
 * If the allocation for the struct fails, this function
 * exit the application.
 */
void struct_nGrams_initialize (struct nGram_struct **arrays);

void struct_filenames_initialize (struct filename_struct **filenames);

void struct_alphabet_initialize (struct alphabet_struct **alphabet);

void struct_sortedLastGram_initialize (int maxLevel, struct sortedLastGram_struct **sortedLastGram, int sizeOf_N, // size of the nGram n
                                       int sizeOf_alphabet, // size of the used alphabet
                                       int indexMax_default); // buffer for the dynamic array

void struct_sortedIP_initialize (int maxLevel, struct sortedIP_struct **sortedIP, int indexMax_default);  // buffer for the dynamic array

void struct_sortedLength_initialize (struct sortedLength_struct **sortedLength);

/*
 * These functions allocate memory for the content of the given struct
 * setting them to the default values.
 * If the allocation for the content fails, this function
 * exit the application.
 */
void struct_filenames_allocateDefaults (struct filename_struct *filenames);

void struct_alphabet_allocateDefaults (struct alphabet_struct *alphabet);

/*
 * These functions calculate the sizes of the arrays in @nGrams based
 * on the size of the given @alphabet and allocate the needed nGram arrays.
 * The alphabet must be set before using this function!
 * If the allocation for the content fails, this function
 * exit the application.
 */
void struct_nGrams_allocate (struct nGram_struct *nGrams, struct alphabet_struct *alphabet);

/*
 * This function copies the content of the nGram_struct @src to
 * the nGram_struct @dest.
 * (dest must be initialized)
 */
void struct_nGrams_copyArrays (struct nGram_struct *dest, // destination (must be initialized)
                               struct nGram_struct *src); // source

/*
 * These functions free any memory allocated by the structs (including the struct)
 */
void struct_nGrams_free (struct nGram_struct **arrays);

void struct_filenames_free (struct filename_struct **filenamesStruct);

void struct_alphabet_free (struct alphabet_struct **alphabetStruct);

void struct_sortedLastGram_free (int maxLevel, struct sortedLastGram_struct **sortedLastGram);

void struct_sortedIP_free (int maxLevel, struct sortedIP_struct **sortedIPStruct);

void struct_sortedLength_free (struct sortedLength_struct **sortedLength);

/*
 *    Fills the @sortedLastGram struct with the positions found
 *    in @source, where @sortedLastGram[x] contains all positions with Level x.
 *    Therefore the size of @sortedLastGram must be at least MAX_LEVEL.
 */
void struct_sortedLastGram_fill (int maxLevel, struct sortedLastGram_struct *sortedLastGram,  // destination
                                 int *source, // source (unsorted nGram array)
                                 int source_size, // size of source array
                                 int sizeOf_N,  // size of the nGram n
                                 int sizeOf_alphabet);  // size of the used alphabet

/*
 *    Fills the @sortedIP struct with the positions found
 *    in @source, where @sortedIP[x] contains all positions with Level x.
 *    Therefore the size of @sortedIP must be at least MAX_LEVEL.
 */
void struct_sortedIP_fill (int maxLevel, struct sortedIP_struct *sortedIP,  // destination
                           int *source, // source (unsorted iP array)
                           int source_size);  // size of source array

/*
 * Sorts the given length array @source, storing it in the @sortedLength struct.
 * The minimum level equals sizeOf_N - 1 (because there can be now PW shorter than that).
 * The @levelModifire works as follows: the level of each length is adjusted by the actual
 * length value multiplied with the @levelModifire. E.g: if length 8 has level 1 and the
 * @levelModifire is 2, the adjusted level for length 8 would be 17 (1 + 8 * 2).
 * The levelModifire is applied before the sort takes place. If the length shouldn't
 * influence the level at all, set @levelModifire to 0.
 */
void struct_sortedLength_fill (struct sortedLength_struct *sortedLength,  // destination
                               int *source, // source (unsorted length array)
                               int lengthMin, // minimum length (should equal sizeOf_N - 1)
                               float levelModifire, // this value defines how much the actual length modified the level of each length
                               int levelSet); // if != -1, set all level to this value before applying the levelModifire

/*
 * This functions returns the index of the first item stored in @sortedLength
 * with a level larger then @level. The lengths stored in @sortedLength must be sorted
 * by level before calling this function (using struct_fill_sortedLength).
 * The returned index isn't reseted, there for this functions returns the same index
 * again (or 0, since @index is initialized with 0) if the level stored in
 * @sortedLength->level[index] is larger then @level.
 */
int struct_sortedLength_getMaxIndexForLevel (struct sortedLength_struct *sortedLength,  // target array
                                             int level);  // level

#endif /* COMMONSTRUCTS_H_ */
