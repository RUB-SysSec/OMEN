OMEN: Ordered Markov ENumerator
================================

OMEN is a Markov model-based password guesser written in C. It generates password candidates according to their occurrence probabilities, i.e., it outputs most likely passwords first. OMEN significantly improves guessing speed over existing proposals.
If you are interested in the details on how OMEN improves on existing Markov model-based password guessing approaches, please refer to [OMEN: Faster Password Guessing Using an Ordered Markov Enumerator](https://hal.archives-ouvertes.fr/hal-01112124/file/omen.pdf).

User Guide
-----------

OMEN consists of two separate program modules: `createNG` and `enumNG`. `createNG`
calculates n-gram probabilities based on a given list of passwords and stores them
on the hard disk. Based on these probabilities `enumNG` enumerates new
passwords in the correct order (descending).

### Installation

Use a recent Linux version make sure you have installed `git` (Git version control system), `gcc` (GNU Compiler Collection), and `make` (GNU Make). You can install it under Ubuntu Linux via:

`$ sudo apt-get install build-essential git`

Check out the source code via:

`$ git clone https://github.com/RUB-SysSec/OMEN.git OMEN`

Change into the newly created directory `OMEN` and run:

`$ make`

If compilation is successful, you can find `createNG` and `enumNG` within the current directory.

```
.
├── alphabetCreator
├── createNG
├── docs
│   ├── CHANGELOG.md
│   ├── LICENSE
│   └── screenshots
├── enumNG
├── evalPW
├── makefile
├── README.md
└── src
    ├── alphabetCreator.c
    ...
```

If you like, you can now remove the `src` folder and the `makefile` file, they are no longer used.

### Basic Usage

Before one can generate any passwords, the n-gram probabilities have to be estimated using
`createNG`. To calculate the probabilities using the default settings, `createNG` must be
called giving a path to a password list that should be trained:

`$ ./createNG --iPwdList password-training-list.txt`

Each password of the given list must be in a new line. The module then
reads and evaluates the list generating a couple of files. Besides a config file (`createConfig`) storing the used settings (in this case the default setting), several files are created containing information about the grams and the password length. These files have the extension '`.level`':

* **IP.level** (Initial Probability): Stores the probabilities of the first
(n-1)-gram of each password.
* **CP.level** (Conditional Probability): Stores the probabilities of the actual
n-grams.
* **EP.level** (End Probability): Stores the probabilities of the last (n-1)-gram
of each password.
* **LN.level** (Length): Stores the probabilities for the password length.

The probabilities of each n-gram and the lengths are mapped to levels between 0
(most likely) and 10 (least likely). Once those files are created, `enumNG` can
be used to generate a list of passwords ordered by probabilities. Currently, `enumNG` supports three modes of operation: *file*, *stdout*, *simulated plaintext attack*. In the default mode of `enumNG`, a list of password guesses based on these levels is created. Using the command

`$ ./enumNG`

generates 1 billion passwords and **stores them in a text file**, which can be found
in the '*results*' folder. The passwords in this file are ordered by level (i.e., by
probability). Since common text editors are not able to handle such huge files,
it is recommended for testing to reduce the number of passwords created. This
can be done using the argument `-m`.

`$ ./enumNG -m 10000`

It will create an ordered list with 10,000 passwords only. If you are interested in printing the passwords to the **standard output (stdout) stream** use the argument `-p`.

`$ ./enumNG -p -m 10000`

If you are interested in evaluating the guessing performance against a *plaintext* password test set use the argument `-s`. Please note: In this mode OMEN benefits from the adaptive length scheduling algorithm incorporating live feedback, which is not available (due to the missing feedback channel) in *file* and *stdout* mode.

`$ ./enumNG -s=password-testing-list.txt -m 10000`

The result of this evaluation can be found in the '*results*' folder.

Both modules provide a help dialog which can be shown using the `-h` or `--help` argument.

### Password Cracking

How to get from `$2a$10$HNYF4KajSTqxIP/KoiB5tOCVeKUgvscTh32hhAmppFk4T/USmI2B.` to `"GoodOMEN!123"`?

#### Ethics
OMEN was developed for [academic use cases](https://password-guessing.org) like [improving probabilistic password modeling](https://hal.archives-ouvertes.fr/hal-01112124/file/omen.pdf), [estimating guess numbers](https://github.com/RUB-SysSec/Password-Guessing-Framework) or [password strength](https://www.internetsociety.org/sites/default/files/06_3.pdf), in general, to improve password security. Do not abuse this software to harm other people's privacy or to break the law.

#### Preimage Attacks
Popular hash evaluators like [Hashcat](https://github.com/hashcat/hashcat) and [John the Ripper](https://github.com/magnumripper/JohnTheRipper) support hundreds of
hash and cipher formats and could be easily integrated due to their support to
read password candidates via their standard input (stdin) stream.

`$ ./enumNG -p -m 10000 | ./hashcat64.bin  ...`

or

`$ ./enumNG -p -m 10000 | ./john --stdin ...`

For optimal guessing performance, consider to train `createNG` with a password distribution that is similar to the one you like to crack.

Please note: Using probabilistic password modeling to crack passwords, in general, should only be considered against slow hashes (e.g., [bcrypt](https://en.wikipedia.org/wiki/Bcrypt), [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2), [scrypt](https://en.wikipedia.org/wiki/Scrypt), or [Argon2](https://en.wikipedia.org/wiki/Argon2)) were the number of feasible guesses is limited or in very targeted attacks. In contrast, for very fast hashes ([MD5](https://en.wikipedia.org/wiki/MD5), [SHA-1](https://en.wikipedia.org/wiki/SHA-1), or [NTLM](https://en.wikipedia.org/wiki/NT_LAN_Manager)), using [good dictionaries](https://weakpass.com) and mangling rules (e.g., best64.rule) are the way to go.

If you are interested in this topic, consider to read the following papers and their related work (this list is incomplete, you can help by expanding it):

**Probabilistic Context-Free Grammars**
* Password Cracking Using Probabilistic Context-Free Grammars (SP '09)
* Guess Again (and Again and Again): Measuring Password Strength by Simulating Password-Cracking Algorithms (SP '12)
* On the Semantic Patterns of Passwords and their Security Impact (NDSS '14)
* Next Gen PCFG Password Cracking (TIFS '15)
* ...
* [Software A](https://github.com/lakiw/pcfg_cracker), [Software B](https://sites.google.com/site/reusablesec/Home/password-cracking-tools/probablistic_cracker)

**Markov Models**
* Fast Dictionary Attacks on Passwords Using Time-Space Tradeoff (CCS '05)
* OMEN+: When Privacy meets Security: Leveraging personal information for password cracking (CoRR '13)
* A Study of Probabilistic Password Models (SP '14)
* OMEN: Faster Password Guessing Using an Ordered Markov Enumerator (ESSoS '15)
* ...
* [Software A](http://openwall.info/wiki/john/markov), [Software B](https://github.com/RUB-SysSec/OMEN)

**Neural Networks**
* Fast, Lean, and Accurate: Modeling Password Guessability Using Neural Networks (USENIX '16)
* Using Neural Networks for Password Cracking (Blog post by Sebastian Neef '16)
* Design and Evaluation of a Data-Driven Password Meter (CHI '17)
* ...
* [Software A](https://github.com/gehaxelt/RNN-Passwords), [Software B](https://github.com/cupslab/neural_network_cracking)

**Hybrids**
* John the Ripper '*Incremental*' Mode
* Introducing the PRINCE Attack-Mode (PASSWORDS '14)
* ...
* [Software A](http://www.openwall.com/john/doc/MODES.shtml), [Software B](https://github.com/hashcat/princeprocessor)

**Approach Comparison**
* Measuring Real-World Accuracies and Biases in Modeling Password Guessability (USENIX '15)
* A Framework for Comparing Password Guessing Strategies (PASSWORDS '15)
* PARS: A Uniform and Open-source Password Analysis and Research System (ACSAC '15)
* ...
* [Software A](https://password-guessing.org), [Software B](https://pgs.ece.cmu.edu)

### Advanced Usage

Both modules provide several command line arguments to select the various
modes available and change the default settings. For instance, the probability
distribution created during the `createNG` process may be manipulated by
choosing one of the supported smoothing functions, the n-gram size, or the used
alphabet. All available parameters for `createNG`, a short description, and the default values can be seen by calling the program with `-h` or `--help`. The same works for `enumNG` where for instance, the enumeration mode, the used length scheduling algorithm (only used in `-s` mode, see '*Basic Usage*' section), and the maximum amount of attempts can be selected. If no enumeration mode is given, the
default mode is executed, storing all created passwords in a text file in the
'*results*' folder.

OMEN+
-----

OMEN+ is based on [When Privacy Meets Security: Leveraging Personal Information for Password Cracking](https://arxiv.org/pdf/1304.6584.pdf)
and is an additional feature of OMEN (implemented in the same binary). Using additional personal information about a user (e.g., a password hint or personal background information scraped from a social network) may help in speeding up the password guessing process (comparable to John the Ripper '*Single crack*' mode).


Therefore, a related hint or several hints (tabulator separated) must be provided in a separate file. Furthermore, an alpha file is required containing the respective
alpha values (tab separated in one line). Alpha values are used to weight the impact of the provided hints. Important is that for each hint in a
line an alpha has to be specified in the alpha file. These alphas have to be in
the same order as the hints per line.

Exemplary, we want to guess the password "*Mary'sPW2305*". The
corresponding line in the hint file containing *first name*, *username*, *date of
birth*, and *email address* looks like the following:

```
mary   mary1   19880523    mary1@yahoo.com
```

An alpha file should order the related alpha values for *first name*, *username*,
*date of birth*, and *email address* in the same order as in the hint file. In
example:

```
1   2   1   2
```

For the usage of OMEN+ `enumNG` must be called giving a path to a hint and an
alpha file:

`$ ./enumNG -H hint-file.txt -a alpha-file.txt`

Performance
-----------
![OMEN](/docs/screenshots/performance.png?raw=true "OMEN")



Smoothing Configuration
-----------------------

The smoothing function is selected and configured using a configuration file (`createConfig`).
The file must contain the name of the smoothing function and may contain the
values for any variable parameters. The file should be formatted like this:

```
<name>
-<parameter>_<target> <value>
...
```

At this time, the only supported smoothing functions are **none** or **additive** smoothing.

The allowed parameters (`<parameter>`) are:
* **levelAdjust** (level adjustment factor, heavily influence performance, i.e., good are 100-250)
* **delta** (additive smoothing adds a value δ (delta) to each n-gram, i.e., 0,1,2, ...)

The allowed targets (`<target>`) are:
* **IP** (Initial Probability)
* **CP** (Conditional Probability)
* **EP** (End Probability)
* **all** (Parameter is used for all possible targets)

Notice, one value for a single target overwrites the one set for all.

An exemplary for the **add1(250)** (Additive Smoothing (δ=1), Level Adjustment Factor of 250) smoothing setting:
```
additive
-delta_all 1
-delta_LN 0
-levelAdjust_all 250
-levelAdjust_CP 2
-levelAdjust_LN 1
```

Additional Program Modules
--------------------------

Besides the two main modules `createNG` and `enumNG`, OMEN provides two other
program modules: `evalPW` and `alphabetCreator`. `evalPW` evaluates a given
password and `alphabetCreator` creates an alphabet with the most frequent
character in a given password list. Both modules should be considered experimental.

#### evalPW

It reads a given password and evaluates its strength by returning a password-level. The result is based on the levels generated by `createNG`. The password-level is the sum of each
occurring n-gram level, based on the level lists IP, CP, and EP. The current
implementation of `evalPW` is only a prototype and does not support the whole
possible functionality and contains **lots of bugs**. For example, the actual password length does not influence the password-level. Therefore, only passwords with the same length can
be compared to each other.

`$ ./evalPW --pw=demo123`

#### alphabetCreator

If you want to limit OMEN to passwords complying to a given alphabet you can specify this in the configuration file (`createConfig`). To determine the most promising alphabet, the `alphabetCreator` might be able to help you. The program module creates a new alphabet based on a given password list. The **characters of the new alphabet are ordered by their frequency in the password list**, beginning with the highest frequency. The length of the alphabet is variable. The created alphabet is based on the 8-bit ASCII table
according to ISO 8859-1 (not allowing ’\n’, ’\r’, ’\t’, and ’ ’ (space)).
Characters that are not part of this table are ignored. Also, an existing
alphabet may be extended with the most frequent characters.

```
# Create an empty alphabet file
$ touch empty-alphabet-file

# Based on frequency statistics of training file (password-training-list.txt), and given (in this case, empty) alphabet file (empty-alphabet-file), we generate the new alphabet (new-alphabet-file.alphabet)
$ ./alphabetCreator --pwList password-training-list.txt --size 95 --alphabet empty-alphabet-file --output new-alphabet-file

# Optional: Cleanup and verification
$ rm empty-alphabet-file
$ cat new-alphabet-file.alphabet
ae1ionrls20tm39c8dy54hu6b7kgpjvfwzAxEIOLRNSTMqCDB.YH!U_PKGJ-*VF@WZ#/X$,&+Q?\)=(';%<]~[:^`">{}|

# Now you can train OMEN using the newly generated alphabet
$ ./createNG --iPwdList password-training-list.txt -A new-alphabet-file.alphabet -v

# Optional: Verification
$ ./enumNG -p -m 1000 > top1k.txt
$ grep password top1k.txt
password```

FAQ
---

* Very poor performance and strange looking passwords?
Make sure you generated the alphabet file with the `alphabetCreator`. Manually generating the alphabet is not supported (see [Issue#4](https://github.com/RUB-SysSec/OMEN/issues/4)).

License
-------

The **Ordered Markov ENumerator (OMEN)** is licensed under the MIT license. Refer to [docs/LICENSE](docs/LICENSE) for more information.

### Third-Party Libraries
* **getopt** is part of the GNU C Library (glibc) and used to parse command
line arguments. The developer, the license, and the source code can be downloaded
[here](http://www.gnu.org/software/libc/).
* **uthash** is a hash table for C structures developed by Troy D. Hanson. The
source code and the license can be downloaded [here](http://troydhanson.github.com/uthash/).

Contact
-------
Visit our [website](https://www.mobsec.rub.de) and follow us on [Twitter](https://twitter.com/hgi_bochum). If you are interested in passwords, consider to contribute and to attend the [International Conference on Passwords (PASSWORDS)](https://passwordscon.org).
