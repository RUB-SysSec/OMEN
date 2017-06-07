CFLAGS = -std=gnu11 -O3 -Wall -Wpedantic -g -flto
LDFLAGS = -g -lm -flto
VERSION = 0.3.1

all: createNG enumNG evalPW alphabetCreator clean-o

src/cmdlineCreateNG.c: src/cmdlineCreateNG.c.in
	sed s/cmdlineCreateNG.h.in/cmdlineCreateNG.h/g src/cmdlineCreateNG.c.in > src/cmdlineCreateNG.c

src/cmdlineCreateNG.h: src/cmdlineCreateNG.h.in
	sed s/__VERSION__/$(VERSION)/g src/cmdlineCreateNG.h.in > src/cmdlineCreateNG.h

src/cmdlineEnumNG.c: src/cmdlineEnumNG.c.in
	sed s/cmdlineEnumNG.h.in/cmdlineEnumNG.h/g src/cmdlineEnumNG.c.in > src/cmdlineEnumNG.c

src/cmdlineEnumNG.h: src/cmdlineEnumNG.h.in
	sed s/__VERSION__/$(VERSION)/g src/cmdlineEnumNG.h.in > src/cmdlineEnumNG.h

src/cmdlineEvalPW.c: src/cmdlineEvalPW.c.in
	sed s/cmdlineEvalPW.h.in/cmdlineEvalPW.h/g src/cmdlineEvalPW.c.in > src/cmdlineEvalPW.c

src/cmdlineEvalPW.h: src/cmdlineEvalPW.h.in
	sed s/__VERSION__/$(VERSION)/g src/cmdlineEvalPW.h.in > src/cmdlineEvalPW.h

src/cmdlineAlphabetCreator.c: src/cmdlineAlphabetCreator.c.in
	sed s/cmdlineAlphabetCreator.h.in/cmdlineAlphabetCreator.h/g src/cmdlineAlphabetCreator.c.in > src/cmdlineAlphabetCreator.c

src/cmdlineAlphabetCreator.h: src/cmdlineAlphabetCreator.h.in
	sed s/__VERSION__/$(VERSION)/g src/cmdlineAlphabetCreator.h.in > src/cmdlineAlphabetCreator.h

%.o: src/%.c
	$(CC) -Wall $(CFLAGS) -c $< -o $@

createNG: src/cmdlineCreateNG.h cmdlineCreateNG.o createNG.o src/common.h src/errorHandler.h src/smoothing.h src/commonStructs.h common.o errorHandler.o smoothing.o commonStructs.o
	$(CC) -o $@ createNG.o common.o errorHandler.o smoothing.o cmdlineCreateNG.o commonStructs.o $(LDFLAGS)

enumNG: src/cmdlineEnumNG.h cmdlineEnumNG.o enumNG.o src/common.h src/errorHandler.h src/boosting.h src/smoothing.h src/commonStructs.h src/nGramReader.h src/attackSimulator.h common.o errorHandler.o boosting.o smoothing.o commonStructs.o nGramReader.o attackSimulator.o
	$(CC) -o $@ enumNG.o common.o errorHandler.o boosting.o smoothing.o cmdlineEnumNG.o commonStructs.o nGramReader.o attackSimulator.o $(LDFLAGS)

evalPW: src/cmdlineEvalPW.h cmdlineEvalPW.o evalPW.o src/common.h src/errorHandler.h src/smoothing.h src/commonStructs.h src/nGramReader.h common.o errorHandler.o smoothing.o commonStructs.o nGramReader.o
	$(CC) -o $@ evalPW.o common.o errorHandler.o smoothing.o cmdlineEvalPW.o commonStructs.o nGramReader.o $(LDFLAGS)

alphabetCreator: src/cmdlineAlphabetCreator.h cmdlineAlphabetCreator.o alphabetCreator.o src/common.h src/errorHandler.h common.o errorHandler.o
	$(CC) -o $@ alphabetCreator.o common.o errorHandler.o cmdlineAlphabetCreator.o $(LDFLAGS)

clean:
	$(RM) -r src/cmdlineCreateNG.c src/cmdlineCreateNG.h src/cmdlineEnumNG.c src/cmdlineEnumNG.h src/cmdlineEvalPW.c src/cmdlineAlphabetCreator.c

clean-o:
	$(RM) *.o

phony: clean clean-o
