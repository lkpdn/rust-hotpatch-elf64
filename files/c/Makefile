TESTS=$(shell ls -d test*)
.PHONY: all $(TESTS)
all: $(patsubst %,all-%,$(TESTS))
clean: $(patsubst %,clean-%,$(TESTS))
all-%:
	@-make -C $*/orig
	@-make -C $*/patch
clean-%:
	@-make -C $*/orig clean
	@-make -C $*/patch clean
