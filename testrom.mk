include $(K)/config.mk

CFLAGS+=-ggdb

CPPFLAGS+=-I $(K)/k/include \
	  -I $(K)/libs/libc/include \
	  -I $(K)/libs/libk/include \

LDFLAGS+=-Wl,-T,$(K)/roms/roms.lds

LDLIBS+=-L $(K)/libs/libk -lk \
	-L $(K)/libs/libc -lc \

LIBS=$(K)/libs/libk/libk.a $(K)/libs/libc/libc.a

BIN=testrom

all: $(BIN)

clean:
	$(RM) $(BIN)

$(BIN): $(LIBS)

$(LIBS):
	make -C $(dir $@) $(notdir $@)

.PHONY: $(LIBS) all clean
