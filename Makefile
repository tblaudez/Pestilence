# **************************************************************************** #
#                                                                              #
#                                                         ::::::::             #
#    Makefile                                           :+:    :+:             #
#                                                      +:+                     #
#    By: tblaudez <tblaudez@student.codam.nl>         +#+                      #
#                                                    +#+                       #
#    Created: 2021/03/31 15:06:14 by tblaudez      #+#    #+#                  #
#    Updated: 2021/05/12 10:06:26 by tblaudez      ########   odam.nl          #
#                                                                              #
# **************************************************************************** #

TARGET := Pestilence

AS := nasm
ASFLAGS ?= -felf64 -I include/
LDFLAGS ?= -nostdlib -pie

SOURCES := $(shell find src/ -type f -name '*.asm')
OBJECTS := $(SOURCES:.asm=.o)
HEADERS := include/famine.inc

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.asm
	$(AS) $(ASFLAGS) $< -o $@

clean:
	@rm -vf $(OBJECTS)

fclean: clean
	@rm -vf $(TARGET)

re: fclean all

.PHONY: all clean fclean re