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

SOURCES := src/pestilence.asm
OBJECTS := $(SOURCES:.asm=.o)
HEADERS := include/pestilence.inc

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(LD) -o $@ $^

%.o: %.asm
	$(AS) $(ASFLAGS) $< -o $@

clean:
	@rm -vf $(OBJECTS)

fclean: clean
	@rm -vf $(TARGET)

re: fclean all

.PHONY: all clean fclean re