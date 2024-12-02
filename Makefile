.PHONY:     			all $(NAME) clear mkbuild clean fclean re

NAME					= ft_nmap

BUILD_DIR				= build/

HEADER_DIR				= include/
HEADER_FILE				= ft_nmap.h

DIR						= src/
SRC			 			= main.c \
							parsing/parsing.c \
							parsing/check/check_file.c \
							parsing/check/check_ip.c \
							parsing/check/check_ports.c \
							parsing/check/check_scan.c \
							parsing/check/check_speedup.c \
							scan/scanTCP.c \
							scan/utils.c \
							scan/print.c \
							scan/packetHandler.c \
							scan/build.c \
							scan/send.c \
							thread/thread.c \
							utils/signal.c \
							utils/free.c \

OBJECTS			    	= $(SRC:%.c=$(BUILD_DIR)%.o)
	
GCC						= gcc
CFLAGS					= -Wall -Wextra -Werror
SANITIZE				= $(CFLAGS) -g3 -fsanitize=address

RM 						= rm -rf
CLEAR					= clear


$(BUILD_DIR)%.o: 		$(DIR)%.c $(HEADER_DIR)/$(HEADER_FILE)
						@mkdir -p $(dir $@)
						$(GCC) $(CFLAGS) -I$(HEADER_DIR) -o $@ -c $<


all: 					clear mkbuild $(HEADER_DIR) $(NAME)

						 
mkbuild:
						@mkdir -p build


clear:
						$(CLEAR)
						
$(NAME): 				$(OBJECTS)
						@$(GCC) $(OBJECTS) -o $(NAME) -lpcap
						@echo "$(GREEN)[✓] $(NAME) created !$(DEFAULT)"
						
clean:					
						@${RM} $(OBJECTS)
						@${RM} $(BUILD_DIR)
						@echo "$(YELLOW)[-] object files deleted !$(DEFAULT)"

fclean:					clean
						@${RM} ${NAME}
						@echo "$(RED)[x] all deleted !$(DEFAULT)"

re:						fclean all
						$(MAKE) all

RED = \033[1;31m
GREEN = \033[1;32m
YELLOW = \033[1;33m
DEFAULT = \033[0m