flags="-Wall -Werror -pedantic -Wextra -std=c17 -fsanitize=address"
program_name="cfger"
gcc $flags cfger.c -o $program_name -lZydis &&\
./$program_name
#valgrind --leak-check=full --show-leak-kinds=all ./$program_name
