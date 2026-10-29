/*
 * closefds: run a command with no descriptor above stderr.
 *
 * jail_attach(2) refuses a process holding an open directory, and a
 * shell or editor may pass some on; jexec(8) in the root cases then
 * fails with EPERM.
 */

#include <err.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	if (argc < 2)
		errx(2, "usage: closefds command [argument ...]");
	closefrom(STDERR_FILENO + 1);
	execvp(argv[1], argv + 1);
	err(127, "%s", argv[1]);
}
