/**
 * Operating Systems 2013-2017 - Assignment 2
 *
 * Cristi Nica, 336CA
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 *Function used to redirect. When it's finished the new stdin / stdout
 * /stderror will be the one represented by file_name. Flags are used to know
 *how we should open the output file or the error file (APPEND or TRUNC).
 */
void redirect(int stream, char *file_name, int flags, char *verb)
{
	int fd;

	/*If we have to redirect standard input*/
	if (stream == STDIN_FILENO)
		fd = open(file_name, O_RDONLY);
	/*If we have to redirect stdout or stderror*/
	if (stream == STDERR_FILENO || stream == STDOUT_FILENO) {
		if (flags == IO_OUT_APPEND || flags == IO_ERR_APPEND)
			fd =
		open(file_name, O_WRONLY | O_CREAT | O_APPEND, 0644);
		else
			fd =
		open(file_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	}
	if (!strcmp(verb, "cd") == 0)
		dup2(fd, stream);
	close(fd);

}

/*
 *Function used to check what and how we should redirect and send parameters
 *to redirect function. We know what we have to redirect from in, out and err
 *members of simple_command_t. Using flags from simple_command_t will show us
 *how to opend the output / error file.
 */

void redict_helper(simple_command_t *s)
{
	word_t *input, *output, *error;
	int flags;
	char *input_file, *output_file, *error_file;
	char *verb;

	input = s->in;
	output = s->out;
	error = s->err;

	verb = get_word(s->verb);
	flags = s->io_flags;
	/*If we have to redirect stdin*/
	if (input != NULL) {
		input_file = get_word(input);
		redirect(STDIN_FILENO, input_file, flags, verb);
		free(input_file);
	}

	/*If we have to redirect stdout or stderror	*/
	if (output != NULL && error == NULL) {
		output_file = get_word(output);
		redirect(STDOUT_FILENO, output_file, flags, verb);
		free(output_file);
	} else if (output == NULL && error != NULL) {
		error_file = get_word(error);
		redirect(STDERR_FILENO, error_file, flags, verb);
		free(error_file);
	} else if (output != NULL && error != NULL) {
		output_file = get_word(output);
		error_file = get_word(error);
		if (strcmp(output_file, error_file) == 0) {
			redirect(STDERR_FILENO, error_file, flags, verb);
			redirect
			(STDOUT_FILENO, output_file, IO_OUT_APPEND, verb);
		} else {
			redirect(STDERR_FILENO, error_file, flags, verb);
			redirect(STDOUT_FILENO, output_file, flags, verb);
		}
		free(error_file);
		free(output_file);
	}
	free(verb);
}

/**
 * Internal change-directory command. New path is represented by dir
 */
static bool shell_cd(word_t *dir)
{
	char *path;
	int exit_code = 0;

	if (dir == NULL || dir->string == NULL || strlen(dir->string) == 0) {
		/* Stay in the same directory */
		exit_code = -1;
	} else {
		path = get_word(dir);
		exit_code =  chdir(path);
		if (exit_code == -1)
			fprintf(stderr, "Erorr\n");
		free(path);
		}
	return exit_code;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	return SHELL_EXIT;
}

/*
 *Function used for variable assignment. If we have to expand
 *an existing variable we should use getenv function to take its old value.
 *Final set is done using setenv function
 */

static int env_var_shell(simple_command_t *s)
{
	const char *var_name = s->verb->string;
	const char *var_value;
	char *aux_var;

	if (s->verb->next_part->next_part->next_part != NULL) {

		if (s->verb->next_part->next_part->expand == true) {
			aux_var = getenv(s->verb->next_part->next_part->string);
			const char *aux =
			s->verb->next_part->next_part->next_part->string;

			var_value = strcat(aux_var, aux);
		}
	} else {
		if (s->verb->next_part->next_part->expand == false)
			var_value = s->verb->next_part->next_part->string;
		else
			var_value =
			getenv(s->verb->next_part->next_part->string);
	}

	return setenv(var_name, var_value, 1);
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	char *verb;
	pid_t child_pid;
	int exit_code = 0;
	int status;
	int size;

	/*sanity checks */
	if (s == NULL)
		exit(-1);

	verb = get_word(s->verb);

	/*if builtin command, execute the command */;
	if (strcmp(verb, "exit") == 0 || strcmp(verb, "quit") == 0) {
		free(verb);
		return shell_exit();
	}

	if (strcmp(verb, "cd") == 0) {
		free(verb);
		redict_helper(s);
		return shell_cd(s->params);
	}
	/*
	 *if variable assignment, execute the assignment and return
	 *the exit status
	 */
	if (s->verb->next_part != NULL &&
		strcmp(s->verb->next_part->string, "=") == 0) {
		free(verb);
		exit_code = env_var_shell(s);
	} else {

		/*if external command:
		 *   1. fork new process
		 *     2c. perform redirections in child
		 *     3c. load executable in child
		 *   2. wait for child
		 *   3. return exit status
		 */

		child_pid = fork();
		if (child_pid == -1) {
			free(verb);
			DIE(child_pid == 1, "Fork error.");
		} else if (child_pid == 0) {
			free(verb);
			redict_helper(s);
			execvp(get_word(s->verb), get_argv(s, &size));
			fprintf(stderr, "Execution failed for '%s'\n", s->verb->string);
			exit(-1);

		} else {
			waitpid(child_pid, &status, 0);

			if (WIFEXITED(status))
				exit_code = WEXITSTATUS(status);
			else
				exit_code = -1;
			free(verb);
		}
	}
	return exit_code;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/*execute cmd1 and cmd2 simultaneously */
	pid_t child1, child2;
	int exit_code = 0;
	int status1, status2;

	child1 = fork();
	if (child1 == -1) {
		DIE(child1 == 1, "Fork error.");
	} else if (child1 == 0) {
		exit_code = parse_command(cmd1, level + 1, father);
		exit(EXIT_FAILURE);
	} else {
		child2 = fork();

		if (child2 == -1) {
			DIE(child2 == 1, "Fork error.");
		} else if (child2 == 0) {
			exit_code = parse_command(cmd2, level + 1, father);
			exit(EXIT_FAILURE);
		} else {
			waitpid(child1, &status1, 0);
			waitpid(child2, &status2, 0);

			if (WIFEXITED(status1) && WIFEXITED(status2))
				exit_code = WEXITSTATUS(status1);
			else
				exit_code = -1;
		}
	}

	return exit_code;
}

/**
 *Run commands by creating an anonymous pipe (cmd1 | cmd2). I have to save
 *the initial stdin and stdout and come back to them at the end of the
 *function, when pipe operation is done.
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/*redirect the output of cmd1 to the input of cmd2 */
	int exit_code = 0;
	int initial_in, initial_out;
	pid_t child;
	int pipe_fd[2];
	int status;

	initial_in = dup(STDIN_FILENO);
	initial_out = dup(STDOUT_FILENO);
	pipe(pipe_fd);

	child = fork();
	if (child == -1) {
		DIE(child == 1, "Fork error.");
	} else if (child == 0) {

		close(pipe_fd[0]);
		dup2(pipe_fd[1], STDOUT_FILENO);
		close(pipe_fd[1]);
		exit_code = parse_command(cmd1, level + 1, cmd1);
		DIE(1, "Error.");

		} else {

			close(pipe_fd[1]);
			dup2(pipe_fd[0], STDIN_FILENO);
			exit_code = parse_command(cmd2, level + 1, cmd2);
			waitpid(child, &status, 0);

			dup2(initial_in, STDIN_FILENO);
			dup2(initial_out, STDOUT_FILENO);

			close(pipe_fd[0]);
			close(initial_in);
			close(initial_out);

		}

	return exit_code;
}

/**
 *Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/*sanity checks */
	if (c == NULL)
		exit(-1);
	int exit_code = 0;

	if (c->op == OP_NONE) {
		/*execute a simple command */
		return parse_simple(c->scmd, level + 1, father);
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/*execute the commands one after the other */
		parse_command(c->cmd1, level + 1, c);
		parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PARALLEL:
		/*execute the commands simultaneously */
		exit_code = do_in_parallel(c->cmd1, c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_NZERO:
		/*execute the second command only if the first one
		 *returns non zero
		 */
		exit_code = parse_command(c->cmd1, level + 1, c);
		if (exit_code != 0)
			exit_code = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_ZERO:
		/*execute the second command only if the first one
		 *returns zero
		 */
		exit_code = parse_command(c->cmd1, level + 1, c);
		if (exit_code == 0)
			exit_code = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PIPE:
		/*redirect the output of the first command to the
		 *input of the second
		 */
		exit_code = do_on_pipe(c->cmd1, c->cmd2, level + 1, c);
		break;

	default:
		return SHELL_EXIT;
	}

	return exit_code;
}
