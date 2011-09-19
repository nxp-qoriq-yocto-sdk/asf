/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asf_tool.c
 *
 * Description: Contains ASF configuration application code.
 * *
 * Authors:	Sachin Saxena <b32168@freescale.com>
 */
/* History
 *  Version	Date		Author		Change Description
*/
/******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <limits.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <asftoolkit.h>

/* Invocation and parameter functions */
static int cvt_afx_ctrl(char *t, enum_afx_ctrl_t *p);
static int param_help(char *t, int n);
static int help();
static int invoke_stdin();
static int invoke_shell();
static int param_filename(char *t, int n);
static int invoke_newfile();
static int invoke_quit();
static int param_sleep(char *t, int n);
static int invoke_sleep();
static int invoke_wait();
static int param_set_var(char *t, int n);
static int set_var();
static char *get_var_value(char *var);
static int unset_var();
static int param_unset_var(char *t, int n);
static int print_vars();
static int echo();
static int param_verbose(char *t, int n);
static int param_onerror(char *t, int n);

static int ASF_verbose();
static int param_asf_verbose(char *t, int n);
static int ASF_open();
static int ASF_close();
static int ASF_enable();
static int param_disable(char *t, int n);
static int ASF_disable();

static int param_asf_write_lan_pause(char *t, int n);
static int param_lan_pause(char *t, int n);
static int ASF_write_lan_pause();
static int param_asf_write_lan_vlan(char *t, int n);
static int param_lan_vlan(char *t, int n);
static int ASF_write_lan_vlan();
static int param_asf_write_lan_afx(char *t, int n);
static int param_lan_afx(char *t, int n);
static int ASF_write_lan_afx();
static int param_asf_write_lan_filer(char *t, int n);
static int param_lan_ftr(char *t, int n);
static int ASF_write_lan_filer();
static int param_asf_write_lan_parse_depth(char *t, int n);
static int ASF_write_lan_parse_depth();
static int param_asf_write_lan_padcrc(char *t, int n);
static int ASF_write_lan_padcrc();
static int param_asf_read_lan_filer(char *t, int n);
static int ASF_read_lan_filer();

/* forget functions*/
static void init_lan_afx();
static void init_lan_vlan();
static void init_lan_pause();

static int param_forget(char *t, int n);
static int forget_params();
static void forget_lan_afx();
static void forget_lan_ftr();
static void forget_lan_vlan();
static void forget_lan_pause();

/* miscellaneous functions*/
static int name_to_cmd(char *name);
static int process_file(char *fp);
static char *get_token(FILE *fp, char *token, int *linecount);
static int partial_name_to_cmd(char *t);

/* conversion functions*/
static int cvt_boole(char *t, BOOLE *p);
static int cvt_reaction(char *t, BOOLE *p);
/*
static int cvt_sint32(char *t, s32 *p);
static int cvt_device(char *t, enum_dev_t *p);
*/
static int cvt_uint32(char *t, ASF_uint32_t *p);
static int cvt_uint16(char *t, ASF_uint16_t *p);
static int cvt_uint8(char *t, ASF_uint8_t *p);
static int cvt_ft_pid(char *t, enum_ft_pid_t *p);
static int cvt_ft_cmp(char *t, enum_ft_cmp_t *p);


const struct ct {
	char	*name;
	int	num_params;
	int	(*pfunc)(char *, int);	/* param save function --
					   parameter token and number*/
	int	(*ifunc)(FILE *ifp);	/* invoke function*/
	void	(*ffunc)();		/* param forget function*/
	char	*help;
} cmdtbl[] = {
	{ "",					0,	NULL,				NULL,					NULL,
	  "\
Scripts are formed from three types of commands, Data, Invocation, and Miscellaneous.\n\
Comments and blank lines are allowed. Comments are introduced by a '#' and may\n\
appear anywhere within a command and its parameters. Everything after the starting of\n\
the comment until the end of the line is ignored.\n\
\n\
Parameters are shown as <param> and valid values for the parameters are shown\n\
For interpretation of the parameter values refer to the SoC API Reference Manual.\n\
\n\
\n\
Miscellaneous Commands\n\
	 These commands are for script control and user convenience" },
	{ "help",					1,	param_help,			help,					NULL,
	"<cmd>\n\
	Displays help for one or all commands. <cmd> identifies the desired command.\n \
		A <cmd> of 'all' or '*', will result in help for all commands." },
	{ "quit",					0,	NULL,				invoke_quit,				NULL,
	  "\n\
	Quit or exit from the utility. This exits from all levels of input from files or stdin." },
	{ "q",					0,	NULL,				invoke_quit,				NULL,
	  "\n\
	Quit or exit from the utility. This exits from all levels of input from files or stdin." },
	{ "file",					1,	  param_filename,			invoke_newfile,				NULL,
	  "<filename>\n\
	Diverts script input from the current source (file, stdin, or shell)\n\
	to the named file. When end-of-file is reached input reverts to the\n\
	previous source." },
	{ "stdin",					0,	  NULL,				invoke_stdin,				NULL,
	  "\n\
	Diverts script input from the current source (file, stdin or shell)\n\
	to stdin until an EOF (^D) is entered." },
	{ "<",					0,	  NULL,				invoke_stdin,				NULL,
	  "\n\
	Diverts script input from the current source (file, stdin or shell)\n\
	to stdin until an EOF (^D) is entered." },
	{ "shell",					1,	  NULL,				invoke_shell,				NULL,
	  "!!not implemented!! will allow input from an invoked process." },
	{ "!",					1,	  NULL,				invoke_shell,				NULL,
	  "!!not implemented!! will allow execution of command." },
	{ "sleep",					1,	param_sleep,			invoke_sleep,				NULL,
	  "<seconds>" },
	{ "wait",					0,	NULL,				invoke_wait,				NULL,
	  "\n\
	Prompts and waits for user action." },
	{ "set",					2,	param_set_var,			set_var,				NULL,
	  "<var> <value>\n\
	Sets a the variable <var> to the value <value>.\n\
	The values is stored as a string and conversion\n\
	occurs when the variable is used." },
	{ "unset",					1,	param_unset_var,		unset_var,				NULL,
	  "<var>\n\
	Removes variable <var> from the current list of variables." },
	{ "vars",					0,	NULL,				print_vars,				NULL,
	  "\n\
	Show all variables" },
	{ "echo",					0,	  NULL,				echo,					NULL,
	  "<output>\n\
	All text after the command is output to stdout until a newline is reached." },
	{ "verbose",				1,	  param_verbose,			NULL,					NULL,
	  "<enable>\n\
	enable ::= true | t | 1 | yes | y | false | f | 0 | no | n\n\
	When enabled shows executed commands." },
	{ "onerror",				1,	  param_onerror,			NULL,					NULL,
	  "<reaction>\n\
	reaction ::= stop | halt | s | h | continue | cont | c | go | g\n\
	Set the rection to errors encountered in the script.\n\
	Default is to stop, unless input is stdin." },
	{ "",					0,	NULL,				NULL,					NULL,
	  "\n\n\
Invocation Commands\n\
	The commands invoke a call to a correspondingly named API function.\n\
	Parameters are shown as <param> and data used by the command is indicated\n\
	by the list of Data Commands after the '<<'. These are automatically \n\
	provided to the Invocation Command and need not be indicated with the\n\
	Invocation Command" },
	{ "asf_verbose",				1,	  param_asf_verbose,		ASF_verbose,				NULL,
	  "<verboseness>\n\
	verboseness ::= number, unsigned 32 bits\n\
					enables selective debug printing in API,\n\
					0 disables all." },
	{ "asf_open",				0,	  NULL,				NULL,				NULL,
	  "" },
	{ "asf_close",				0,	  NULL,				NULL,				NULL,
	  "" },
	{ "asf_write_lan_pause",			1,	  param_asf_write_lan_pause,	ASF_write_lan_pause,			NULL,
	  "<lan> << lan_pause\n\
	lan ::= 0 | 1 | 2" },
	{ "asf_write_lan_vlan",			1,	  param_asf_write_lan_vlan,	ASF_write_lan_vlan,			NULL,
	  "<lan> << lan_vlan\n\
	lan ::= 0 | 1 | 2" },
	{ "asf_write_lan_afx",			1,	  param_asf_write_lan_afx,	ASF_write_lan_afx,			NULL,
	  "<lan> << lan_afx\n\
	lan ::= 0 | 1 | 2" },
	{ "asf_write_lan_filer",			1,	  param_asf_write_lan_filer,	ASF_write_lan_filer,			NULL,
	  "<lan> << lan_ftr\n\
	lan ::= 0 | 1 | 2" },
	{ "asf_write_lan_parse_depth",		2,	  param_asf_write_lan_parse_depth, ASF_write_lan_parse_depth,		NULL,
	  "<lan> <depth>\n\
	lan   ::= 0 | 1 | 2\n\
	depth ::= 2 | 3 | 4" },
	{ "asf_write_lan_padcrc",			3,	  param_asf_write_lan_padcrc,	 ASF_write_lan_padcrc,			NULL,
	  "<lan> <padcrc> <crc>\n\
	lan	::= 0 | 1 | 2\n\
	padcrc ::= true | t | 1 | yes | y | false | f | 0 | no | n\n\
	crc	::= true | t | 1 | yes | y | false | f | 0 | no | n" },
	{ "asf_read_lan_filer",			1,	 param_asf_read_lan_filer,	 ASF_read_lan_filer,			NULL,
	  "<lan>\n\
	lan	::= 0 | 1 | 2" },
	{ "asf_enable",				0,	  NULL,				ASF_enable,				NULL,
	  "" },
	{ "asf_disable",				2,	  param_disable,			ASF_disable,				NULL,
	  " <timeout> <force>\n\
	timeout ::= number\n\
	force   ::= true | t | 1 | yes | y | false | f | 0 | no | n" },
	{ "",					0,	NULL,				NULL,					NULL,
	  "\n\n\
Data Commands\n\
	These commands gather information to be used in subsequent Invocation Commands" },
	{ "lan_afx",				4,	  param_lan_afx,			NULL,					forget_lan_afx,
	  "<lan> <field> <control> <offset>\n\
	lan	 ::= 0 | 1 | 2\n\
	field   ::= number 0-3\n\
	control ::= none | frame | l3hdr | l4hdr\n\
	offset  ::= number" },
	{ "lan_ftr",				9,	  param_lan_ftr,			NULL,					forget_lan_ftr,
	  "<lan> <rule> <queue> <cluster> <reject> <and> <cmp> <pid> <prop_val>\n\
	lan	  ::= 0 | 1 | 2\n\
	rule	 ::= number, 0-255\n\
	queue	::= number, 0-63\n\
	cluster  ::= true | t | 1 | yes | y | false | f | 0 | no | n\n\
	reject   ::= true | t | 1 | yes | y | false | f | 0 | no | n\n\
	and	  ::= true | t | 1 | yes | y | false | f | 0 | no | n\n\
	cmp	  ::= always_match | am | always_fail | af |\n\
				 equal | == | greater_equal | >= |\n\
				 not_equal | != | less | <\n\
	pid	  ::= mask | misc | arb | dah | dal | sah | sal |\n\
				  ety | vid  | pri | tos | l4p | dia | sia |\n\
				  dpt | spt\n\
	prop_val ::= number" },
	{ "lan_vlan",				5,	  param_lan_vlan,		NULL,					forget_lan_vlan,
	  "<lan> <extract> <insert> <def_vtpi> <def_vlctl>\n\
	lan	   ::= 0 | 1 | 2\n\
	extract   ::= true | t | 1 | yes | y | false | f | 0 | no | n\n\
	insert	::= true | t | 1 | yes | y | false | f | 0 | no | n\n\
	def_vtpi  ::= number, 16 bits (0 ==> 0x8100)\n\
	def_vlctl ::= number, 16 bits (priority, cfi, vlan_id)" },
	{ "lan_pause",				6,	  param_lan_pause,		NULL,					forget_lan_pause,
	  "<lan> <tx_pause> <rx_pause> <rx_pause_value> <rx_threshold> <rx_shutoff>\n\
	lan		  ::= 0 | 1 | 2\n\
	tx_pause	 ::= true | t | 1 | yes | y | false | f | 0 | no | n\n\
	rx_pause	 ::= true | t | 1 | yes | y | false | f | 0 | no | n\n\
	rx_pause_value ::= number, 16 bits, 0 = no change\n\
	rx_threshold ::= number, 8 bits, 0 = no change\n\
	rx_shutoff   ::= number, 8 bits, 0 = no change" },
	{ "forget",				1,	param_forget,			forget_params,				NULL,
	  "<data_cmd_name>\n\
	data_cmd_name ::= any data command except 'forget'" },
	{ NULL,					0,	NULL,				NULL,					NULL,
	  "" }
};


/* parameter storage*/
static ASF_uint32_t		api_verbosity;
static char		*new_filename;
static char		*help_for_cmd;
static ASF_uint16_t		sleep_time;
static char		*var_name;
static char		*var_value;
typedef struct var {
	struct var *next;
	char	*name;
	char	*value;
} var_t;
var_t			*var_head; /* head of variable list*/
static char		*forget_what;
static ASF_uint8_t	cur_pause_lan;
static BOOLE		lan_pause_valid[3];
static lan_pause_t	lan_pause[3];
static ASF_uint8_t	cur_vlan_lan;
static BOOLE		lan_vlan_valid[3];
static lan_vlan_t	lan_vlan[3];
static ASF_uint8_t	cur_afx_lan;
static ASF_uint8_t	cur_lan_afx_field;
static filer_afx_t	lan_afx[3][AFX_NUM_FIELDS];
static ASF_uint8_t	cur_filer_lan;
static ASF_uint16_t	num_lan_rules[3] = {0, 0, 0};
static lan_ftr_t	lan_filer_rule[3][LAN_NUM_FILER_RULES];
static ASF_uint8_t	cur_parse_depth_lan;
static enum_lpd_t	lan_parse_depth[3] = {
				LPD_LAYER_4, LPD_LAYER_4, LPD_LAYER_4};
static ASF_uint8_t	cur_padcrc_lan;
static BOOLE		lan_padcrc[3] = {TRUE, TRUE, TRUE};
static BOOLE		lan_crc[3] = {TRUE, TRUE, TRUE};
static ASF_uint8_t	disable_timeout;
static BOOLE		disable_force;

/* globals*/
static BOOLE	verbose = FALSE;
static BOOLE	trial_mode = FALSE;
static BOOLE	stop_on_error = TRUE;
#define NULL_ERROR_INDEX	0xFFFFFFFF
static ASF_uint32_t	error_index = NULL_ERROR_INDEX; /* which means not set*/
static char	*asf_config_err;

BOOLE	termios_configured = FALSE;
struct termios saved_termios;
struct termios new_termios;

void sig_exit(int u)
{
	invoke_quit();
}

int main(int argc, char **argv)
{
	int			opt;
	char		*filename;
	int			err;

	opterr = 0;

	while ((opt = getopt(argc, argv, "vhtea:")) != EOF) {
		switch (opt) {
		case 'v':
			verbose = TRUE;
			break;

		case 't':
			trial_mode = TRUE;
			break;

		case 'e':
			stop_on_error = FALSE;
			break;

		case 'a':
			if (cvt_uint32(optarg, &api_verbosity) < 0) {
				fprintf(stderr, "Unable to convert -a value\n:");
				exit(1);
			}
			asf_verbose(api_verbosity);
			break;

		case 'h':
			help_for_cmd = "*";
			help();
			return 0;

		default:
			fprintf(stderr, "Invalid option: %c\n", argv[optind-1][1]);
usage:
			fprintf(stderr, "Usage: %s [-h] [-v] [-t] [-e] [-a <verbosity>] <config_file>\n\
		  -h   help, prints help for all commands\n\
		  -v   verbose mode, shows executed commands\n\
		  -e   do NOT stop on errors\n\
		  -a   enables verbose mode in the SoC API library with the level of <verbosity>\n\
		  -t   trial mode, process the scripts but does not call API functions\n\
", argv[0]);
			exit(1);
			break;
		}
	}

	if (optind == argc)
		filename = "";
	else if (optind > argc)
		goto usage;
	else
		filename = argv[optind];

#ifndef GPON_RUN_ON_X86
	if (trial_mode == FALSE) {
		if (getuid() != 0) {
			printf("you must be root\n");
			exit(0);
		}
	}
#endif

	/* initialize arrays of data*/
	init_lan_afx();
	init_lan_vlan();
	init_lan_pause();

	/* register signal handlers to gracefully die upon interrupt */
	signal(SIGHUP, sig_exit);
	signal(SIGINT, sig_exit);
	signal(SIGQUIT, sig_exit);

	ASF_open();
	err = process_file(filename);
	if (err != 0)
		exit(3);

	ASF_close();
	exit(0);
}

static int process_file(char *filename)
{
	FILE		*fp = NULL;
	char		token[1024];
	char		*t;
	int			line_count = 1;
	int			err;
	int			state = 0;  /* 0 for command, 1 for parameter*/
	int			cmd = 0;
	int			i = 0;
	int			num_params = 0;
	int			cur_param = 0;
	char		*ename;
	char		*edescr;

	/* open the file (or stdin)*/
	if ((*filename) == '\0') {
		if (termios_configured == FALSE) {
			if (tcgetattr(fileno(stdin), &saved_termios) == 0) {
				new_termios = saved_termios;
				new_termios.c_cc[VERASE] = '\b';
				new_termios.c_lflag |= IEXTEN;
				if (tcsetattr(fileno(stdin), TCSANOW, &new_termios) == 0)
					termios_configured = TRUE;
			}
		}
		fp = stdin;
		printf("? ");
		fflush(stdin);
	} else {
		fp = fopen(filename, "r");
		if (NULL == fp) {
			fprintf(stderr, "process_file: Unable to open file '%s'.\n", filename);
			asf_config_err = "Unable to open file.";
			return -1;
		}
	}


	while ((t = get_token(fp, token, &line_count)) != NULL) {
		if (state == 0) {/* command token*/
			if (verbose)
				printf("[[ %s", t);

		if (strcmp(t, "echo") == 0)
			line_count++; /* because echo throws one away*/

		cmd = name_to_cmd(t);
		if (cmd < 0) {
			if (fp == stdin) {
				/* show them the first that matches what they gave*/
				i = partial_name_to_cmd(t);
				if (i >= 0) {
					printf("%s ", cmdtbl[i].name);
					fflush(stdout);
					/* if its the only partial match, use it*/
					cmd = partial_name_to_cmd(NULL);
					if (cmd < 0) {
						cmd = i;
						goto got_command;
					}
					printf("\n");
					i = cmd;
					/* now show all others that match what they gave*/
					do
						printf("%s\n", cmdtbl[i].name);
					while ((i = partial_name_to_cmd(NULL)) >= 0);

					/* print the prompt and continue with a new try at the command*/
					printf("? ");
					fflush(stdout);
					continue; /* the while get_token*/
				}
			}

			if (fp == stdin) {
				fprintf(stderr, "Unrecognized command '%s'\n", t);
				printf("? ");
				fflush(stdin);
				continue;
			} else {
				fprintf(stderr, "process_file: Unrecognized command '%s' on line %d of file %s\n",
							t, line_count, filename);
				(void)fclose(fp);
				return -1;
			}
		}
got_command:
		num_params = cmdtbl[cmd].num_params;
		cur_param = 0;
		state = 1;
		} else { /* parameter token*/
			if (verbose)
				printf(" %s\n", t);

			/* gather tokens until we have all parameters for that command*/
			if (cmdtbl[cmd].pfunc(t, cur_param+1) < 0) {
				if (fp != stdin) {
					fprintf(stderr, "process_file: Parameter (%d) '%s', error on line %d of file %s\n",
								cur_param+1, t, line_count, filename);
					(void)fclose(fp);
					return -1; /* error*/
				}

				fprintf(stderr, "Parameter (# %d) '%s', error\n", cur_param+1, t);
				printf("%s %s\n", cmdtbl[cmd].name, (cmdtbl[cmd].help ? cmdtbl[cmd].help : ""));
				printf("Try again, starting with parameter %d: ", cur_param+1);
				fflush(stdout);
				continue; /* while gettoken*/
			}
		cur_param++;
		}
		if (cur_param >= num_params) {/* we have all parameters for the previous command*/
			if (verbose)
				printf(" ]]\n");

			if (cmdtbl[cmd].ifunc != NULL) { /* is it an invocation command*/
				error_index = NULL_ERROR_INDEX;
				err = cmdtbl[cmd].ifunc(fp);
			if (err != 0) {
				if (err > 0) {/* err from an API function*/
					ename = asf_error_name(err, &edescr);
					if (fp != stdin) {
						fprintf(stderr, "process_file: %s - command error '%s', errno=%d %s:%s, on line %d of file %s\n",
							filename, cmdtbl[cmd].name, errno, ename, edescr, line_count, filename);
						if (error_index != NULL_ERROR_INDEX)
							fprintf(stderr, "\terror_index = %u\n", error_index);
					} else {
						printf("Command error '%s', errno=%d %s:%s", cmdtbl[cmd].name, errno, ename, edescr);
						if (error_index != NULL_ERROR_INDEX)
							printf("  error_index = %u\n", error_index);
						else
							printf("\n");
					}
				} else {/* err from an asf_config invocation function (not from called API function).*/
					if (fp != stdin) {
						fprintf(stderr, "process_file: %s - command error '%s', error= '%s', on line %d of file '%s'\n",
									filename, cmdtbl[cmd].name, asf_config_err, line_count, filename);
					} else {
						printf("Command error '%s', error = '%s'\n", cmdtbl[cmd].name, asf_config_err);
					}
				}
				if (fp != stdin && stop_on_error == TRUE) {
					asf_config_err = "Error within processed file";
					(void)fclose(fp);
					return -1;
				}
			}
			}
			state = 0; /* back to command state*/
			if (fp == stdin) {
				printf("? ");
				fflush(stdout);
			}
		}
	} /* End of While Loop */

	if (fp != stdin)
		(void)fclose(fp);

	return 0;
}

/**/
/* Obtains one token from the input. A token is any set of non-whitespace characters*/
/* Comments, introduced with '#' are discarded until a newline or EOF is encoutered.*/
/**/
/**/
char *get_token(FILE *fp, char *token, int *line_count)
{
	char	*t = token;
	int		c;
	int		state = 0; /* 0 = between tokens, 1 = in a token 2 = in a comment*/
	char	*val;

	while (1) {
		c = fgetc(fp);

		if (c == '\n')
			(*line_count)++;

		switch (state) {
		case 0: /* between tokens (whitespace)*/
			if (isspace(c))
				continue;
			else if (c == '#') { /* start a comment*/
				state = 2;
				continue;
			} else if (c == EOF) {
				return NULL;
			} else {/* start a token*/
				*t++ = (char) c;
				state = 1;
				continue;
			}
			break;
		case 1: /* in a token*/
			if (isspace(c) || c == '#') { /* end token, start whitespace or comment*/
				*t = '\0';
				ungetc(c, fp);
				if (c == '\n')	/* don't want to count it twice*/
					(*line_count)--;
					goto return_token;
			} else if (c == EOF) {
				*t = '\0';
				if (token[0] == '\0')
					return NULL;
				else
					goto return_token;
			} else { /* more token*/
				*t++ = (char)c;
				continue;
			}
			break;
		case 2: /* in a comment*/
			if (c == '\n') {
				state = 0;
				continue;
			} else if (c == EOF) {
				return NULL;
			} else
				continue;
			break;
		}
	}


return_token:
	/* replace a var with its value*/
	if (*token == '$') {
		val = get_var_value(token+1);
		if (val != NULL)
			strcpy(token, val);
	/* the varname with preceeding $ gets returned*/
	}

	return token;
}

static int name_to_cmd(char *t)
{
	int	i;
	for (i = 0; cmdtbl[i].name; i++)
		if (strcmp(t, cmdtbl[i].name) == 0)
			return i;

	return -1;
}
static int partial_name_to_cmd(char *t)
{
	static char *nm;
	static int	i;

	if (t != NULL) { /* first search with this string*/
		nm = t;
		i = 0;
	}

	for ( ; cmdtbl[i].name; i++) {
		if (strncmp(nm, cmdtbl[i].name, strlen(nm)) == 0) {
			i++; /* so we find the next one when called again*/
			return i-1;
		}
	}

	return -1;
}

static int param_help(char *t, int n)
{
	switch (n) {
	case 1: /* var*/
		help_for_cmd = t;
		while (*t != '\0') {
			*t = (char)tolower(*t);
			t++;
		}
		break;
	default:
		return -1;
	}
	return 0;
}

static int help()
{
	/* find the command and print out its help*/
	int i;

	if (strcmp(help_for_cmd, "all") == 0 || strcmp(help_for_cmd, "*") == 0) {
		for (i = 0; cmdtbl[i].name; i++)
			printf("%s %s\n\n", cmdtbl[i].name, (cmdtbl[i].help ? cmdtbl[i].help : ""));
		return 0;
	} else {
		i = name_to_cmd(help_for_cmd);
		if (i < 0) {
			/* no exact match, find the first that matches what
			   they asked for*/
			i = partial_name_to_cmd(help_for_cmd);
			if (i < 0) {
				printf("%s - not recognized as a command\n", help_for_cmd);
				return 0;
			}
			printf("%s %s\n", cmdtbl[i].name, (cmdtbl[i].help ? cmdtbl[i].help : ""));
			/* now find all others that match what they asked for*/
			while ((i = partial_name_to_cmd(NULL)) >= 0)
				printf("%s %s\n", cmdtbl[i].name, (cmdtbl[i].help ? cmdtbl[i].help : ""));
		} else
			printf("%s %s\n", cmdtbl[i].name, (cmdtbl[i].help ? cmdtbl[i].help : ""));
	}
	return 0;
}
static int param_filename(char *t, int n)
{
	switch (n) {
	case 1: /* var*/
		new_filename = t;
		break;
	default:
		return -1;
	}
	return 0;
}
static int invoke_newfile()
{
	return process_file(new_filename);
}
static int invoke_quit()
{
	if (termios_configured)
		tcsetattr(fileno(stdin), TCSANOW, &saved_termios);

	exit(0);
}

static int invoke_stdin()
{
	return process_file("");
}
static int invoke_shell()
{
	printf("shell command not yet implemented\n");
	return -1;
}
static int param_sleep(char *t, int n)
{
	switch (n) {
	case 1: /* var*/
		if (cvt_uint16(t, &sleep_time) < 0)
			return -1;
		break;
	default:
		return -1;
	}
	return 0;
}
static int invoke_sleep()
{
	sleep(sleep_time);
	return 0;
}
static int invoke_wait()
{
	int c;
	printf("WAITING ... press Enter to continue ... ");
	fflush(stdout);
	while ((c = getc(stdin)) != EOF && c != '\n') ;

	return 0;
}
static int param_set_var(char *t, int n)
{
	switch (n) {
	case 1: /* var*/
		var_name = malloc(strlen(t)+1);
		if (!var_name) {
			printf("Malloc Error\n");
			return -1;
		}
		strcpy(var_name, t);
		break;
	case 2: /* value*/
		var_value = malloc(strlen(t)+1);
		if (!var_value) {
			printf("Malloc Error\n");
			return -1;
		}
		strcpy(var_value, t);
		break;
	default:
		return -1;
	}
	return 0;
}
static int set_var()
{
	var_t	*var;
	var_t	*nv;

	/* find var with same name*/
	var = var_head;
	while (var != NULL) {
		if (strcmp(var_name, var->name) == 0) {
			free(var->value);
			var->value = var_value;
			return 0;
		}
		var = var->next;
	}
	if (var == NULL) {/* no match, add to front of list*/
		nv = malloc(sizeof(var_t));
		if (!nv) {
			printf("Malloc Error\n");
			return -1;
		}
		nv->next = var_head;
		nv->name = var_name;
		nv->value = var_value;
		var_head = nv;
	}
	return 0;
}
static char *get_var_value(char *name)
{
	var_t	*var;

	var = var_head;
	while (var != NULL) {
		if (strcmp(var->name, name) == 0)
			return var->value;
		var = var->next;
	}
	return NULL;
}
static int param_unset_var(char *t, int n)
{
	switch (n) {
	case 1: /* var*/
		var_name = malloc(strlen(t)+1);
		if (!var_name) {
			printf("Malloc Error\n");
			return -1;
		}
		strcpy(var_name, t);
		break;
	default:
		return -1;
	}
	return 0;
}
static int unset_var()
{
	var_t	*var;
	var_t	*prev;

	var = var_head;
	prev = NULL;
	while (var != NULL) {
		if (strcmp(var->name, var_name) == 0) {
			if (prev == NULL)
				var_head = var->next;
			else
				prev->next = var->next;

			free(var->name);
			free(var->value);
			free(var);
			free(var_name);
			return 0;
		}
		prev = var;
		var = var->next;
	}
	free(var_name);
	return 0;
}

static int print_vars()
{
	var_t	*var;

	var = var_head;
	while (var != NULL) {
		printf("%s = %s\n", var->name, var->value);
		var = var->next;
	}
	return 0;
}

static int echo(FILE *fp)
{
	int c;

	/* print everything until we get to the end of the line or end of file*/
	while ((c = fgetc(fp)) != EOF) {
		putchar(c);
		if (c == '\n')
			return 0;
	}
	putchar('\n');
	return 0;
}
static int param_verbose(char *t, int n)
{
	switch (n) {
	case 1: /* enable*/
		if (cvt_boole(t, &verbose) < 0)
			return -1;
		break;
	default:
		return -1;
	}
	return 0;
}
static int param_onerror(char *t, int n)
{
	switch (n) {
	case 1: /* reaction*/
		if (cvt_reaction(t, &stop_on_error) < 0)
			return -1;
		break;
	default:
		return -1;
	}
	return 0;
}

static int param_asf_verbose(char *t, int n)
{
	switch (n) {
	case 1: /* channel*/
		if (cvt_uint32(t, &api_verbosity) < 0)
			return -1;
		break;
	default:
		return -1;
	}

	return 0;
}
int ASF_verbose()
{
	if (trial_mode)
		return 0;

	asf_verbose(api_verbosity);
	return 0;
}

static int ASF_open()
{
	if (trial_mode)
		return 0;

	return asf_open();
}

static int ASF_close()
{
	if (trial_mode)
		return 0;

	return asf_close();
}
static void init_lan_vlan()
{
	lan_vlan_valid[0] = FALSE;
	lan_vlan_valid[1] = FALSE;
}
static int param_asf_write_lan_vlan(char *t, int n)
{
	switch (n) {
	case 1: /* <lan>*/
		if (cvt_uint8(t, &cur_vlan_lan) < 0)
			return -1;
		if (cur_vlan_lan > 1)
			return -1;
		break;
	default:
		return -1;
	}
	return 0;
}

static int param_lan_vlan(char *t, int n)
{
	switch (n) {
	case 1: /* lan*/
		if (cvt_uint8(t, &cur_vlan_lan) < 0)
			return -1;
		if (cur_vlan_lan > 1)
			return -1;
		lan_vlan_valid[cur_vlan_lan] = FALSE;
		break;
	case 2: /* extract*/
		if (cvt_boole(t, &lan_vlan[cur_vlan_lan].extract) < 0)
			return -1;
		break;
	case 3: /* insert*/
		if (cvt_boole(t, &lan_vlan[cur_vlan_lan].insert) < 0)
			return -1;
		break;
	case 4: /* def_vtpi*/
		if (cvt_uint16(t, &lan_vlan[cur_vlan_lan].default_vtpi) < 0)
			return -1;
		break;
	case 5: /* def_vlctl*/
		if (cvt_uint16(t, &lan_vlan[cur_vlan_lan].default_vlctl) < 0)
			return -1;
		lan_vlan_valid[cur_vlan_lan] = TRUE;
		break;
	default:
		return -1;
	}
	return 0;
}
static int ASF_write_lan_vlan()
{
	if (trial_mode)
		return 0;

	if (!lan_vlan_valid[cur_vlan_lan]) {
		asf_config_err = "invalid (not provided) lan_vlan configuration";
		return -1;
	}

	return asf_write_lan_vlan(cur_vlan_lan, &lan_vlan[cur_vlan_lan]);

}
static void init_lan_pause()
{
	lan_pause_valid[0] = FALSE;
	lan_pause_valid[1] = FALSE;
}
static int param_lan_pause(char *t, int n)
{
	switch (n) {
	case 1: /* lan*/
		if (cvt_uint8(t, &cur_pause_lan) < 0)
			return -1;
		if (cur_pause_lan > 1)
			return -1;
		lan_pause_valid[cur_pause_lan] = FALSE;
		break;
	case 2: /* tx_pause*/
		if (cvt_boole(t, &lan_pause[cur_pause_lan].tx_pause) < 0)
			return -1;
		break;
	case 3: /* rx_pause*/
		if (cvt_boole(t, &lan_pause[cur_pause_lan].rx_pause) < 0)
			return -1;
		break;
	case 4: /* rx_pause_value*/
		if (cvt_uint16(t, &lan_pause[cur_pause_lan].rx_pause_value) < 0)
			return -1;
		break;
	case 5: /* rx_threshold*/
		if (cvt_uint8(t, &lan_pause[cur_pause_lan].rx_threshold) < 0)
			return -1;
		break;
	case 6: /* rx_shutoff*/
		if (cvt_uint8(t, &lan_pause[cur_pause_lan].rx_shutoff) < 0)
			return -1;
		lan_pause_valid[cur_pause_lan] = TRUE;
		break;
	default:
		return -1;
	}
	return 0;
}
static int param_asf_write_lan_pause(char *t, int n)
{
	switch (n) {
	case 1: /* lan*/
		if (cvt_uint8(t, &cur_pause_lan) < 0)
			return -1;
		if (cur_pause_lan > 1)
			return -1;
		break;
	default:
			return -1;
	}
	return 0;
}
static int ASF_write_lan_pause()
{
	if (trial_mode)
		return 0;

	if (!lan_pause_valid[cur_pause_lan]) {
		asf_config_err = "invalid (not provided) lan_pause configuration";
		return -1;
	}

	return asf_write_lan_pause(cur_pause_lan, &lan_pause[cur_pause_lan]);
}
static void init_lan_afx()
{
	int i;

	for (i = 0; i < AFX_NUM_FIELDS; i++) {
		lan_afx[0][i].offset = MAX_AFX_OFFSET + 1; /* to indicate configure entry*/
		lan_afx[1][i].offset = MAX_AFX_OFFSET + 1;
		lan_afx[2][i].offset = MAX_AFX_OFFSET + 1;
	}

}
static int param_asf_write_lan_afx(char *t, int n)
{
	switch (n) {
	case 1: /* <lan>*/
		if (cvt_uint8(t, &cur_afx_lan) < 0)
			return -1;
		if (cur_afx_lan > 2)
			return -1;
		break;
	case 2: /* field*/
		if (cvt_uint8(t, &cur_lan_afx_field) < 0)
			return -1;
		if (cur_lan_afx_field >= AFX_NUM_FIELDS)
			return -1;
		if (lan_afx[cur_afx_lan][cur_lan_afx_field].offset > MAX_AFX_OFFSET)
			return -1;
		break;
	default:
		return -1;
	}
	return 0;
}
static int param_lan_afx(char *t, int n)
{
	switch (n) {
	case 1: /* <lan>*/
		if (cvt_uint8(t, &cur_afx_lan) < 0)
			return -1;
		if (cur_afx_lan > 2)
			return -1;
		break;
	case 2: /* field*/
		if (cvt_uint8(t, &cur_lan_afx_field) < 0)
			return -1;
		if (cur_lan_afx_field >= AFX_NUM_FIELDS)
			return -1;
		break;
	case 3: /* control*/
		if (cvt_afx_ctrl(t, &lan_afx[cur_afx_lan][cur_lan_afx_field].control) < 0)
			return -1;
		break;
	case 4: /* offset*/
		if (cvt_uint8(t, &lan_afx[cur_afx_lan][cur_lan_afx_field].offset) < 0)
			return -1;
		break;
	default:
		return -1;
	}
	return 0;
}
static int ASF_write_lan_afx()
{
	if (trial_mode)
		return 0;

	return asf_write_lan_afx(cur_afx_lan, cur_lan_afx_field,
			&lan_afx[cur_afx_lan][cur_lan_afx_field]);

}
static int param_asf_write_lan_filer(char *t, int n)
{
	switch (n) {
	case 1: /* <lan>*/
		if (cvt_uint8(t, &cur_filer_lan) < 0)
			return -1;
		if (cur_filer_lan > 2)
			return -1;
		break;
	default:
		return -1;
	}
	return 0;
}
static int param_lan_ftr(char *t, int n)
{
	switch (n) {
	case 1: /* <lan>*/
		if (cvt_uint8(t, &cur_filer_lan) < 0)
			return -1;
		if (cur_filer_lan > 2)
			return -1;
		if (num_lan_rules[cur_filer_lan] >= LAN_NUM_FILER_RULES)
			return -1;
		break;
	case 2: /* rule*/
		if (cvt_uint8(t, &lan_filer_rule[cur_filer_lan][num_lan_rules[cur_filer_lan]].index) < 0)
			return -1;
		break;
	case 3: /* queue*/
		if (cvt_uint8(t, &lan_filer_rule[cur_filer_lan][num_lan_rules[cur_filer_lan]].queue) < 0)
			return -1;
		break;
	case 4: /* cluster*/
		if (cvt_boole(t, &lan_filer_rule[cur_filer_lan][num_lan_rules[cur_filer_lan]].cluster) < 0)
			return -1;
		break;
	case 5: /* reject*/
		if (cvt_boole(t, &lan_filer_rule[cur_filer_lan][num_lan_rules[cur_filer_lan]].reject) < 0)
			return -1;
		break;
	case 6: /* and*/
		if (cvt_boole(t, &lan_filer_rule[cur_filer_lan][num_lan_rules[cur_filer_lan]].and_next) < 0)
			return -1;
		break;
	case 7: /* cmp*/
		if (cvt_ft_cmp(t, &lan_filer_rule[cur_filer_lan][num_lan_rules[cur_filer_lan]].cmp) < 0)
			return -1;
		break;
	case 8: /* pid*/
		if (cvt_ft_pid(t, &lan_filer_rule[cur_filer_lan][num_lan_rules[cur_filer_lan]].pid) < 0)
			return -1;
		break;
	case 9: /* prop_val*/
		if (cvt_uint32(t, &lan_filer_rule[cur_filer_lan][num_lan_rules[cur_filer_lan]].prop_val) < 0)
			return -1;
		num_lan_rules[cur_filer_lan]++;
		break;
	default:
		return -1;
	}
	return 0;
}

static int ASF_write_lan_filer()
{
	if (trial_mode)
		return 0;

	return asf_write_lan_filer(cur_filer_lan, num_lan_rules[cur_filer_lan],
				lan_filer_rule[cur_filer_lan], &error_index);
}
static int param_asf_write_lan_parse_depth(char *t, int n)
{
	ASF_uint8_t depth;
	switch (n) {
	case 1: /* <lan>*/
		if (cvt_uint8(t, &cur_parse_depth_lan) < 0)
			return -1;
		if (cur_parse_depth_lan > 1)
			return -1;
		break;
	case 2: /* <depth>*/
		if (cvt_uint8(t, &depth) < 0)
			return -1;
		switch (depth) {
		case 2:
			lan_parse_depth[cur_parse_depth_lan] = LPD_LAYER_2;
			break;
		case 3:
			lan_parse_depth[cur_parse_depth_lan] = LPD_LAYER_3;
			break;
		case 4:
			lan_parse_depth[cur_parse_depth_lan] = LPD_LAYER_4;
			break;
		default:
			return -1;
		}
		break;
	default:
		return -1;
	}
	return 0;
}
static int ASF_write_lan_parse_depth()
{
	if (trial_mode)
		return 0;

	return asf_write_lan_parse_depth(cur_parse_depth_lan, lan_parse_depth[cur_parse_depth_lan]);
}
static int param_asf_write_lan_padcrc(char *t, int n)
{
	switch (n) {
	case 1: /* <lan>*/
		if (cvt_uint8(t, &cur_padcrc_lan) < 0)
			return -1;
		if (cur_padcrc_lan > 2)
			return -1;
		break;
	case 2: /* padcrc*/
		if (cvt_boole(t, &lan_padcrc[cur_padcrc_lan]) < 0)
			return -1;
		break;
	case 3: /* crc*/
		if (cvt_boole(t, &lan_crc[cur_padcrc_lan]) < 0)
			return -1;
		break;
	default:
		return -1;
	}
	return 0;
}
static int ASF_write_lan_padcrc()
{
	if (trial_mode)
		return 0;

	return asf_write_lan_padcrc(cur_padcrc_lan, lan_padcrc[cur_padcrc_lan], lan_crc[cur_padcrc_lan]);
}

static int param_asf_read_lan_filer(char *t, int n)
{
	switch (n) {
	case 1: /* <lan>*/
		if (cvt_uint8(t, &cur_filer_lan) < 0)
			return -1;
		if (cur_filer_lan > 2)
			return -1;
		break;
	default:
		return -1;
	}
	return 0;
}
static int ASF_read_lan_filer()
{
	if (trial_mode)
		return 0;

	return asf_read_lan_filer(cur_filer_lan);
}
static int ASF_enable()
{
	if (trial_mode)
		return 0;

	return asf_control_enable();
}

static int param_disable(char *t, int n)
{
	switch (n) {
	case 1: /* <timeout>*/
		if (cvt_uint8(t, &disable_timeout) < 0)
			return -1;
		break;
	case 2: /* <force>*/
		if (cvt_boole(t, &disable_force) < 0)
			return -1;
		break;
	default:
		return -1;
	}
	return 0;
}

void sighndlr(int u)
{
	return;
}

static int ASF_disable()
{
	int ret;

	if (trial_mode)
		return 0;

	if (disable_timeout) {
		/* register signal handlers to allow interrupt
		   to get out of timeout */
		signal(SIGHUP, sighndlr);
		signal(SIGINT, sighndlr);
		signal(SIGQUIT, sighndlr);
	}

	ret = asf_control_disable(disable_timeout, disable_force);

	if (disable_timeout) {
		signal(SIGHUP, sig_exit);
		signal(SIGINT, sig_exit);
		signal(SIGQUIT, sig_exit);
	}

	/* EPROTO happens when everything is already disabled*/
	/* so its OK*/
	if (ret == EPROTO) {
		printf("asf_disable: EPROTO, nothing to disable\n");
		ret = 0;
	}

	return ret;
}

static int param_forget(char *t, int n)
{
	switch (n) {
	case 1:
		forget_what = t;
		while (*t) {
			*t =  (char)tolower(*t);
			t++;
		}
		break;
	default:
		return -1;
	}
	return 0;
}
static int forget_params()
{
	int cmd;

	if (strcmp(forget_what, "all") == 0) {
		/* loop through cmd array and call all ffuncs*/
		for (cmd = 0; cmdtbl[cmd].name; cmd++)
			if (cmdtbl[cmd].ffunc != NULL)
				cmdtbl[cmd].ffunc();

		return 0;
	}
	/* do the one indicated*/
	cmd = name_to_cmd(forget_what);
	if (cmd < 0)
		return -1;

	if (cmdtbl[cmd].ffunc == NULL)
		return -1;

	cmdtbl[cmd].ffunc();
	return 0;
}
static void forget_lan_afx()
{
	init_lan_afx();
}
static void forget_lan_ftr()
{
	num_lan_rules[0] = 0;
	num_lan_rules[1] = 0;
}
static void forget_lan_vlan()
{
	init_lan_vlan();
}
static void forget_lan_pause()
{
	init_lan_pause();
}
/**/
/*Conversion functions*/
/**/
static int cvt_boole(char *t, BOOLE *p)
{
	char *s = t;

	while (*s) {
		*s =  (char)tolower(*s);
		s++;
	}
	if (strcmp("true", t) == 0)
		*p = TRUE;
	else if (strcmp("t", t) == 0)
		*p = TRUE;
	else if (strcmp("1", t) == 0)
		*p = TRUE;
	else if (strcmp("yes", t) == 0)
		*p = TRUE;
	else if (strcmp("y", t) == 0)
		*p = TRUE;
	else if (strcmp("false", t) == 0)
		*p = FALSE;
	else if (strcmp("f", t) == 0)
		*p = FALSE;
	else if (strcmp("0", t) == 0)
		*p = FALSE;
	else if (strcmp("no", t) == 0)
		*p = FALSE;
	else if (strcmp("n", t) == 0)
		*p = FALSE;
	else
		return -1;

	return 0;
}

static int cvt_reaction(char *t, BOOLE *p)
{
	char *s = t;

	while (*s) {
		*s =  (char)tolower(*s);
		s++;
	}
	if (strcmp("stop", t) == 0)
		*p = TRUE;
	else if (strcmp("halt", t) == 0)
		*p = TRUE;
	else if (strcmp("s", t) == 0)
		*p = TRUE;
	else if (strcmp("h", t) == 0)
		*p = TRUE;
	else if (strcmp("continue", t) == 0)
		*p = FALSE;
	else if (strcmp("cont", t) == 0)
		*p = FALSE;
	else if (strcmp("c", t) == 0)
		*p = FALSE;
	else if (strcmp("go", t) == 0)
		*p = FALSE;
	else if (strcmp("g", t) == 0)
		*p = FALSE;
	else
		return -1;

	return 0;
}

#if 0
static int cvt_sint32(char *t, s32 *p)
{
	s64 v;
	char *cvt_err;

	v = strtoll(t, &cvt_err, 0);
	if (*cvt_err != '\0')
		return -1;

	/*range check*/
	if (v < LONG_MIN || v > LONG_MAX)
		return 0;

	*p = (s32)v;

	return 0;
}
#endif

static int cvt_uint32(char *t, ASF_uint32_t *p)
{
	unsigned long long int v;
	ASF_uint32_t x;
	char *cvt_err;

	v = strtoull(t, &cvt_err, 0);
	if (*cvt_err != '\0')
		return -1;

	/*range check*/
	x = 0; x--; /*get largest acceptable value*/
	if (v > x)
		return -1;

	*p = (ASF_uint32_t)v;

	return 0;
}

static int cvt_uint16(char *t, ASF_uint16_t *p)
{
	unsigned long long int v;
	ASF_uint16_t x;
	char *cvt_err;

	v = strtoull(t, &cvt_err, 0);
	if (*cvt_err != '\0')
		return -1;

	/*range check*/
	x = 0; x--; /*get largest acceptable value*/
	if (v > x)
		return -1;

	*p = (ASF_uint16_t)v;

	return 0;
}

static int cvt_uint8(char *t, ASF_uint8_t *p)
{
	unsigned long long int v;
	ASF_uint8_t x;
	char *cvt_err;

	v = strtoull(t, &cvt_err, 0);
	if (*cvt_err != '\0')
		return -1;

	/*range check*/
	x = 0; x--; /*get largest acceptable value*/
	if (v > x)
		return -1;

	*p = (ASF_uint8_t)v;

	return 0;
}
#if 0
static int cvt_device(char *t, enum_dev_t *p)
{
	char *s = t;
	while (*s) {
		*s =  (char)tolower(*s);
		s++;
	}
	if (strcmp("none", t) == 0)
		*p = Dev_NONE;
	else if (strcmp("lan0", t) == 0)
		*p = Dev_LAN0;
	else if (strcmp("lan1", t) == 0)
		*p = Dev_LAN1;
	else
		return -1;

	return 0;
}
#endif
static int cvt_ft_pid(char *t, enum_ft_pid_t *p)
{
	char *s = t;
	while (*s) {
		*s =  (char)tolower(*s);
		s++;
	}
	if (strcmp("mask", t) == 0)
		*p = FT_MASK_PROP;
	else if (strcmp("misc", t) == 0)
		*p = FT_MISC_PROP;
	else if (strcmp("arb", t) == 0)
		*p = FT_ARB_PROP;
	else if (strcmp("dah", t) == 0)
		*p = FT_DAH_PROP;
	else if (strcmp("dal", t) == 0)
		*p = FT_DAL_PROP;
	else if (strcmp("sah", t) == 0)
		*p = FT_SAH_PROP;
	else if (strcmp("sal", t) == 0)
		*p = FT_SAL_PROP;
	else if (strcmp("ety", t) == 0)
		*p = FT_ETY_PROP;
	else if (strcmp("vid", t) == 0)
		*p = FT_VID_PROP;
	else if (strcmp("pri", t) == 0)
		*p = FT_PRI_PROP;
	else if (strcmp("tos", t) == 0)
		*p = FT_TOS_PROP;
	else if (strcmp("l4p", t) == 0)
		*p = FT_L4P_PROP;
	else if (strcmp("dia", t) == 0)
		*p = FT_DIA_PROP;
	else if (strcmp("sia", t) == 0)
		*p = FT_SIA_PROP;
	else if (strcmp("dpt", t) == 0)
		*p = FT_DPT_PROP;
	else if (strcmp("spt", t) == 0)
		*p = FT_SPT_PROP;
	else
		return -1;

	return 0;
}

static int cvt_ft_cmp(char *t, enum_ft_cmp_t *p)
{
	char *s = t;
	while (*s) {
		*s =  (char)tolower(*s);
		s++;
	}
	if (strcmp("always_match", t) == 0)
		*p = FT_ALWAYS_MATCH;
	else if (strcmp("am", t) == 0)
		*p = FT_ALWAYS_MATCH;
	else if (strcmp("af", t) == 0)
		*p = FT_ALWAYS_FAIL;
	else if (strcmp("always_fail", t) == 0)
		*p = FT_ALWAYS_FAIL;
	else if (strcmp("equal", t) == 0)
		*p = FT_EQUAL;
	else if (strcmp("==", t) == 0)
		*p = FT_EQUAL;
	else if (strcmp("greater_equal", t) == 0)
		*p = FT_GREATER_EQUAL;
	else if (strcmp(">=", t) == 0)
		*p = FT_GREATER_EQUAL;
	else if (strcmp("not_equal", t) == 0)
		*p = FT_NOT_EQUAL;
	else if (strcmp("!=", t) == 0)
		*p = FT_NOT_EQUAL;
	else if (strcmp("less", t) == 0)
		*p = FT_LESS;
	else if (strcmp("<", t) == 0)
		*p = FT_LESS;
	else
		return -1;

	return 0;
}

static int cvt_afx_ctrl(char *t, enum_afx_ctrl_t *p)
{
	char *s = t;
	while (*s) {
		*s =  (char)tolower(*s);
		s++;
	}
	if (strcmp("none", t) == 0)
		*p = AFX_NONE;
	else if (strcmp("frame", t) == 0)
		*p = AFX_Frame;
	else if (strcmp("l3hdr", t) == 0)
		*p = AFX_L3hdr;
	else if (strcmp("l4hdr", t) == 0)
		*p = AFX_L4hdr;
	else
		return -1;

	return 0;
}
