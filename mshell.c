#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>

struct Process
{
	int arg_count;
	char **argv;
	int backgorund;
	char* input;
	char* output;
	char* err;
};

struct Command
{
	int proc_count;
	struct Process **procv;	
	int pipes_count;
	int background;
};

struct BuildInCommand
{
	char* name;
	int (*function_ptr)(char**);
};

void showParsing(struct Command* command)
{
	struct Process* proc;
	for(int i = 0; i < command->proc_count; i++)
	{
		proc = command->procv[i];
		for(int j = 0; j < proc->arg_count; j++)
		{
			printf("%s\n", proc->argv[j]);
		}
		printf("redirection OUTPUT: %s\n", proc->output);
		printf("redirection INPUT: %s\n", proc->input);
		printf("__________________________________\n");
	}
}



void freeResources(char* input, struct Command* command);
int cd_func(char** argv);
int exit_func(char** argv);
int help_func(char** argv);
void prompt();
struct BuildInCommand buildins[3] = { {"cd", cd_func}, {"exit", exit_func}, {"help", help_func} };
int EOF_flag = 0;
char *get_input();
struct Command *parse(char *line);
int execute_command(struct Command* command);
int execute_process(struct Process* process, int input, int output);
int execute_buildin_process(struct Process* process);
void signal_handler_SIGCHLD(int n);
void signal_handler_SIGINT(int n);

int main(int argc, char* argv[])
{
	char *typed_line;
	struct Command* command;
	int shell_status = 1;
	signal(SIGCHLD, signal_handler_SIGCHLD);
	signal(SIGINT, SIG_IGN);
	do
	{
		prompt();
		typed_line = get_input();
		
		if(EOF_flag != -1)
		{
			command = parse(typed_line);
			//showParsing(command);
			shell_status = execute_command(command);
			freeResources(typed_line, command);
		}
		else
			free(typed_line);
			
		
	}while(shell_status && (EOF_flag != -1));
	kill(-getpid(), SIGINT);
	printf("\n");
}


char* get_input() 
{
	char *input = NULL;
	size_t buf_size = 0;
	EOF_flag = getline(&input, &buf_size, stdin);
	
	return input;
}

struct Command* parse(char *line)
{
	const int argbuf_size = 128;
	const int procbuf_size = 64;
	struct Process* proc = malloc(sizeof(struct Process));				// FREE proc and command and vectors
	proc->argv = malloc(argbuf_size * sizeof(char*));
	memset(proc->argv, 0, argbuf_size * sizeof(*(proc->argv)));
	proc->arg_count = 0;
	proc->backgorund = 0;
	proc->output = NULL;
	proc->input = NULL;
	proc->err = NULL;
	struct Command* command = malloc(sizeof(struct Command));
	command->procv = malloc(procbuf_size * sizeof(struct Process*));
	command->pipes_count = 0;
	command->proc_count = 0;
	command->background = 0;
	char *pos;								// current position in command
	char *beg_of_arg;						// beginning of quoted argument
	//char *beg_of_proc;						// beginning of 
	int c;
	
	enum STATE {PRS_COMMAND, PRS_PROCESS, PRS_QUOTED_ARG, PRS_ARG};
	enum STATE state = PRS_PROCESS;
	enum REDIRECTION { NONE, INPUT, OUTPUT, STDERR };
	enum REDIRECTION redirection_flag = NONE;
	for(pos = &line[0]; *pos != '\0'; pos++)
	{
		c = (unsigned char) *pos;
		switch(state)
		{
			case PRS_COMMAND:
				
			break;
			
			case PRS_PROCESS:
			
				if (isspace(c))
					continue;
				if (c == '"') 
				{
					state = PRS_QUOTED_ARG;
					beg_of_arg = pos + 1; 
					continue;
				}
				
				if (c == '|')
				{
					command->procv[command->proc_count++] = proc;
					command->pipes_count++;
					proc = malloc(sizeof(struct Process));
					proc->argv = malloc(argbuf_size * sizeof(char*));
					memset(proc->argv, 0, argbuf_size * sizeof(*(proc->argv)));
					proc->arg_count = 0;
					proc->backgorund = 0;
					proc->output = NULL;
					proc->input = NULL;
					proc->err = NULL;
					continue;
				}
				
				if (c == '>')
				{
					redirection_flag = OUTPUT;
					continue;
				}
				
				if (c == '<')
				{
					redirection_flag = INPUT;
					continue;
				}
				
				if (c == '2')
				{
					if(*(pos + 1) == '>')
					{
						redirection_flag = STDERR;
						pos+=2;
						continue;
					}
				}
				
				state = PRS_ARG;
				beg_of_arg = pos;
				continue;
			
			case PRS_QUOTED_ARG:
			
				if (c == '"') 
				{
					*pos = 0;
					if(redirection_flag == OUTPUT)
						proc->output = beg_of_arg;
					if(redirection_flag == INPUT)
						proc->input = beg_of_arg;
					if(redirection_flag == STDERR)
						proc->err = beg_of_arg;
					if(redirection_flag == NONE)
						proc->argv[proc->arg_count++] = beg_of_arg;
					state = PRS_PROCESS;
					redirection_flag = NONE;
				}
				continue;
			
			case PRS_ARG:
			
				if (isspace(c)) 
				{
					*pos = 0;
					if(redirection_flag == OUTPUT)
						proc->output = beg_of_arg;
					if(redirection_flag == INPUT)
						proc->input = beg_of_arg;
					if(redirection_flag == STDERR)
						proc->err = beg_of_arg;
					if(redirection_flag == NONE)
						proc->argv[proc->arg_count++] = beg_of_arg;
					state = PRS_PROCESS;
					redirection_flag = NONE;
				}
				continue;			
		}
	}
	if (state != PRS_PROCESS)
        proc->argv[proc->arg_count++] = beg_of_arg;
        
    //command->procv[command->proc_count++] = proc
    
    if(proc->arg_count > 0 && strcmp(proc->argv[proc->arg_count - 1], "&") == 0)
    {
		proc->argv[proc->arg_count - 1] = NULL;
		proc->arg_count--;
		command->background = 1;
	}
	command->procv[command->proc_count++] = proc;

    return command;
}


void freeResources(char* input, struct Command* command)
{
	free(input);
	struct Process* proc;
	for(int i = 0; i < command->proc_count; i++)
	{
		proc = command->procv[i];
		free(proc->argv);
		free(proc);
	}
	free(command->procv);
	free(command);
}


int execute_command(struct Command* command)
{
	int status;
	int leader_pid;
	int saved_stdin = dup(1);
	int saved_stdout = dup(0);
	
	if(command->procv[0]->argv[0] == NULL)
		return 1;
	
	status = execute_buildin_process(command->procv[0]);	
	if(status == -1)
	{
		//int old_pipe[2];
		int new_pipe[2];
		int input = 0;
		leader_pid = fork();
		if(leader_pid == -1)
		{
			perror("Error, cannot create child process");
			return -1;
		}
		if(leader_pid == 0)
		{
			//if(command->background)
			//	setpgid(0, 0);
	
			char process_name[60] = "group: ";
			strcat(process_name, command->procv[0]->argv[0]);
			prctl(PR_SET_NAME, process_name);
			signal(SIGINT, SIG_DFL);
			for(int i = 0; i < command->proc_count - 1; i++)
			{
				pipe(new_pipe);
				execute_process(command->procv[i], input, new_pipe[1]);
				close(new_pipe[1]);
				input = new_pipe[0];
			}
			if(input != 0)
				dup2(input, 0);
			execute_process(command->procv[command->proc_count - 1], -1, -1);
			exit(1);
		}
		else
		{
			if(!command->background)
				waitpid(leader_pid,NULL,0);
			else
			 printf("Created process with pid: %d\n", leader_pid);
		}
	}
		
	dup2(saved_stdin, 1);
	dup2(saved_stdout, 0);	
	return status;
}

int execute_buildin_process(struct Process* process)
{
	for(int i = 0; i < (sizeof(buildins) / sizeof(buildins[0])); i++)
	{
		if(strcmp(process->argv[0], buildins[i].name) == 0)
		{
			return buildins[i].function_ptr(process->argv);
		}
	}
	return -1;
}
int execute_process(struct Process* process, int input, int output)
{
	int status = 1;
	pid_t pid;
	int fd;
	
	
	if((pid = fork()) == -1)
	{
		perror("Error, cannot create child process");
		return -1;
	}
	
	if(pid == 0)
	{
		if(!process->backgorund)
			signal(SIGINT, signal_handler_SIGINT);
		else
		{
			struct sigaction act;
			act.sa_handler = SIG_IGN;
			act.sa_flags = SA_NOMASK;
			sigaction(SIGINT, &act, NULL);
		}
			
		if(input != -1 && output != -1)
		{
			if (input != 0)
			{
				dup2 (input, 0);
				close (input);
			}

			if (output != 1)
			{
				dup2 (output, 1);
				close (output);
			}
		}
		
		if(process->input != NULL)
		{
			fd = open(process->input, O_RDONLY, 0600);  
			dup2(fd, STDIN_FILENO);
			close(fd);
		}
		
		if(process->output != NULL)
		{
			fd = open(process->output, O_CREAT | O_TRUNC | O_WRONLY, 0600);
			dup2(fd, STDOUT_FILENO); 
			close(fd);
		}
		
		if(process->err != NULL)
		{
			fd = open(process->err, O_CREAT | O_TRUNC | O_WRONLY, 0600);
			dup2(fd, STDERR_FILENO); 
			close(fd);
		}
		
		status = execvp(process->argv[0], process->argv);
		if(status == -1)
		{
			perror("Command not found");
			kill(getpid(), SIGTERM);
		}
	}
	
	//if(!process->backgorund)
		waitpid(pid,NULL,0);
	//else
	//	printf("Created process with PID: %d \n", pid);
	 
	return status;
}

int cd_func(char** argv)
{
	if(argv[1] == NULL) {
		chdir(getenv("HOME")); 
		return 1;
	}
	
	else if(chdir(argv[1]) == -1)
	{
		printf(" %s: no such directory\n", argv[1]);
        return -1;
	}
	return 1;
}

int exit_func(char** argv)
{
	return 0;
}

int help_func(char** argv)
{
	printf("INFO\n");
	return 1;
}

void prompt()
{
	char host_name[128] = "";
	char current_directory[512] = "";
	gethostname(host_name, sizeof(host_name));
	printf("\x1b[38;5;1;1m%s@%s:\x1b[38;5;4m%s > \x1b[0m", getenv("LOGNAME"), host_name, getcwd(current_directory, 512));
}

void signal_handler_SIGCHLD(int p)
{
	while (waitpid(-1, NULL, WNOHANG) > 0) 
	{
	}
}
void signal_handler_SIGINT(int p)
{
	kill(getpid(), SIGINT);
}
