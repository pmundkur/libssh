/* This is a sample implementation of a libssh based SSH server */
/*
Copyright 2009 Aris Adamantiadis
Copyright 2017 Prashanth Mundkur

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
The goal is to show the API in action. It's not a reference on how terminal
clients must be made or how a client should react.
*/

#include "config.h"

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#include <argp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <pty.h>
#include <utmp.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <poll.h>

#define USER "myuser"
#define PASSWORD "mypassword"
#define BUF_SIZE 1048576

/* A userdata struct for channel. */
struct channel_data_struct {
    ssh_channel channel;
    struct pid_registry *pids;
    /* pid of the child process the channel will spawn. */
    pid_t pid;
    /* For PTY allocation */
    socket_t pty_master;
    socket_t pty_slave;
    /* For communication with the child process. */
    socket_t child_stdin;
    socket_t child_stdout;
    /* Only used for subsystem and exec requests. */
    socket_t child_stderr;
    /* Event which is used to poll the above descriptors. */
    ssh_event event;
    /* Terminal size struct. */
    struct winsize *winsize;
};

struct channel_pid {
    pid_t pid;
    struct channel_data_struct *cdata;
};

#define MAX_PIDS 5
struct pid_registry {
    struct channel_pid pids[MAX_PIDS];
};

/* A userdata struct for session. */
struct session_data_struct {
    ssh_event mainloop;
    struct pid_registry *pids;
    /* Pointer to the channel the session will allocate. */
    ssh_channel channel;
    int auth_attempts;
    int authenticated;
    int error;
};

struct bind_data_struct {
    ssh_event mainloop;
    struct pid_registry *pids;
    int accepted;
    int errors;
};

void init_pid_registry(struct pid_registry *pids) {
    bzero(pids, sizeof(*pids));
}

void register_pid_for_channel(struct pid_registry *r, pid_t pid, struct channel_data_struct *cdata) {
    int p = 0;
    while (p < MAX_PIDS) {
        if (r->pids[p].pid != 0) {
            p++;
            continue;
        }
        r->pids[p].pid = pid;
        r->pids[p].cdata = cdata;
        return;
    }
    fprintf(stderr, "%s: too many children (increase MAX_PIDS), exiting.\n", __func__);
    exit(1);
}

/* Incoming data from the client on the channel, going to input of
   local channel.
*/
static int data_function(ssh_session session, ssh_channel channel, void *data,
                         uint32_t len, int is_stderr, void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

    if (len == 0) return 0;

    return write(cdata->child_stdin, (char *) data, len);
}

static int pty_request(ssh_session session, ssh_channel channel,
                       const char *term, int cols, int rows, int py, int px,
                       void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *)userdata;

    cdata->winsize->ws_row = rows;
    cdata->winsize->ws_col = cols;
    cdata->winsize->ws_xpixel = px;
    cdata->winsize->ws_ypixel = py;

    if (openpty(&cdata->pty_master, &cdata->pty_slave, NULL, NULL,
                cdata->winsize) != 0) {
        fprintf(stderr, "Failed to open pty\n");
        return SSH_ERROR;
    }
    return SSH_OK;
}

static int pty_resize(ssh_session session, ssh_channel channel, int cols,
                      int rows, int py, int px, void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *)userdata;

    cdata->winsize->ws_row = rows;
    cdata->winsize->ws_col = cols;
    cdata->winsize->ws_xpixel = px;
    cdata->winsize->ws_ypixel = py;

    if (cdata->pty_master != -1)
        return ioctl(cdata->pty_master, TIOCSWINSZ, cdata->winsize);

    return SSH_ERROR;
}

static int process_stdout(socket_t fd, int revents, void *userdata) {
    char buf[BUF_SIZE];
    int n = -1;
    ssh_channel channel = (ssh_channel) userdata;

    if (channel != NULL && (revents & POLLIN) != 0) {
        n = read(fd, buf, BUF_SIZE);
        if (n > 0)
            ssh_channel_write(channel, buf, n);
    }

    return n;
}

static int process_stderr(socket_t fd, int revents, void *userdata) {
    char buf[BUF_SIZE];
    int n = -1;
    ssh_channel channel = (ssh_channel) userdata;

    if (channel != NULL && (revents & POLLIN) != 0) {
        n = read(fd, buf, BUF_SIZE);
        if (n > 0)
            ssh_channel_write_stderr(channel, buf, n);
    }

    return n;
}

static int exec_pty(const char *mode, const char *command,
                    struct channel_data_struct *cdata) {

    switch(cdata->pid = fork()) {
        case -1:
            close(cdata->pty_master);
            close(cdata->pty_slave);
            cdata->pty_master = cdata->pty_slave = -1;
            fprintf(stderr, "Failed to fork\n");
            return SSH_ERROR;
        case 0:
            close(cdata->pty_master);
            cdata->pty_master = -1;
            if (login_tty(cdata->pty_slave) != 0) {
                fprintf(stderr, "error in login_tty: %s\n", strerror(errno));
                exit(1);
            }
            execl("/bin/sh", "sh", mode, command, NULL);
            exit(0);
        default:
            close(cdata->pty_slave);
            cdata->pty_slave = -1;
            register_pid_for_channel(cdata->pids, cdata->pid, cdata);
            /* pty fd is bi-directional */
            cdata->child_stdout = cdata->child_stdin = cdata->pty_master;
            if (ssh_event_add_fd(cdata->event, cdata->child_stdout, POLLIN,
                                 process_stdout, cdata->channel) != SSH_OK) {
                fprintf(stderr, "%s: failed to register stdout to poll context\n",
                        __func__);
                exit(1);
            }
    }
    return SSH_OK;
}

static int exec_nopty(const char *command, struct channel_data_struct *cdata) {
    int in[2], out[2], err[2];

    /* Do the plumbing to be able to talk with the child process. */
    if (pipe(in) != 0) {
        goto stdin_failed;
    }
    if (pipe(out) != 0) {
        goto stdout_failed;
    }
    if (pipe(err) != 0) {
        goto stderr_failed;
    }

    switch(cdata->pid = fork()) {
        case -1:
            goto fork_failed;
        case 0:
            /* Finish the plumbing in the child process. */
            close(in[1]);
            close(out[0]);
            close(err[0]);
            dup2(in[0], STDIN_FILENO);
            dup2(out[1], STDOUT_FILENO);
            dup2(err[1], STDERR_FILENO);
            close(in[0]);
            close(out[1]);
            close(err[1]);
            /* exec the requested command. */
            execl("/bin/sh", "sh", "-c", command, NULL);
            exit(0);
    }

    close(in[0]);
    close(out[1]);
    close(err[1]);

    cdata->child_stdin = in[1];
    cdata->child_stdout = out[0];
    cdata->child_stderr = err[0];

    register_pid_for_channel(cdata->pids, cdata->pid, cdata);
    if (ssh_event_add_fd(cdata->event, cdata->child_stdout, POLLIN,
                         process_stdout, cdata->channel) != SSH_OK) {
        fprintf(stderr, "%s: failed to register stdout to poll context\n",
                __func__);
        exit(1);
    }
    if (ssh_event_add_fd(cdata->event, cdata->child_stderr, POLLIN,
                         process_stderr, cdata->channel) != SSH_OK) {
        fprintf(stderr, "%s: failed to register stderr to poll context\n",
                __func__);
        exit(1);
    }

    return SSH_OK;

fork_failed:
    close(err[0]);
    close(err[1]);
stderr_failed:
    close(out[0]);
    close(out[1]);
stdout_failed:
    close(in[0]);
    close(in[1]);
stdin_failed:
    return SSH_ERROR;
}

static int exec_request(ssh_session session, ssh_channel channel,
                        const char *command, void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

    if(cdata->pid > 0)
        return SSH_ERROR;

    if (cdata->pty_master != -1 && cdata->pty_slave != -1)
        return exec_pty("-c", command, cdata);

    return exec_nopty(command, cdata);
}

static int shell_request(ssh_session session, ssh_channel channel,
                         void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

    if(cdata->pid > 0)
        return SSH_ERROR;

    if (cdata->pty_master != -1 && cdata->pty_slave != -1)
        return exec_pty("-l", NULL, cdata);

    /* Client requested a shell without a pty, let's pretend we allow that */
    return SSH_OK;
}

static int subsystem_request(ssh_session session, ssh_channel channel,
                             const char *subsystem, void *userdata) {
    /* subsystem requests behave simillarly to exec requests. */
    /*
    if (strcmp(subsystem, "sftp") == 0) {
        return exec_request(session, channel, SFTP_SERVER_PATH, userdata);
    }
    */
    return SSH_ERROR;
}

static int auth_password(ssh_session session, const char *user,
                         const char *password, void *userdata) {
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;

    if(strcmp(user,USER) == 0 && strcmp(password, PASSWORD) == 0){
        sdata->authenticated = 1;
        return SSH_AUTH_SUCCESS;
    }
    if (sdata->auth_attempts >= 3){
        fprintf(stdout, "%s: too many authentication tries (%d) for user %s, disconnecting.\n",
                __func__, sdata->auth_attempts, user);
        ssh_disconnect(session);
        sdata->error = 1;
        return SSH_AUTH_DENIED;
    }
    sdata->auth_attempts++;
    return SSH_AUTH_DENIED;
}


static int service_request(ssh_session session, const char *service,
                           void *userdata) {
    /* fprintf(stdout, "%s(%s): accepting\n", __func__, service); */
    return 0; // accepted; -1 => denied
}

static void signal_callback(ssh_session session, ssh_channel channel,
                            const char *signal, void *userdata) {
    /* fprintf(stdout, "%s(%s)\n", __func__, signal); */
}

static void close_callback(ssh_session session, ssh_channel channel,
                           void *userdata) {
    /* fprintf(stdout, "%s()\n", __func__); */
}

static void exit_status_callback(ssh_session session, ssh_channel channel,
                                 int exit_status, void *userdata) {
    /* fprintf(stdout, "%s(%d)\n", __func__, exit_status); */
}

static void exit_signal_callback(ssh_session session, ssh_channel channel,
                                 const char *signal, int core,
                                 const char *errmsg, const char *lang,
                                 void *userdata) {
    /* fprintf(stdout, "%s(signal=%s core=%d errmsg=%s lang=%s)\n",
               __func__, signal, core, errmsg, lang); */
}

static void eof_function(ssh_session session, ssh_channel channel,
                  void *userdata) {
    /* fprintf(stdout, "%s()\n", __func__); */
}

static int env_request(ssh_session session, ssh_channel channel,
                 const char *env_name, const char *env_value,
                void *userdata) {
    /* fprintf(stdout, "%s: env[%s] <- %s\n", __func__, env_name, env_value); */
    return 0;
}

const char *argp_program_version = "libssh server example "
SSH_STRINGIFY(LIBSSH_VERSION);
const char *argp_program_bug_address = "<libssh@libssh.org>";

/* Program documentation. */
static char doc[] = "libssh -- a Secure Shell protocol implementation";

/* A description of the arguments we accept. */
static char args_doc[] = "BINDADDR";

/* The options we understand. */
static struct argp_option options[] = {
    {
        .name  = "port",
        .key   = 'p',
        .arg   = "PORT",
        .flags = 0,
        .doc   = "Set the port to bind.",
        .group = 0
    },
    {
        .name  = "hostkey",
        .key   = 'k',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the host key.",
        .group = 0
    },
    {
        .name  = "dsakey",
        .key   = 'd',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the dsa key.",
        .group = 0
    },
    {
        .name  = "rsakey",
        .key   = 'r',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the rsa key.",
        .group = 0
    },
    {
        .name  = "verbose",
        .key   = 'v',
        .arg   = NULL,
        .flags = 0,
        .doc   = "Get verbose output.",
        .group = 0
    },
    {NULL, 0, NULL, 0, NULL, 0}
};

/* Parse a single option. */
static error_t parse_opt (int key, char *arg, struct argp_state *state) {
    /* Get the input argument from argp_parse, which we
     * know is a pointer to our arguments structure.
     */
    ssh_bind sshbind = state->input;

    switch (key) {
        case 'p':
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, arg);
            break;
        case 'd':
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, arg);
            break;
        case 'k':
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, arg);
            break;
        case 'r':
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, arg);
            break;
        case 'v':
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "3");
            break;
        case ARGP_KEY_ARG:
            if (state->arg_num >= 1) {
                /* Too many arguments. */
                argp_usage (state);
            }
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, arg);
            break;
        case ARGP_KEY_END:
            if (state->arg_num < 1) {
                /* Not enough arguments. */
                argp_usage (state);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

/* Our argp parser. */
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};

/* Structure for storing the pty size. */
struct winsize *new_winsize() {
    struct winsize *wsize = (struct winsize *)calloc(1, sizeof(*wsize));
    return wsize;
}

struct bind_data_struct *new_bind_data(ssh_event mainloop, struct pid_registry *pids) {
    struct bind_data_struct *bdata = (struct bind_data_struct *)calloc(1, sizeof(*bdata));
    bdata->mainloop = mainloop;
    bdata->pids = pids;
    return bdata;
}

/* Our struct holding information about the session. */
struct session_data_struct *new_session_data(struct bind_data_struct *bdata) {
    struct session_data_struct *sdata = (struct session_data_struct *)calloc(1, sizeof(*sdata));
    sdata->mainloop = bdata->mainloop;
    sdata->pids = bdata->pids;
    return sdata;
}

/* Our struct holding information about the channel. */
struct channel_data_struct *new_channel_data(struct session_data_struct *sdata, ssh_channel channel) {
    struct channel_data_struct *cdata = (struct channel_data_struct *)calloc(1, sizeof(*cdata));
    cdata->event = sdata->mainloop;
    cdata->pids = sdata->pids;
    cdata->channel = channel;
    cdata->pid = 0;
    cdata->pty_master = -1;
    cdata->pty_slave = -1;
    cdata->child_stdin = -1;
    cdata->child_stdout = -1;
    cdata->child_stderr = -1;
    cdata->winsize = new_winsize();
    return cdata;
}

void close_channel_data(struct channel_data_struct *cdata) {
    if (cdata->pty_master != -1)   close(cdata->pty_master);
    if (cdata->pty_slave != -1)    close(cdata->pty_slave);
    if (cdata->child_stdin != -1)  close(cdata->child_stdin);

    if (cdata->child_stdout != -1) {
        if (cdata->event) ssh_event_remove_fd(cdata->event, cdata->child_stdout);
        close(cdata->child_stdout);
    }
    if (cdata->child_stderr != -1) {
        if (cdata->event) ssh_event_remove_fd(cdata->event, cdata->child_stderr);
        close(cdata->child_stderr);
    }
    if (cdata->winsize) free(cdata->winsize);
    cdata->winsize = NULL;
}

struct ssh_channel_callbacks_struct *new_channel_cb(struct channel_data_struct *cdata) {
    struct ssh_channel_callbacks_struct *cb = (struct ssh_channel_callbacks_struct *)calloc(1, sizeof(*cb));

    cb->userdata = cdata;

    cb->channel_pty_request_function = pty_request;
    cb->channel_pty_window_change_function = pty_resize;

    cb->channel_shell_request_function = shell_request;
    cb->channel_env_request_function = env_request;

    cb->channel_exec_request_function = exec_request;

    cb->channel_subsystem_request_function = subsystem_request;

    cb->channel_data_function = data_function;
    cb->channel_eof_function = eof_function;
    cb->channel_close_function = close_callback;
    cb->channel_write_wontblock_function = NULL;
    cb->channel_signal_function = signal_callback;

    cb->channel_exit_status_function = exit_status_callback;
    cb->channel_exit_signal_function = exit_signal_callback;

    ssh_callbacks_init(cb);
    return cb;
}

static ssh_channel new_session_channel(ssh_session session, void *userdata){
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;

    if (sdata->channel) {
        fprintf(stderr, "%s: only one channel per session supported!\n", __func__);
        return NULL;
    }

    sdata->channel = ssh_channel_new(session);
    if (sdata->channel) {
        struct channel_data_struct *cdata = new_channel_data(sdata, sdata->channel);
        struct ssh_channel_callbacks_struct *cb = new_channel_cb(cdata);
        if (cdata && cb)
            ssh_set_channel_callbacks(sdata->channel, cb);
    }
    return sdata->channel;
}

struct ssh_server_callbacks_struct *new_server_cb(struct session_data_struct *sdata) {
    struct ssh_server_callbacks_struct *cb = (struct ssh_server_callbacks_struct *)calloc(1, sizeof(*cb));

    cb->userdata = sdata;

    cb->auth_password_function = auth_password;
    cb->service_request_function = service_request;
    cb->channel_open_request_session_function = new_session_channel;

    ssh_callbacks_init(cb);
    return cb;
}

static void incoming_connection(ssh_bind sshbind, void *userdata) {
    struct session_data_struct *sdata;
    struct ssh_server_callbacks_struct *server_cb;

    struct bind_data_struct *bdata = (struct bind_data_struct *)userdata;
    ssh_session session = ssh_new();

    int r = ssh_bind_accept(sshbind, session);
    if (r == SSH_ERROR) {
        fprintf(stderr, "%s: error accepting a connection : %s\n",
                __func__, ssh_get_error(sshbind));
        bdata->errors++;
        ssh_free(session);
        return;
    }

    if (ssh_handle_key_exchange(session)) {
        fprintf(stderr, "%s: ssh_handle_key_exchange: %s\n",
                __func__, ssh_get_error(session));
        ssh_free(session);
        return;
    }
    ssh_set_auth_methods(session,SSH_AUTH_METHOD_PASSWORD);

    ssh_event_add_session(bdata->mainloop, session);

    sdata = new_session_data(bdata);
    server_cb = new_server_cb(sdata);
    ssh_set_server_callbacks(session, server_cb);
    bdata->accepted++;
}


int serve(ssh_bind sshbind){
    ssh_event mainloop;
    struct pid_registry reg;

    struct ssh_bind_callbacks_struct bind_cb = {
        .incoming_connection = incoming_connection,
    };

    struct bind_data_struct *bdata;

    int r, rc;

    init_pid_registry(&reg);

    if(ssh_bind_listen(sshbind)<0){
        fprintf(stderr, "%s: error listening to socket: %s\n",
                __func__, ssh_get_error(sshbind));
        return 1;
    }

    ssh_bind_set_blocking(sshbind, 0);
    ssh_callbacks_init(&bind_cb);
    mainloop = ssh_event_new();

    bdata = new_bind_data(mainloop, &reg);
    ssh_bind_set_callbacks(sshbind, &bind_cb, bdata);

    r = ssh_bind_accept_nonblocking(sshbind, mainloop);
    if (r == SSH_ERROR) {
        fprintf(stderr, "%s: error binding connection: %s\n",
                __func__, ssh_get_error(sshbind));
        return 1;
    }

    do {
        int p;
        if (ssh_event_dopoll(mainloop, -1) == SSH_ERROR) {
            fprintf(stderr, "%s: error handling connections\n", __func__);
            ssh_event_free(mainloop);
            return 1;
        }
        for (p = 0; p < MAX_PIDS; p++) {
            if (reg.pids[p].pid == 0) continue;
            if (waitpid(reg.pids[p].pid, &rc, WNOHANG) != 0) {
                ssh_channel channel = reg.pids[p].cdata->channel;
                ssh_channel_close(channel);
                ssh_disconnect(ssh_channel_get_session(channel));
                close_channel_data(reg.pids[p].cdata);
                free(reg.pids[p].cdata);
                reg.pids[p].cdata = NULL;
                reg.pids[p].pid = 0;
            }
        }
    } while (bdata->errors == 0);

    return 0;
}

#define KEYS_FOLDER "/etc/ssh/"

int main(int argc, char **argv){
    ssh_bind sshbind;

    ssh_init();

    sshbind=ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "ssh_host_dsa_key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");

    /*
     * Parse our arguments; every option seen by parse_opt will
     * be reflected in arguments.
     */
    argp_parse (&argp, argc, argv, 0, 0, sshbind);

    serve(sshbind);

    ssh_bind_free(sshbind);
    ssh_finalize();

    return 0;
}

