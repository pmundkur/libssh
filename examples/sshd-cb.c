/* This is a sample implementation of a libssh based SSH server */
/*
Copyright 2003-2009 Aris Adamantiadis

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

/* A userdata struct for session. */
struct session_data_struct {
    /* Pointer to the channel the session will allocate. */
    ssh_channel channel;
    int auth_attempts;
    int authenticated;
    int error;
};

struct bind_data_struct {
    int accepted;
    int errors;
    /* temp place to recover connected session */
    ssh_session session;
};

/* Incoming data from the client on the channel, going to input of
   local channel.
*/
static int data_function(ssh_session session, ssh_channel channel, void *data,
                         uint32_t len, int is_stderr, void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

    if (len == 0 /* || cdata->pid < 1 || kill(cdata->pid, 0) < 0 */) {
        return 0;
    }
    fprintf(stdout, "%s: stdin <- len=%d\n", __func__, len);
    return write(cdata->child_stdin, (char *) data, len);
}

static int pty_request(ssh_session session, ssh_channel channel,
                       const char *term, int cols, int rows, int py, int px,
                       void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *)userdata;

    fprintf(stdout, "%s(term=%s, cols=%d, rows=%d, px=%d, py=%d)\n",
            __func__, term, cols, rows, px, py);

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

    fprintf(stdout, "%s(cols=%d, rows=%d, px=%d, py=%d)\n",
            __func__, cols, rows, px, py);

    if (cdata->pty_master != -1) {
        return ioctl(cdata->pty_master, TIOCSWINSZ, cdata->winsize);
    }

    return SSH_ERROR;
}

static int exec_pty(const char *mode, const char *command,
                    struct channel_data_struct *cdata) {
    fprintf(stdout, "%s(mode=%s, command='%s')\n", __func__, mode, command);

    switch(cdata->pid = fork()) {
        case -1:
            close(cdata->pty_master);
            close(cdata->pty_slave);
            fprintf(stderr, "Failed to fork\n");
            return SSH_ERROR;
        case 0:
            close(cdata->pty_master);
            if (login_tty(cdata->pty_slave) != 0) {
                exit(1);
            }
            execl("/bin/sh", "sh", mode, command, NULL);
            exit(0);
        default:
            close(cdata->pty_slave);
            /* pty fd is bi-directional */
            cdata->child_stdout = cdata->child_stdin = cdata->pty_master;
    }
    return SSH_OK;
}

static int exec_nopty(const char *command, struct channel_data_struct *cdata) {
    int in[2], out[2], err[2];

    printf("%s(%s)\n", __func__, command);
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

    fprintf(stdout, "%s(%s)\n", __func__, command);
    if(cdata->pid > 0) {
        return SSH_ERROR;
    }

    if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
        return exec_pty("-c", command, cdata);
    }
    return exec_nopty(command, cdata);
}

static int shell_request(ssh_session session, ssh_channel channel,
                         void *userdata) {
    struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

    printf("%s()\n", __func__);

    if(cdata->pid > 0) {
        return SSH_ERROR;
    }

    if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
        return exec_pty("-l", NULL, cdata);
    }
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
    fprintf(stdout, "%s(%s)\n", __func__, subsystem);
    return SSH_ERROR;
}

static int auth_password(ssh_session session, const char *user,
                         const char *password, void *userdata) {
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;

    fprintf(stdout, "%s: authenticating user %s pwd %s\n",
            __func__, user, password);

    if(strcmp(user,USER) == 0 && strcmp(password, PASSWORD) == 0){
        sdata->authenticated = 1;
        fprintf(stdout, "%s: authenticated\n", __func__);
        return SSH_AUTH_SUCCESS;
    }
    if (sdata->auth_attempts >= 3){
        fprintf(stdout, "%s: too many authentication tries (%d)\n",
                __func__, sdata->auth_attempts);
        ssh_disconnect(session);
        sdata->error = 1;
        return SSH_AUTH_DENIED;
    }
    sdata->auth_attempts++;
    return SSH_AUTH_DENIED;
}

static ssh_channel new_session_channel(ssh_session session, void *userdata){
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;

    if (sdata->channel)
        fprintf(stderr, "%s: OVERWRITING PREVIOUS CHANNEL!\n", __func__);
    fprintf(stdout, "%s: allocated session channel\n", __func__);

    sdata->channel = ssh_channel_new(session);
    return sdata->channel;
}

static int process_stdout(socket_t fd, int revents, void *userdata) {
    char buf[BUF_SIZE];
    int n = -1;
    ssh_channel channel = (ssh_channel) userdata;

    if (channel != NULL && (revents & POLLIN) != 0) {
        n = read(fd, buf, BUF_SIZE);
        fprintf(stdout, "%s: stdout -> %d bytes\n", __func__, n);
        if (n > 0) {
            ssh_channel_write(channel, buf, n);
        }
    }

    return n;
}

static int process_stderr(socket_t fd, int revents, void *userdata) {
    char buf[BUF_SIZE];
    int n = -1;
    ssh_channel channel = (ssh_channel) userdata;

    if (channel != NULL && (revents & POLLIN) != 0) {
        n = read(fd, buf, BUF_SIZE);
        fprintf(stdout, "%s: stderr -> %d bytes\n", __func__, n);
        if (n > 0) {
            ssh_channel_write_stderr(channel, buf, n);
        }
    }

    return n;
}

static int service_request(ssh_session session, const char *service,
                           void *userdata) {
    fprintf(stdout, "%s(%s): accepting\n", __func__, service);
    return 0; // accepted; -1 => denied
}

static void signal_callback(ssh_session session, ssh_channel channel,
                            const char *signal, void *userdata) {
    fprintf(stdout, "%s(%s)\n", __func__, signal);
}

static void close_callback(ssh_session session, ssh_channel channel,
                           void *userdata) {
    fprintf(stdout, "%s()\n", __func__);
}

static void exit_status_callback(ssh_session session, ssh_channel channel,
                                 int exit_status, void *userdata) {
    fprintf(stdout, "%s(%d)\n", __func__, exit_status);
}

static void exit_signal_callback(ssh_session session, ssh_channel channel,
                                 const char *signal, int core,
                                 const char *errmsg, const char *lang,
                                 void *userdata) {
    fprintf(stdout, "%s(signal=%s core=%d errmsg=%s lang=%s)\n",
            __func__, signal, core, errmsg, lang);
}

static void eof_function(ssh_session session, ssh_channel channel,
                  void *userdata) {
    fprintf(stdout, "%s()\n", __func__);
}

static int env_request(ssh_session session, ssh_channel channel,
                 const char *env_name, const char *env_value,
                void *userdata) {
    fprintf(stdout, "%s: env[%s] <- %s\n", __func__, env_name, env_value);
    return 0;
}

static void incoming_connection(ssh_bind sshbind, void *userdata) {
    struct bind_data_struct *bdata = (struct bind_data_struct *)userdata;
    ssh_session session = ssh_new();

    int r = ssh_bind_accept(sshbind, session);
    if (r == SSH_ERROR) {
        fprintf(stdout, "%s: error accepting a connection : %s\n",
                __func__, ssh_get_error(sshbind));
        bdata->errors++;
        ssh_free(session);
        return;
    }

    bdata->session = session;
    bdata->accepted++;
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

int serve_one(ssh_bind sshbind){
    ssh_session session;
    ssh_event mainloop;

    /* Structure for storing the pty size. */
    struct winsize wsize = {
        .ws_row = 0,
        .ws_col = 0,
        .ws_xpixel = 0,
        .ws_ypixel = 0
    };

    struct bind_data_struct bdata = {
        .accepted = 0,
        .errors   = 0,
        .session  = NULL
    };

    /* Our struct holding information about the channel. */
    struct channel_data_struct cdata = {
        .pid = 0,
        .pty_master = -1,
        .pty_slave = -1,
        .child_stdin = -1,
        .child_stdout = -1,
        .child_stderr = -1,
        .event = NULL,
        .winsize = &wsize
    };

    /* Our struct holding information about the session. */
    struct session_data_struct sdata = {
        .channel = NULL,
        .auth_attempts = 0,
        .authenticated = 0,
        .error = 0
    };

    struct ssh_channel_callbacks_struct channel_cb = {
        .userdata = &cdata,

        .channel_pty_request_function = pty_request,
        .channel_pty_window_change_function = pty_resize,

        .channel_shell_request_function = shell_request,
        .channel_env_request_function = env_request,

        .channel_exec_request_function = exec_request,

        .channel_subsystem_request_function = subsystem_request,

        .channel_data_function = data_function,
        .channel_eof_function = eof_function,
        .channel_close_function = close_callback,
        .channel_write_wontblock_function = NULL,
        .channel_signal_function = signal_callback,

        .channel_exit_status_function = exit_status_callback,
        .channel_exit_signal_function = exit_signal_callback,
    };

    struct ssh_server_callbacks_struct server_cb = {
        .userdata = &sdata,
        .auth_password_function = auth_password,
        .service_request_function = service_request,
        .channel_open_request_session_function = new_session_channel
    };

    struct ssh_bind_callbacks_struct bind_cb = {
        .incoming_connection = incoming_connection,
    };

    int r, rc;

    ssh_callbacks_init(&bind_cb);

    if(ssh_bind_listen(sshbind)<0){
        fprintf(stdout, "%s: error listening to socket: %s\n",
                __func__, ssh_get_error(sshbind));
        return 1;
    }

    printf("Waiting for session ...\n");
    session=ssh_new();

    if (0) {
        r = ssh_bind_accept(sshbind,session);
        if (r==SSH_ERROR) {
            fprintf(stdout, "%s: error accepting a connection : %s\n",
                    __func__, ssh_get_error(sshbind));
            return 1;
        }
    } else {
        /* non-blocking accept */

        /* set-blocking before doing bind-accept */
        ssh_bind_set_blocking(sshbind, 0);
        ssh_bind_set_callbacks(sshbind, &bind_cb, &bdata);

        mainloop = ssh_event_new();
        r = ssh_bind_accept(sshbind, session);
        if (r == SSH_ERROR) {
            fprintf(stderr, "%s: error binding connection: %s / %s\n",
                    __func__, ssh_get_error(sshbind), ssh_get_error(session));
            return 1;
        }
        fprintf(stderr, "%s: starting loop\n", __func__);
        do {
            if (ssh_event_dopoll(mainloop, -1) == SSH_ERROR) {
                fprintf(stderr, "%s: error waiting for connection\n", __func__);
                ssh_event_free(mainloop);
                return 1;
            }
        } while (bdata.accepted == 0 && bdata.errors == 0);

        if (bdata.errors > 0) {
            fprintf(stderr, "%s: error accepting connection\n", __func__);
            ssh_event_free(mainloop);
            return 1;
        }
        if (bdata.accepted) {
            session = bdata.session;
            bdata.session = NULL;
        }
        ssh_event_remove_session(mainloop, session);
        ssh_event_free(mainloop);
    }

    ssh_callbacks_init(&server_cb);
    ssh_callbacks_init(&channel_cb);

    ssh_set_server_callbacks(session, &server_cb);

    fprintf(stdout, "%s: starting key exchange ...\n", __func__);
    if (ssh_handle_key_exchange(session)) {
        fprintf(stdout, "%s: ssh_handle_key_exchange: %s\n",
                __func__, ssh_get_error(session));
        return 1;
    }
    ssh_set_auth_methods(session,SSH_AUTH_METHOD_PASSWORD);

    fprintf(stdout, "%s: starting main loop\n", __func__);
    mainloop = ssh_event_new();
    ssh_event_add_session(mainloop, session);

    while (!(sdata.authenticated && sdata.channel != NULL)){
        if(sdata.error)
            break;
        r = ssh_event_dopoll(mainloop, -1);
        if (r==SSH_ERROR) {
            fprintf(stdout, "%s: error : %s\n",
                    __func__, ssh_get_error(session));
            ssh_disconnect(session);
            ssh_event_remove_session(mainloop, session);
            return 1;
        }
    }
    if(sdata.error){
        fprintf(stdout, "%s: error, exiting loop\n", __func__);
        return 1;
    }

    fprintf(stdout, "%s: authenticated and got a channel\n", __func__);
    ssh_set_channel_callbacks(sdata.channel, &channel_cb);

    do {
        /* Poll the main event which takes care of the session, the channel and
         * even our child process's stdout/stderr (once it's started). */
        if (ssh_event_dopoll(mainloop, -1) == SSH_ERROR) {
            fprintf(stderr, "%s: poll error, closing channel\n", __func__);
            ssh_channel_close(sdata.channel);
        }

        /* If child process's stdout/stderr has been registered with the event,
         * or the child process hasn't started yet, continue. */
        if (cdata.event != NULL || cdata.pid == 0) {
            continue;
        }
        /* Executed only once, once the child process starts. */
        cdata.event = mainloop;
        /* If stdout valid, add stdout to be monitored by the poll event. */
        if (cdata.child_stdout != -1) {
            if (ssh_event_add_fd(mainloop, cdata.child_stdout, POLLIN,
                                 process_stdout, sdata.channel) != SSH_OK) {
                fprintf(stderr, "%s: failed to register stdout to poll context\n",
                        __func__);
                ssh_channel_close(sdata.channel);
            }
        }

        /* If stderr valid, add stderr to be monitored by the poll event. */
        if (cdata.child_stderr != -1){
            if (ssh_event_add_fd(mainloop, cdata.child_stderr, POLLIN,
                                 process_stderr, sdata.channel) != SSH_OK) {
                fprintf(stderr, "%s: failed to register stderr to poll context\n",
                        __func__);
                ssh_channel_close(sdata.channel);
            }
        }
    } while (ssh_channel_is_open(sdata.channel)
             && ((cdata.pid == 0) || waitpid(cdata.pid, &rc, WNOHANG) == 0));

    if (!ssh_channel_is_open(sdata.channel)) {
        fprintf(stderr, "%s: channel is not open, quitting loop.\n", __func__);
    }
    if (waitpid(cdata.pid, &rc, WNOHANG) != 0) {
        fprintf(stderr, "%s: child exited with code %d.\n", __func__, rc);
    }

    if (!close(cdata.pty_master))   fprintf(stderr, "%s: error closing pty_master\n", __func__);
    if (!close(cdata.child_stdin))  fprintf(stderr, "%s: error closing child stdin\n", __func__);
    if (!close(cdata.child_stdout)) fprintf(stderr, "%s: error closing child stdout\n", __func__);
    if (!close(cdata.child_stderr)) fprintf(stderr, "%s: error closing child stderr\n", __func__);

    /* Remove the descriptors from the polling context, since they are now
     * closed, they will always trigger during the poll calls. */
    ssh_event_remove_fd(mainloop, cdata.child_stdout);
    ssh_event_remove_fd(mainloop, cdata.child_stderr);

    ssh_disconnect(session);
    ssh_free(session);
    ssh_event_free(mainloop);

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
    printf("Parsing args ...\n");
    argp_parse (&argp, argc, argv, 0, 0, sshbind);

    serve_one(sshbind);

    ssh_bind_free(sshbind);
    ssh_finalize();

    return 0;
}

