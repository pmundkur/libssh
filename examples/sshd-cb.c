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

#ifdef HAVE_ARGP_H
#include <argp.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef KEYS_FOLDER
#ifdef _WIN32
#define KEYS_FOLDER
#else
#define KEYS_FOLDER "/etc/ssh/"
#endif
#endif

#define USER "myuser"
#define PASSWORD "mypassword"

static int authenticated=0;
static int error = 0;

struct userdata {
    ssh_channel channel;
};

static int auth_password(ssh_session session, const char *user,
        const char *password, void *userdata){
    static int tries = 0;
    (void)userdata;
    printf("Authenticating user %s pwd %s\n",user, password);
    if(strcmp(user,USER) == 0 && strcmp(password, PASSWORD) == 0){
        authenticated = 1;
        printf("Authenticated\n");
        return SSH_AUTH_SUCCESS;
    }
    if (tries >= 3){
        printf("Too many authentication tries\n");
        ssh_disconnect(session);
        error = 1;
        return SSH_AUTH_DENIED;
    }
    tries++;
    return SSH_AUTH_DENIED;
}

static int pty_request(ssh_session session, ssh_channel channel, const char *term,
        int x,int y, int px, int py, void *userdata){
    (void) session;
    (void) channel;
    (void) term;
    (void) x;
    (void) y;
    (void) px;
    (void) py;
    (void) userdata;
    printf("Allocated terminal\n");
    return 0;
}

static int shell_request(ssh_session session, ssh_channel channel, void *userdata){
    (void)session;
    (void)channel;
    (void)userdata;
    printf("Allocated shell\n");
    return 0;
}

static void signal_callback(ssh_session session, ssh_channel channel, const char *signal, void *userdata){
    printf("Received signal %s!\n", signal);
}

static void close_callback(ssh_session session, ssh_channel channel, void *userdata){
    printf("Closed channel!\n");
}

static void exit_status_callback(ssh_session session, ssh_channel channel, int exit_status, void *userdata){
    printf("Exit status: %d\n", exit_status);
}

static void exit_signal_callback(ssh_session session, ssh_channel channel, const char *signal, int core, const char *errmsg, const char *lang, void *userdata) {
    printf("Exit signal: %s core=%d errmsg=%s lang=%s\n", signal, core, errmsg, lang);
}

int pty_window_change_callback(ssh_session session, ssh_channel channel, int width, int height, int pxwidth, int pxheight, void *userdata){
    printf("PTY window change to w=%d h=%d pxw=%d pwh=%d\n", width, height, pxwidth, pxheight);
    return 0; // accepted; -1 => denied
}

struct ssh_channel_callbacks_struct channel_cb = {
    .channel_data_function = NULL,
    .channel_eof_function = NULL,
    .channel_close_function = close_callback,
    .channel_signal_function = signal_callback,
    .channel_exit_status_function = exit_status_callback,
    .channel_exit_signal_function = exit_signal_callback,
    .channel_pty_request_function = pty_request,
    .channel_shell_request_function = shell_request,
    .channel_pty_window_change_function = NULL,
    .channel_exec_request_function = NULL,
    .channel_env_request_function = NULL,
    .channel_subsystem_request_function = NULL,
    .channel_write_wontblock_function = NULL,
};

static ssh_channel new_session_channel(ssh_session session, void *userdata){
    struct userdata *ud = (struct userdata *)userdata;
    ssh_channel chan;
    printf("Allocated session channel\n");
    chan = ssh_channel_new(session);
    ssh_callbacks_init(&channel_cb);
    ssh_set_channel_callbacks(chan, &channel_cb);
    if (ud->channel) printf("OVERWRITING PREVIOUS CHANNEL!\n");
    ud->channel = chan;
    return chan;
}

static int service_request(ssh_session session, const char *service, void *userdata){
    printf("Received request for service: %s, accepting\n", service);
    return 0; // accepted; -1 => denied
}

#ifdef HAVE_ARGP_H
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
#endif /* HAVE_ARGP_H */

int serve_one(ssh_bind sshbind){
    ssh_session session;
    ssh_event mainloop;

    struct userdata userdata = {
	.channel = NULL,
    };
    struct ssh_server_callbacks_struct cb = {
        .userdata = &userdata,
        .auth_password_function = auth_password,
	.service_request_function = service_request,
        .channel_open_request_session_function = new_session_channel
    };

    char buf[2048];
    int i;
    int r;

    if(ssh_bind_listen(sshbind)<0){
        printf("Error listening to socket: %s\n",ssh_get_error(sshbind));
        return 1;
    }

    session=ssh_new();
    printf("Waiting for session ...\n");
    r=ssh_bind_accept(sshbind,session);
    if(r==SSH_ERROR){
        printf("error accepting a connection : %s\n",ssh_get_error(sshbind));
        return 1;
    }
    ssh_callbacks_init(&cb);
    ssh_set_server_callbacks(session, &cb);

    printf("Starting key exchange ...\n");
    if (ssh_handle_key_exchange(session)) {
        printf("ssh_handle_key_exchange: %s\n", ssh_get_error(session));
        return 1;
    }
    ssh_set_auth_methods(session,SSH_AUTH_METHOD_PASSWORD);

    printf("Starting main loop ...\n");
    mainloop = ssh_event_new();
    ssh_event_add_session(mainloop, session);

    while (!(authenticated && userdata.channel != NULL)){
        if(error)
            break;
        r = ssh_event_dopoll(mainloop, -1);
        if (r==SSH_ERROR){
            printf("Error : %s\n",ssh_get_error(session));
            ssh_disconnect(session);
	    ssh_event_remove_session(mainloop, session);
            return 1;
        }
    }
    if(error){
        printf("Error, exiting loop\n");
    } else
        printf("Authenticated and got a channel\n");

    do{
        i=ssh_channel_read(userdata.channel, buf, 2048, 0);
        if(i>0) {
            ssh_channel_write(userdata.channel, buf, i);
            if (write(1,buf,i) < 0) {
                printf("error writing to buffer\n");
                return 1;
            }
            if (buf[0] == '\x0d') {
                if (write(1, "\n", 1) < 0) {
                    printf("error writing to buffer\n");
                    return 1;
                }
                ssh_channel_write(userdata.channel, "\n", 1);
            }
        }
    } while (i>0);

    ssh_disconnect(session);
    ssh_free(session);
    ssh_event_free(mainloop);

    return 0;
}

int main(int argc, char **argv){
    ssh_bind sshbind;

    ssh_init();

    sshbind=ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "ssh_host_dsa_key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");

#ifdef HAVE_ARGP_H
    /*
     * Parse our arguments; every option seen by parse_opt will
     * be reflected in arguments.
     */
    argp_parse (&argp, argc, argv, 0, 0, sshbind);
#else
    (void) argc;
    (void) argv;
#endif
    serve_one(sshbind);
    ssh_bind_free(sshbind);

    ssh_finalize();

    return 0;
}

