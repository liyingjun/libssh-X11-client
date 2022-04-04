/*
 * ssh.c - Simple example of SSH X11 client using libssh
 *
 * Copyright (C) 2022 Marco Fortina
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <sys/time.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <time.h>


/*
 * Data Structures and Macros
*/

#define _PATH_UNIX_X 	"/tmp/.X11-unix/X%d"
#define _XAUTH_CMD	"/usr/bin/xauth list %s 2>/dev/null"

typedef struct item {
	ssh_channel channel;
	int fd_in;
	int fd_out;
	struct item *next;
} node_t;

node_t *node = NULL;


/*
 * Mutex
*/

pthread_mutex_t mutex;


/*
 * Function declarations
*/

// Linked nodes to manage channel/fd tuples
static void insert_item(ssh_channel channel, int fd_in, int fd_out);
static void delete_item(ssh_channel channel);
static node_t * search_item(ssh_channel channel);

// X11 Display
const char * ssh_gai_strerror(int gaierr);
static int x11_get_proto(const char *display, char **_proto, char **_data);
static void set_nodelay(int fd);
static int connect_local_xsocket_path(const char *pathname);
static int connect_local_xsocket(int display_number);
static int x11_connect_display();

// Send data to channel
static int copy_fd_to_channel_callback(int fd, int revents, void *userdata);

// Read data from channel
static int copy_channel_to_fd_callback(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata);

// EOF&Close channel
static void channel_close_callback(ssh_session session, ssh_channel channel, void *userdata);

// X11 Request
static ssh_channel x11_open_request_callback(ssh_session session, const char *shost, int sport, void *userdata);

// Main loop
static int main_loop(ssh_channel channel);


/*
 * Callbacks Data Structures
*/

// SSH Channel Callbacks
struct ssh_channel_callbacks_struct channel_cb =
{
	.channel_data_function = copy_channel_to_fd_callback,
	.channel_eof_function = channel_close_callback,
	.channel_close_function = channel_close_callback,
	.userdata = NULL
};

// SSH Callbacks
struct ssh_callbacks_struct cb =
{
	.channel_open_request_x11_function = x11_open_request_callback,
	.userdata = NULL
};


/*
 * SSH Event Context
*/

short events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;
ssh_event event;


/*
 * Internal data structures
*/

struct termios _saved_tio;


/*
 * Internal functions
*/

int64_t
_current_timestamp() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	int64_t milliseconds = (int64_t)(tv.tv_sec) * 1000 + (tv.tv_usec / 1000);
	return milliseconds;
}

static void
_logging_callback(int priority, const char *function, const char *buffer, void *userdata)
{
	FILE *fp;
	char buf[100];
	time_t now = time (0);

	strftime(buf, 100, "%Y-%m-%d %H:%M:%S", localtime (&now));

	fp = fopen("debug.log","a");
	if(fp == NULL)
	{
		printf("Error!");
		exit(-11);
	}

	int64_t milliseconds = _current_timestamp();

	fprintf(fp, "[%s.%jd, %d] %s: %s\n", buf, milliseconds, priority, function, buffer);
	fclose(fp);
}

static int
_enter_term_raw_mode(void)
{
	struct termios tio;
	int ret = tcgetattr(fileno(stdin), &tio);
	if (ret != -1) {
		_saved_tio = tio;
		tio.c_iflag |= IGNPAR;
		tio.c_iflag &= ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
		tio.c_iflag &= ~IUCLC;
		tio.c_lflag &= ~(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL);
		tio.c_lflag &= ~IEXTEN;
		tio.c_oflag &= ~OPOST;
		tio.c_cc[VMIN] = 1;
		tio.c_cc[VTIME] = 0;
		ret = tcsetattr(fileno(stdin), TCSADRAIN, &tio);
	}
	return ret;
}

static int
_leave_term_raw_mode(void)
{
	int ret = tcsetattr(fileno(stdin), TCSADRAIN, &_saved_tio);
	return ret;
}


/*
 * Functions
*/

static void
insert_item(ssh_channel channel, int fd_in, int fd_out)
{
	pthread_mutex_lock(&mutex);

	node_t *node_iterator, *new;
	if (node == NULL) {
		/* Calloc ensure that node is full of 0 */
		node = (node_t *) calloc(1, sizeof(node_t));
		node->channel = channel;
		node->fd_in = fd_in;
		node->fd_out = fd_out;
		node->next = NULL;
	} else {
		node_iterator = node;
		while (node_iterator->next != NULL)
			node_iterator = node_iterator->next;
		/* Create the new node */
		new = (node_t *) malloc(sizeof(node_t));
		new->channel = channel;
		new->fd_in = fd_in;
		new->fd_out = fd_out;
		new->next = NULL;
		node_iterator->next = new;

	}

	pthread_mutex_unlock(&mutex);
}


static void
delete_item(ssh_channel channel)
{
	pthread_mutex_lock(&mutex);

	node_t *current, *previous = NULL;
	for (current = node; current; previous = current, current = current->next) {
		if (current->channel != channel)
			continue;

		if (previous == NULL)
			node = current->next;
		else
			previous->next = current->next;

		free(current);
		pthread_mutex_unlock(&mutex);
		return;
	}

	pthread_mutex_unlock(&mutex);
}


static node_t *
search_item(ssh_channel channel)
{
	pthread_mutex_lock(&mutex);

	node_t *current = node;
	while (current != NULL) {
		if (current->channel == channel) {
			pthread_mutex_unlock(&mutex);
			return current;
		} else {
			current = current->next;
		}
	}

	pthread_mutex_unlock(&mutex);

	return NULL;
}



static void
set_nodelay(int fd)
{
	int opt;
	socklen_t optlen;

	optlen = sizeof(opt);
	if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen) == -1) {
		_ssh_log(SSH_LOG_FUNCTIONS, __func__, "getsockopt TCP_NODELAY: %.100s", strerror(errno));
		return;
	}
	if (opt == 1) {
		_ssh_log(SSH_LOG_FUNCTIONS, __func__, "fd %d is TCP_NODELAY", fd);
		return;
	}
	opt = 1;
	_ssh_log(SSH_LOG_FUNCTIONS, __func__, "fd %d setting TCP_NODELAY", fd);
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) == -1)
		_ssh_log(SSH_LOG_FUNCTIONS, __func__, "setsockopt TCP_NODELAY: %.100s", strerror(errno));
}


const char *
ssh_gai_strerror(int gaierr)
{
	if (gaierr == EAI_SYSTEM && errno != 0)
		return strerror(errno);
	return gai_strerror(gaierr);
}



static int
x11_get_proto(const char *display, char **_proto, char **_cookie)
{
	char cmd[256], line[512], xdisplay[512];
	static char proto[512], cookie[512];
	FILE *f;
	int ret = 0, r;

	*_proto = proto;
	*_cookie = cookie;

	proto[0] = cookie[0] = '\0';

	if (strncmp(display, "localhost:", 10) == 0) {
		if ((r = snprintf(xdisplay, sizeof(xdisplay), "unix:%s", display + 10)) < 0 || (size_t)r >= sizeof(xdisplay)) {
			_ssh_log(SSH_LOG_FUNCTIONS, __func__, "display name too long. display: %s", display);
			return -1;
		}
		display = xdisplay;
	}

	snprintf(cmd, sizeof(cmd), _XAUTH_CMD, display);
	_ssh_log(SSH_LOG_FUNCTIONS, __func__, "xauth cmd: %s", cmd);

	f = popen(cmd, "r");
	if (f && fgets(line, sizeof(line), f) && sscanf(line, "%*s %511s %511s", proto, cookie) == 2) {
		ret = 0;
	} else {
		ret = 1;
	}

	if (f) pclose(f);

	_ssh_log(SSH_LOG_FUNCTIONS, __func__, "proto: %s - cookie: %s - ret: %d", proto, cookie, ret);

	return ret;
}

static int
connect_local_xsocket_path(const char *pathname)
{
	int sock;
	struct sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1)
		_ssh_log(SSH_LOG_FUNCTIONS, __func__, "socket: %.100s", strerror(errno));
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	addr.sun_path[0] = '\0';
	strncpy(addr.sun_path + 1, pathname, strlen(pathname));
	if (connect(sock, (struct sockaddr *)&addr, offsetof(struct sockaddr_un, sun_path) + 1 + strlen(pathname)) == 0)
		return sock;
	close(sock);
	_ssh_log(SSH_LOG_FUNCTIONS, __func__, "connect %.100s: %.100s", addr.sun_path, strerror(errno));
	return -1;
}


static int
connect_local_xsocket(int display_number)
{
	char buf[1024];
	snprintf(buf, sizeof(buf), _PATH_UNIX_X, display_number);
	return connect_local_xsocket_path(buf);
}


static int
x11_connect_display()
{
	int display_number;
	const char *display;
	char buf[1024], *cp;
	struct addrinfo hints, *ai, *aitop;
	char strport[NI_MAXSERV];
	int gaierr, sock = 0;

	/* Try to open a socket for the local X server. */
	display = getenv("DISPLAY");
	if (!display) {
		return -1;
	}

	_ssh_log(SSH_LOG_FUNCTIONS, __func__, "display: %s", display);

	/* Check if it is a unix domain socket. */
	if (strncmp(display, "unix:", 5) == 0 || display[0] == ':') {
		/* Connect to the unix domain socket. */
		if (sscanf(strrchr(display, ':') + 1, "%u", &display_number) != 1) {
			_ssh_log(SSH_LOG_FUNCTIONS, __func__, "Could not parse display number from DISPLAY: %.100s", display);
			return -1;
		}

		_ssh_log(SSH_LOG_FUNCTIONS, __func__, "display_number: %d", display_number);

		/* Create a socket. */
		sock = connect_local_xsocket(display_number);

		_ssh_log(SSH_LOG_FUNCTIONS, __func__, "socket: %d", sock);

		if (sock < 0)
			return -1;

		/* OK, we now have a connection to the display. */
		return sock;
	}

	/* Connect to an inet socket. */
	strncpy(buf, display, sizeof(buf));
	cp = strchr(buf, ':');
	if (!cp) {
		_ssh_log(SSH_LOG_FUNCTIONS, __func__, "Could not find ':' in DISPLAY: %.100s", display);
		return -1;
	}
	*cp = 0;
	if (sscanf(cp + 1, "%u", &display_number) != 1) {
		_ssh_log(SSH_LOG_FUNCTIONS, __func__, "Could not parse display number from DISPLAY: %.100s", display);
		return -1;
	}

	/* Look up the host address */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, sizeof(strport), "%u", 6000 + display_number);
	if ((gaierr = getaddrinfo(buf, strport, &hints, &aitop)) != 0) {
		_ssh_log(SSH_LOG_FUNCTIONS, __func__, "%.100s: unknown host. (%s)", buf, ssh_gai_strerror(gaierr));
		return -1;
	}
	for (ai = aitop; ai; ai = ai->ai_next) {
		/* Create a socket. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock == -1) {
			_ssh_log(SSH_LOG_FUNCTIONS, __func__, "socket: %.100s", strerror(errno));
			continue;
		}
		/* Connect it to the display. */
		if (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			_ssh_log(SSH_LOG_FUNCTIONS, __func__, "connect %.100s port %u: %.100s", buf, 6000 + display_number, strerror(errno));
			close(sock);
			continue;
		}
		/* Success */
		break;
	}
	freeaddrinfo(aitop);
	if (!ai) {
		_ssh_log(SSH_LOG_FUNCTIONS, __func__, "connect %.100s port %u: %.100s", buf, 6000 + display_number, strerror(errno));
		return -1;
	}
	set_nodelay(sock);
	return sock;
}



static int
copy_fd_to_channel_callback(int fd, int revents, void *userdata)
{
	ssh_channel channel = (ssh_channel)userdata;
	char buf[2097152];
	int sz, ret = 0;

	_ssh_log(SSH_LOG_FUNCTIONS, __func__, "event: %d - fd: %d", revents, fd);

	if (!channel) {
		_ssh_log(SSH_LOG_FUNCTIONS, __func__, "channel does not exist.");
		close(fd);
		return -1;
	}

	if (fcntl(fd, F_GETFD) == -1) {
		_ssh_log(SSH_LOG_FUNCTIONS, __func__, "fcntl error. fd: %d", fd);
		ssh_channel_close(channel);
		return -1;
	}

	if ((revents & POLLIN) || (revents & POLLPRI)) {
		sz = read(fd, buf, sizeof(buf));
		_ssh_log(SSH_LOG_FUNCTIONS, __func__, "sz: %d", sz);
		if (sz > 0) {
			ret = ssh_channel_write(channel, buf, sz);
			_ssh_log(SSH_LOG_FUNCTIONS, __func__, "channel_write ret: %d", ret);
		} else if (sz < 0) {
			ssh_channel_close(channel);
			return -1;
		} else {
			/* sz = 0. Why the hell I'm here? */
			_ssh_log(SSH_LOG_FUNCTIONS, __func__, "Why the hell I'm here?: sz: %d", sz);
			close(fd);
			return -1;
		}
	}

	if ((revents & POLLHUP) || (revents & POLLNVAL) || (revents & POLLERR)) {
		ssh_channel_close(channel);
		return -1;
	}

	return sz;
}


static int
copy_channel_to_fd_callback(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata)
{
	(void)session;
	(void)is_stderr;
	(void)userdata;

	node_t *temp_node = search_item(channel);
	int fd = temp_node->fd_out;
	int sz;

	_ssh_log(SSH_LOG_FUNCTIONS, __func__, "len: %d - fd: %d - is_stderr: %d", len, fd, is_stderr);

	sz = write(fd, data, len);

	return sz;
}


static void
channel_close_callback(ssh_session session, ssh_channel channel, void *userdata)
{
	(void)session;
	(void)userdata;

	node_t *temp_node = search_item(channel);

	if (temp_node != NULL) {
		int fd = temp_node->fd_in;

		_ssh_log(SSH_LOG_FUNCTIONS, __func__, "fd: %d", fd);

		delete_item(channel);
		ssh_event_remove_fd(event, fd);

		if (fd !=0) {
			close(fd);
		}
	}
}


static ssh_channel
x11_open_request_callback(ssh_session session, const char *shost, int sport, void *userdata)
{
	(void)shost;
	(void)sport;
	(void)userdata;

	ssh_channel channel = ssh_channel_new(session);

	int sock = x11_connect_display();

	_ssh_log(SSH_LOG_FUNCTIONS, __func__, "sock: %d", sock);

	insert_item(channel, sock, sock);

	ssh_event_add_fd(event, sock, events, copy_fd_to_channel_callback, channel);
	ssh_event_add_session(event, session);

	ssh_add_channel_callbacks(channel, &channel_cb);

	return channel;
}



/*
 * MAIN LOOP
*/

static int
main_loop(ssh_channel channel)
{
	ssh_session session = ssh_channel_get_session(channel);

	insert_item(channel, fileno(stdin), fileno(stdout));

	ssh_callbacks_init(&channel_cb);
	ssh_set_channel_callbacks(channel, &channel_cb);

	event = ssh_event_new();
	if (event == NULL) {
		printf("Couldn't get a event\n");
		return -1;
	}

	if (ssh_event_add_fd(event, fileno(stdin), events, copy_fd_to_channel_callback, channel) != SSH_OK) {
		printf("Couldn't add an fd to the event\n");
		return -1;
	}

	if(ssh_event_add_session(event, session) != SSH_OK) {
		printf("Couldn't add the session to the event\n");
		return -1;
	}

	do {
		ssh_event_dopoll(event, 1000);
	} while (!ssh_channel_is_closed(channel));

	delete_item(channel);
	ssh_event_remove_fd(event, fileno(stdin));
	ssh_event_remove_session(event, session);
	ssh_event_free(event);

	return 0;
}


/*
 * MAIN
*/

int main()
{
	ssh_session session;
	char *hostname = "127.0.0.1";
	char *username = "s0n1k";
	char *password;

	const char *compression = "yes";
	int verbosity = SSH_LOG_FUNCTIONS;
	int port = 22;
	int enableX11 = 1; // 0 disabled - 1 enabled
	int ret;

	const char *display;
	char *proto = NULL, *cookie = NULL;

	ssh_set_log_callback(_logging_callback);
	ret = ssh_init();

	session = ssh_new();
	if (session == NULL) exit(-1);

	ssh_options_set(session, SSH_OPTIONS_HOST, hostname);
	ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(session, SSH_OPTIONS_PORT, &port);
	ssh_options_set(session, SSH_OPTIONS_COMPRESSION, &compression);

	ret = ssh_connect(session);
	if (ret != SSH_OK) {
		fprintf(stderr, "Error connecting to %s: %s\n", hostname, ssh_get_error(session));
		exit(-1);
	}

	password = getpass("Password: ");
	ret = ssh_userauth_password(session, username, password);
	if (ret != SSH_AUTH_SUCCESS) {
		fprintf(stderr, "Error authenticating with password: %s\n", ssh_get_error(session));
		exit(-1);
	}

	ssh_channel channel = ssh_channel_new(session);
	if (channel == NULL) return SSH_ERROR;

	ret = ssh_channel_open_session(channel);
	if (ret != SSH_OK) return ret;

	ret = ssh_channel_request_pty(channel);
	if (ret != SSH_OK) return ret;

	ret = ssh_channel_change_pty_size(channel, 80, 24);
	if (ret != SSH_OK) return ret;

	if (enableX11 == 1) {
		ssh_callbacks_init(&cb);
		ssh_set_callbacks(session, &cb);

		display = getenv("DISPLAY");
		if (x11_get_proto(display, &proto, &cookie) != 0) {
			_ssh_log(SSH_LOG_FUNCTIONS, __func__, "Using fake authentication data for X11 forwarding");
			proto = NULL;
			cookie = NULL;
		}

		_ssh_log(SSH_LOG_FUNCTIONS, __func__, "proto: %s - cookie: %s", proto, cookie);
		ret = ssh_channel_request_x11(channel, 0, proto, cookie, 0);
		if (ret != SSH_OK) return ret;
	}

	ret = _enter_term_raw_mode();
	if (ret != 0) exit(-1);

	ret = ssh_channel_request_shell(channel);
	if (ret != SSH_OK) return ret;

	ret = main_loop(channel);
	if (ret != SSH_OK) return ret;

	_leave_term_raw_mode();

	ssh_channel_close(channel);
	ssh_channel_free(channel);
	ssh_disconnect(session);
	ssh_free(session);
	ssh_finalize();
}
