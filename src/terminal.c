#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/ttydefaults.h>
#include <unistd.h>

#include "leek.h"


static int leek_terminal_restore(void)
{
	int ret;

	if (leek.terminal.flags & LEEK_TERMINAL_IS_TTY) {
		ret = tcsetattr(STDIN_FILENO, TCSADRAIN, &leek.terminal.saved);
		if (ret < 0) {
			fprintf(stderr, "error: tcsetattr: %s\n", strerror(errno));
			goto out;
		}
	}

	ret = 0;
out:
	return ret;
}


static int leek_terminal_set(void)
{
	struct termios term_modified;
	int ret;

	ret = isatty(STDIN_FILENO);
	if (ret) {
		__sync_fetch_and_or(&leek.terminal.flags, LEEK_TERMINAL_IS_TTY);

		ret = tcgetattr(STDIN_FILENO, &leek.terminal.saved);
		if (ret < 0) {
			fprintf(stderr, "error: tcgetattr: %s\n", strerror(errno));
			goto out;
		}

		term_modified = leek.terminal.saved;
		term_modified.c_lflag &= ~(ICANON | ECHO);
		term_modified.c_cc[VMIN] = 1;
		term_modified.c_cc[VTIME] = 0;

		ret = tcsetattr(STDIN_FILENO, TCSANOW, &term_modified);
		if (ret < 0) {
			fprintf(stderr, "error: tcsetattr: %s\n", strerror(errno));
			goto out;
		}
	}

out:
	return ret;
}


static void leek_terminal_prompt_show(void)
{
	int length = 0;

	if (leek.terminal.flags & LEEK_TERMINAL_IS_TTY) {
		length += printf("[h]elp [s]tatus ");

		if (leek.stats.successes)
			length += printf("[f]ound ");
		length += printf("[q]uit => ");
	}
	else
		length += printf("[+] Running in non-interactive mode (hit Ctrl-C to quit)");

	fflush(stdout);
	leek.terminal.clean_len = length;
}


static void leek_terminal_prompt_clear(void)
{
	printf("\r%*s", leek.terminal.clean_len, "\r");
	fflush(stdout);
}


static void leek_terminal_usage_display(void)
{
	printf("[+] Terminal usage:\n");
	printf("> f   show last results.\n");
	printf("> F   show last results with detailed keys.\n");
	printf("> s   show attack status summary.\n");
	printf("> S   show detailed attack status.\n");
	printf("> q   quit leek (finishes current runs).\n");
	printf("> h   show this help menu.\n");
	printf("\n");
}


static int leek_terminal_handle_stdin(void)
{
	int c = getchar();
	int verbose = 0;

	switch (c) {
		case CEOF:
		case 'q':
			printf("[+] Exit requested received from terminal input.\n");
			__sync_and_and_fetch(&leek.terminal.flags, ~LEEK_TERMINAL_FLAGS_RUNNING);
			break;

		case 'S':
			verbose = 1;
		/* fall-through */
		case 's':
			leek_status_display(verbose);
			break;

		case 'h':
		case '?':
			leek_terminal_usage_display();
			break;

		case 'F':
			verbose = 1;
		/* fall-through */
		case 'f':
			leek_result_found_display(verbose);
			break;
	}

	return 0;
}


static int leek_terminal_handle_event(void)
{
	bool verbose = !!(leek.options.flags & LEEK_OPTION_VERBOSE);
	unsigned int events;
	eventfd_t counter;
	int ret;

	ret = eventfd_read(leek.terminal.efd, &counter);
	if (ret < 0) {
		fprintf(stderr, "error: eventfd_read: %s\n", strerror(errno));
		goto out;
	}
	events = (leek.terminal.flags & LEEK_EVENTS_ALL);

	/* Consider all events as handled */
	__sync_and_and_fetch(&leek.terminal.flags, ~events);

	if (events & LEEK_EVENT_NEW_RESULT) {
		if (leek.options.flags & LEEK_OPTION_SHOW_RESULTS)
			leek_result_new_display(verbose);

		if (leek.options.flags & LEEK_OPTION_STOP) {
			if (leek.stats.successes >= leek.options.stop_count) {
				printf("[+] Exit triggered by reaching --stop option.\n");
				__sync_and_and_fetch(&leek.terminal.flags, ~LEEK_TERMINAL_FLAGS_RUNNING);
			}
		}
	}

	if (events & LEEK_EVENT_SHOW_RESULTS)
		leek_result_found_display(true);

	if (events & LEEK_EVENT_EXIT_REQUEST) {
		printf("[+] Exit requested received from process signal.\n");
		__sync_and_and_fetch(&leek.terminal.flags, ~LEEK_TERMINAL_FLAGS_RUNNING);
	}

	ret = 0;
out:
	return ret;
}

static int leek_terminal_handle_timeout(void)
{
	printf("[+] Exiting because duration timer expired.\n");
	__sync_and_and_fetch(&leek.terminal.flags, ~LEEK_TERMINAL_FLAGS_RUNNING);
	return 0;
}

typedef int (*leek_epoll_callback_t)(void);

static int leek_terminal_epoll_add(int epfd, int fd, leek_epoll_callback_t callback)
{
	struct epoll_event event;
	int ret;

	event.events = EPOLLIN;
	event.data.fd = fd;
	event.data.ptr = callback;

	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);
	if (ret < 0)
		fprintf(stderr, "epoll_ctl_add: %s\n", strerror(errno));
	return ret;
}

/* Number of events we are going to handle at the same time.
 * This is fairly not important in our case as the number of events
 * is very very low (except if you choose very small prefix). */
#define LEEK_TERMINAL_LOOP_ENTRIES     4

/* stdin + evenfd + timerfd */
static int leek_terminal_loop(int fd_timeout, int fd_stats)
{
	int epfd;
	int ret;

	ret = epoll_create1(EPOLL_CLOEXEC);
	if (ret < 0)
		goto out;
	epfd = ret;

	/* Add epoll handler for STDIN */
	if (leek.terminal.flags & LEEK_TERMINAL_IS_TTY) {
		ret = leek_terminal_epoll_add(epfd, STDIN_FILENO, leek_terminal_handle_stdin);
		if (ret < 0)
			goto close_epfd;
	}

	/* Add epoll handler for EventFD */
	ret = leek_terminal_epoll_add(epfd, leek.terminal.efd, leek_terminal_handle_event);
	if (ret < 0)
		goto close_epfd;

	/* Add epoll handler for timeout if needed */
	if (fd_timeout >= 0) {
		ret = leek_terminal_epoll_add(epfd, fd_timeout, leek_terminal_handle_timeout);
		if (ret < 0)
			goto close_epfd;
	}

	/* Main terminal thread is now running */
	__sync_fetch_and_or(&leek.terminal.flags, LEEK_TERMINAL_FLAGS_RUNNING);

	while (leek.terminal.flags & LEEK_TERMINAL_FLAGS_RUNNING) {
		leek_epoll_callback_t callback;
		struct epoll_event events[LEEK_TERMINAL_LOOP_ENTRIES];

		leek_terminal_prompt_show();
		ret = epoll_wait(epfd, events, LEEK_TERMINAL_LOOP_ENTRIES, -1);
		leek_terminal_prompt_clear();

		if (ret < 0) {
			if (errno == EINTR)
				continue;

			fprintf(stderr, "error: epoll: %s\n", strerror(errno));
			goto close_epfd;
		}

		for (int i = 0; i < ret; ++i) {
			callback = events[i].data.ptr;

			/* Any error in any callback is considered fatal for
			 * the application. While dangerous it helps to ensure
			 * that we will not work in weird conditions. */
			ret = callback();
			if (ret < 0)
				goto close_epfd;
		}
	}

	ret = 0;
close_epfd:
	close(epfd);
out:
	return ret;
}


static int leek_terminal_timer(unsigned long duration)
{
	struct itimerspec its;
	int timer_fd;
	int ret;

	ret = timerfd_create(CLOCK_MONOTONIC, 0);
	if (ret < 0) {
		fprintf(stderr, "error: timerfd_create: %s\n", strerror(errno));
		goto out;
	}
	timer_fd = ret;

	memset(&its, 0, sizeof its);
	its.it_value.tv_sec = duration;
	its.it_value.tv_nsec = 0;

	ret = timerfd_settime(timer_fd, 0, &its, NULL);
	if (ret < 0) {
		fprintf(stderr, "error: timerfd_settime: %s\n", strerror(errno));
		goto error_settime;
	}

	ret = timer_fd;
out:
	return ret;

error_settime:
	close(timer_fd);
	goto out;
}


static void leek_signal_exit_handler(int signal)
{
	leek_events_notify(LEEK_EVENT_EXIT_REQUEST);
	(void) signal;
}


static void leek_signal_result_handler(int signal)
{
	leek_events_notify(LEEK_EVENT_SHOW_RESULTS);
	(void) signal;
}


static int leek_signal_restore(void)
{
	struct sigaction sigrest_act;
	int ret_u;
	int ret_i;
	int ret_t;

	memset(&sigrest_act, 0, sizeof sigrest_act);
	sigrest_act.sa_flags = 0;
	sigrest_act.sa_handler = SIG_DFL;

	ret_u = sigaction(SIGUSR1, &sigrest_act, NULL);
	if (ret_u < 0)
		fprintf(stderr, "error: sigaction: %s\n", strerror(errno));

	ret_i = sigaction(SIGINT, &sigrest_act, NULL);
	if (ret_i < 0)
		fprintf(stderr, "error: sigaction: %s\n", strerror(errno));

	ret_t = sigaction(SIGTERM, &sigrest_act, NULL);
	if (ret_t < 0)
		fprintf(stderr, "error: sigaction: %s\n", strerror(errno));

	return (ret_u < 0 || ret_i < 0 || ret_t < 0) ? -1 : 0;
}


static int leek_signal_setup(void)
{
	struct sigaction sigusr1_act;
	struct sigaction sigterm_act;
	struct sigaction sigint_act;
	int ret;

	memset(&sigusr1_act, 0, sizeof sigterm_act);
	sigusr1_act.sa_flags = 0;
	sigusr1_act.sa_handler = &leek_signal_result_handler;

	memset(&sigterm_act, 0, sizeof sigterm_act);
	sigterm_act.sa_flags = 0;
	sigterm_act.sa_handler = &leek_signal_exit_handler;

	memset(&sigint_act, 0, sizeof sigint_act);
	sigint_act.sa_flags = 0;
	sigint_act.sa_handler = &leek_signal_exit_handler;

	ret = sigaction(SIGUSR1, &sigusr1_act, NULL);
	if (ret < 0) {
		fprintf(stderr, "error: sigaction: %s\n", strerror(errno));
		goto error_sigact;
	}

	ret = sigaction(SIGINT, &sigint_act, NULL);
	if (ret < 0) {
		fprintf(stderr, "error: sigaction: %s\n", strerror(errno));
		goto error_sigact;
	}

	ret = sigaction(SIGTERM, &sigterm_act, NULL);
	if (ret < 0) {
		fprintf(stderr, "error: sigaction: %s\n", strerror(errno));
		goto error_sigact;
	}

out:
	return ret;

error_sigact:
	leek_signal_restore();
	goto out;
}


/**
 * This is the main function after all workers
 * have started and we initialized everything.
 * Nothing is executed after us except for exit
 * handlers.
 */
int leek_terminal_runner(void)
{
	int fd_duration = -1;
	int fd_refresh = -1;
	int ret;

	ret = leek_terminal_set();
	if (ret < 0)
		goto out;

	/* From now terminal is set in canonical mode (if on tty).
	 * Signals are not yet registered so we can leave user
	 * terminal in a bad shape when receiving signals. */

	ret = leek_signal_setup();
	if (ret < 0)
		goto term_restore;

	/* From now we can handle signals and create events on
	 * event fd queue from outside of the process. */

	if (leek.options.duration) {
		/* This timer is used to tell the loop when it should
		 * stops its activities (when set). */
		ret = leek_terminal_timer(leek.options.duration);
		if (ret < 0)
			goto sig_restore;
		fd_duration = ret;
	}

	if (leek.options.refresh) {
		/* This timer is used to tell the loop when it should
		 * display statistics. */
		ret = leek_terminal_timer(leek.options.refresh);
		if (ret < 0)
			goto sig_restore;
		fd_refresh = ret;
	}

	/* This is the main event loop that just waits for signals
	 * from either the sighandler, keyboard, timers or events
	 * from worker threads. */
	ret = leek_terminal_loop(fd_duration, fd_refresh);

	if (fd_duration >= 0)
		close(fd_duration);
	if (fd_refresh >= 0)
		close(fd_refresh);
sig_restore:
	leek_signal_restore();
term_restore:
	/* This error is ignored (but displayed on stderr) */
	leek_terminal_restore();
out:
	return ret;
}


int leek_events_notify(unsigned int flags)
{
	eventfd_t val = 1;
	int ret;

	__sync_fetch_and_or(&leek.terminal.flags, flags);

	ret = eventfd_write(leek.terminal.efd, val);
	if (ret < 0)
		fprintf(stderr, "error: eventfd_write: %s\n", strerror(errno));
	return ret;
}


int leek_events_init(void)
{
	int ret;

	pthread_mutex_init(&leek.terminal.ring.lock, NULL);
	leek.terminal.ring.head = NULL;
	leek.terminal.ring.count = 0;
	leek.terminal.flags = 0;

	ret = eventfd(0, EFD_NONBLOCK);
	if (ret < 0)
		goto out;
	leek.terminal.efd = ret;

out:
	return ret;
}


static void leek_events_late_handle(void)
{
	bool verbose = !!(leek.options.flags & LEEK_OPTION_VERBOSE);
	unsigned int events;

	/* This is the only kind of late event we care about */
	events = (leek.terminal.flags & LEEK_EVENT_NEW_RESULT);

	/* We still clear it just in case this function get called multiple times */
	__sync_and_and_fetch(&leek.terminal.flags, ~events);

	if (events & LEEK_EVENT_NEW_RESULT) {
		printf("\n");
		if (leek.options.flags & LEEK_OPTION_SHOW_RESULTS)
			leek_result_new_display(verbose);
	}
}


void leek_events_exit(void)
{
	/* Check for late results to display here... */
	leek_events_late_handle();
	leek_results_purge();

	if (leek.terminal.efd >= 0)
		close(leek.terminal.efd);
	leek.terminal.efd = -1;
}
