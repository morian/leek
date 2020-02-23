#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
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


/* stdin + evenfd + timerfd */
#define LEEK_TERMINAL_POLL_COUNT     3

static int leek_terminal_poll(int timer_fd)
{
	struct pollfd pfds[LEEK_TERMINAL_POLL_COUNT];
	int ret;

	/* stdin is our first polled fd */
	pfds[0].fd = (leek.terminal.flags & LEEK_TERMINAL_IS_TTY)
	           ? STDIN_FILENO : -1;
	pfds[0].events = POLLIN;

	/* eventfd is our second polled fd */
	pfds[1].fd = leek.terminal.efd;
	pfds[1].events = POLLIN;

	/* timerfd (if applicable) is our last polled fd */
	pfds[2].fd = timer_fd;
	pfds[2].events = POLLIN;

	/* Main terminal thread is now running */
	__sync_fetch_and_or(&leek.terminal.flags, LEEK_TERMINAL_FLAGS_RUNNING);

	while (leek.terminal.flags & LEEK_TERMINAL_FLAGS_RUNNING) {
		leek_terminal_prompt_show();
		ret = poll(pfds, LEEK_TERMINAL_POLL_COUNT, -1);
		leek_terminal_prompt_clear();

		if (ret < 0) {
			if (errno == EINTR)
				continue;

			fprintf(stderr, "error: poll: %s\n", strerror(errno));
			goto out;
		}

		if (pfds[0].revents & POLLIN) {
			ret = leek_terminal_handle_stdin();
			if (ret < 0)
				goto out;
		}

		if (pfds[1].revents & POLLIN) {
			ret = leek_terminal_handle_event();
			if (ret < 0)
				goto out;
		}

		if (pfds[2].revents & POLLIN) {
			printf("[+] Exiting because duration timer expired.\n");
			__sync_and_and_fetch(&leek.terminal.flags, ~LEEK_TERMINAL_FLAGS_RUNNING);
		}
	}

	ret = 0;
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
		goto out;
	}

	ret = timer_fd;
out:
	return ret;
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
		goto out;
	}

	ret = sigaction(SIGINT, &sigint_act, NULL);
	if (ret < 0) {
		fprintf(stderr, "error: sigaction: %s\n", strerror(errno));
		goto out;
	}

	ret = sigaction(SIGTERM, &sigterm_act, NULL);
	if (ret < 0) {
		fprintf(stderr, "error: sigaction: %s\n", strerror(errno));
		goto out;
	}

out:
	return ret;
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


int leek_terminal_runner(void)
{
	int timer_fd = -1;
	int ret;

	ret = leek_terminal_set();
	if (ret < 0)
		goto out;

	ret = leek_signal_setup();
	if (ret < 0)
		goto term_restore;

	if (leek.options.duration) {
		ret = leek_terminal_timer(leek.options.duration);
		if (ret < 0)
			goto sig_restore;
		timer_fd = ret;
	}

	ret = leek_terminal_poll(timer_fd);

	if (timer_fd >= 0)
		close(timer_fd);
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
