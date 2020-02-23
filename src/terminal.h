#ifndef __LEEK_TERMINAL_H
# define __LEEK_TERMINAL_H
# include <termios.h>
# include "result.h"

/* Number of items to keep on ring (others are deleted) */
# define LEEK_TERMINAL_RING_MAX    32

struct leek_terminal {
	struct termios saved;   /* Saved terminal configuration */
	unsigned int clean_len; /* Last prompt length */
	unsigned int flags;     /* Terminal related flags */
	int efd;                /* EventFD descriptor for notifications */

	/* Ring of results */
	struct {
		struct leek_result *head;   /* Head of the ring */
		unsigned int count;         /* Current number of items */
		pthread_mutex_t lock;       /* Locks operations on the ring */
	} ring;
};

enum {
	/* Main thread is running (keeps this thing running) */
	LEEK_TERMINAL_FLAGS_RUNNING     = (1 <<  0),
	/* Wether stdin is a valid terminal */
	LEEK_TERMINAL_IS_TTY            = (1 <<  1),

	/* We were told to quit somehow */
	LEEK_EVENT_EXIT_REQUEST         = (1 << 16),
	/* We have a new result here */
	LEEK_EVENT_NEW_RESULT           = (1 << 17),
	/* We are told to dump the full list of results */
	LEEK_EVENT_SHOW_RESULTS         = (1 << 18),
	/* We are told to show statistics */
	LEEK_EVENT_SHOW_STATS           = (1 << 19),

	/* All possible events received by the main thread */
	LEEK_EVENTS_ALL                 = 0xffff0000,
};


/* Main monitoring and terminal interaction */
int leek_terminal_runner(void);

/* Open the eventfd descriptor (for event notifications) */
int leek_events_init(void);

/* Close the eventfd descriptor */
void leek_events_exit(void);

/* Send a notification to the main thread */
int leek_events_notify(unsigned int flags);

#endif /* !__LEEK_TERMINAL_H */
