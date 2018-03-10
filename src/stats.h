#ifndef __LEEK_STATS_H
# define __LEEK_STATS_H

struct leek_stats {
	long double proba_one;        /* One hash to have a success */
};


/** Probability computations **/
/* Update probability statistics (to do after lookup length is chosen). */
void leek_stats_proba_update(void);


#endif /* !__LEEK_STATS_H */
