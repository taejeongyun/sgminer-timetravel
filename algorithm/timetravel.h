#ifndef TIMETRAVEL_H
#define TIMETRAVEL_H

#include "miner.h"

extern int timetravel_test(unsigned char *pdata, const unsigned char *ptarget,	uint32_t nonce);
extern void timetravel_regenhash(struct work *work);
extern void timetravel_twisted_code(char *result, char *ntime, char *code);

#endif /* TIMETRAVEL_H */
