#ifndef NORT_CONTROL_H
#define NORT_CONTROL_H

#include "nort_nostr.h"

typedef struct nort_control_srv nort_control_srv_t;

int nort_control_start(const char *socket_path, nort_agent_t *agent, nort_control_srv_t **out_srv);
void nort_control_stop(nort_control_srv_t *srv);

#endif
