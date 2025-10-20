#ifndef _EVENT_H
#define _EVENT_H

enum state
{
    STATE_INIT,
    STATE_SEARCHING,
    STATE_CONNECTING,
    STATE_CONNECTED,
    STATE_READY,
    STATE_PLAYING,
    STATE_MAX
};

enum event
{
    EVENT_ENABLE,
    EVENT_SEARCH,
    EVENT_FOUND,
    EVENT_RESET,
    EVENT_CONNECTED,
    EVENT_TIMEOUT,
    EVENT_PLAY,
    EVENT_STOP,
    EVENT_MAX
};

typedef void (action_f) (void *data);

struct action
{
    action_f *func;
    int new_state;
};

char *state_str (int state);
char *event_str (int event);

void action_search (void *data);
void action_connect (void *data);
void action_status (void *data);

void event (int event, void *data);

#endif
