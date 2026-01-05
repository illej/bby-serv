#ifndef _EVENT_H
#define _EVENT_H

enum state
{
    STATE_INIT,
    STATE_CONNECTING,
    STATE_CONNECTED,
    STATE_READY,
    STATE_CONTROLLING,
    STATE_LOADING,
    STATE_PLAYING,
    STATE_MAX
};

enum event
{
    EVENT_FOUND,
    EVENT_RESET,
    EVENT_CONNECTED,
    EVENT_LAUNCH,
    EVENT_LOAD,
    EVENT_LOADED,
    EVENT_PLAY,
    EVENT_STOP,
    EVENT_UPDATE,
    EVENT_MAX
};

typedef void (action_f) (void *data);

struct action
{
    action_f *func;
    int new_state;
};

static char *
state_str (int state)
{
    char *str;

    switch (state)
    {
        case STATE_INIT:        { str = "INIT";        } break;
        case STATE_CONNECTING:  { str = "CONNECTING";  } break;
        case STATE_CONNECTED:   { str = "CONNECTED";   } break;
        case STATE_READY:       { str = "READY";       } break;
        case STATE_CONTROLLING: { str = "CONTROLLING"; } break;
        case STATE_LOADING:     { str = "LOADING";     } break;
        case STATE_PLAYING:     { str = "PLAYING";     } break;
        default:                { str = "??";          } break;
    }

    return str;
}

static char *
event_str (int event)
{
    char *str;

    switch (event)
    {
        case EVENT_FOUND:     { str = "FOUND";     } break;
        case EVENT_RESET:     { str = "RESET";     } break;
        case EVENT_CONNECTED: { str = "CONNECTED"; } break;
        case EVENT_LAUNCH:    { str = "LAUNCH";    } break;
        case EVENT_LOAD:      { str = "LOAD";      } break;
        case EVENT_LOADED:    { str = "LOADED";    } break;
        case EVENT_PLAY:      { str = "PLAY";      } break;
        case EVENT_STOP:      { str = "STOP";      } break;
        case EVENT_UPDATE:    { str = "UPDATE";    } break;
        default:              { str = "??";        } break;
    }

    return str;
}

void action_search (void *data);
void action_connect (void *data);
void action_status (void *data);
void action_launch (void *data);
void action_load (void *data);
void action_play (void *data);
void action_reset (void *data);
void action_update (void *data);

void event (int event, void *data);

#endif
