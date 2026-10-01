from dataclasses import dataclass

@dataclass
class Event:
    AUTH_SUCCESS = 'auth.success'
    AUTH_FAILED_CREDENTIAL = 'auth.failed_credential'
    AUTH_ERROR = 'auth.error'
    AUTH_ACCESS_DENIED = 'auth.access_denied'
    AUTH_LOGGED_OUT = "auth.logged_out"
    SHED_CANCELLED_ERROR = 'scheduler.cancelled_error'
    SHED_EXCEPTION = 'scheduler.exception'
    SHED_PARAM_CONNECT = 'scheduler.param_connect'
    SHED_FORMATION_TASK = 'scheduler.formation_task'