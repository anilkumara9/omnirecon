from functools import wraps

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        return fn(*a, **kw)
    return wrapper
