"""Probe package — importing a module registers its probes.

Import order is execution order (the registry preserves insertion order), so
the cheap mechanical surface sweep runs first, adversarial batteries next, and
the rate-limit proofs (which deliberately spend limiter budget, then clear it
via the documented env control) run last.
"""
from . import surfaces          # noqa: F401  mechanical surface reach
from . import infra             # noqa: F401  services / health / env
from . import invariants        # noqa: F401  schema + scoping invariants
from . import auth              # noqa: F401  auth lifecycle + captcha
from . import authz             # noqa: F401  IDOR / roles / CP gates
from . import cp                # noqa: F401  control-plane operator surface
from . import console           # noqa: F401  console SSR
from . import hostile           # noqa: F401  hostile input battery
from . import state             # noqa: F401  replay / races / transitions
from . import errors            # noqa: F401  error taxonomy
from . import mail              # noqa: F401  delivery / templates / DKIM / consent
from . import money             # noqa: F401  billing math
from . import tracking          # noqa: F401  tracking abuse + real click
from . import bots              # noqa: F401  grader / placement / explorer
from . import marketing         # noqa: F401  marketing pages / links
from . import pipeline          # noqa: F401  e2e events / webhooks / unsubscribe
from . import resource          # noqa: F401  rate-limit proofs (last: spends buckets)

__all__ = [
    "surfaces", "infra", "invariants", "auth", "authz", "cp", "console", "hostile",
    "state", "errors", "mail", "money", "tracking", "bots", "marketing",
    "pipeline", "resource",
]
