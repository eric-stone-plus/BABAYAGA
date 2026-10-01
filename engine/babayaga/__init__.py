"""BABAYAGA — authorized-only credential-attack engine (lab-only v0).

This package is the engine core. The opencode plugin (engine/host/opencode/)
is a thin control plane that shells out to the `babayaga` CLI; it must never
re-implement gate semantics.
"""

__version__ = "0.0.1"

LAB_ONLY = True

# Boundary A exit-code contract:
#   0 = ok, 2 = refusal (gate/validation), 1 = unexpected failure
EXIT_OK = 0
EXIT_REFUSAL = 2
EXIT_ERROR = 1
