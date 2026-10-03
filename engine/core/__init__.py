"""BABAYAGA — the authorized-only phase-2 operator (RE, lateral, spend).

This package is the engine core. The opencode plugin (engine/scripts/)
is a thin control plane that shells out to the `babayaga` CLI; it must never
re-implement gate semantics.
"""

__version__ = "0.0.1"

LAB_ONLY = False

# Boundary A exit-code contract:
#   0 = ok, 2 = refusal (gate/validation), 1 = unexpected failure
EXIT_OK = 0
EXIT_REFUSAL = 2
EXIT_ERROR = 1
