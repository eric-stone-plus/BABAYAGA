# lab/ — loopback fixtures

`http_get_lab.py`: basic-auth HTTP server on 127.0.0.1 with simulated
lockout (5 fails → X-Lab-Lockout until reset). Demo principals: labuser1
(guessable), labuser2 (never valid). Synthetic material only.

Run standalone: `python3 engine/lab/http_get_lab.py [port]` (default 8080;
port 0 = ephemeral). Once the listen socket is live the fixture prints one
readiness line to stdout, `127.0.0.1 <port>`; `babayaga run --lab` spawns it
as a subprocess and reads that line to learn the port (core/run.py).

`demo_passwords.json`: the v0 lab candidate list (obviously synthetic;
labuser1's password last, so a full run exercises valid, invalid, and — via
`-f` early exit — the unknown-outcome policy in one pass).

Instrument note: hydra builds frequently ship without ssh support (no
libssh) — http-get is the demo protocol on purpose.
