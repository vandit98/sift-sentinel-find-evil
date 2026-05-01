# Demo Evidence

This fixture is synthetic and safe to redistribute. It is shaped like common
SIFT outputs after parsing memory, Windows execution artifacts, event logs, and
registry autoruns. It is intentionally small so judges can run the autonomous
loop without downloading a multi-gigabyte image.

The important design choice: the agent treats these CSV files as read-only
evidence and writes all generated manifests, logs, reports, and benchmark scores
under `outputs/`.

