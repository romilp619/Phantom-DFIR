"""PHANTOM AI Safety — evidence-grounded, adversarially resilient forensic reasoning.

Additive layer over the upstream PHANTOM DFIR project. The upstream clone is never
modified: this package imports its verification code, exposes a harness that runs
it without forensic tooling, and adds the safety, red-team and evaluation modules
used for the Lexsi Track 2 submission.
"""

__version__ = "0.1.0"