"""Backend API: serves triage results and the correlation dashboard.

The dashboard renders, it never recomputes (Master Specification 6.2):
every endpoint reads chain documents from this process's triage service
or from the Elastic results index (the source of truth) and the timeline
and 3D-graph views are pure reshapes of those documents.
"""
