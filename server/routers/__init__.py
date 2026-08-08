"""
server.routers – HTTP layer, one Flask blueprint per concern.

Blueprints hold request parsing, auth decoration, and response shaping only;
detection, scoring, persistence, and delivery live in their own packages.
:data:`ALL_BLUEPRINTS` is the single list :func:`server.app.create_app`
registers, so adding an endpoint group means adding it here and nowhere else.

Note for maintainers: modules here reference *modules* rather than importing
names directly (``from server.detection import rules`` then ``rules.evaluate``,
not ``from server.detection.rules import evaluate``).  The test suite calls
``importlib.reload`` on config-bearing modules between tests; module-level
attribute lookup resolves through the reloaded module dict, whereas a directly
imported name would stay bound to the pre-reload object.
"""

from server.routers.admin import admin_bp
from server.routers.alerts import alerts_bp
from server.routers.analytics import analytics_bp
from server.routers.anchor import anchor_bp
from server.routers.audit import audit_bp
from server.routers.events import events_bp
from server.routers.integrity import integrity_bp
from server.routers.system import system_bp

ALL_BLUEPRINTS = (
    events_bp,
    alerts_bp,
    audit_bp,
    anchor_bp,
    analytics_bp,
    integrity_bp,
    admin_bp,
    system_bp,
)

__all__ = ["ALL_BLUEPRINTS"]
