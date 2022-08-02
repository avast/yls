# pylint: disable=unused-argument

from __future__ import annotations

import logging

import yaramod

from yls.plugin_manager_provider import PluginManagerProvider

log = logging.getLogger(__name__)


class YaramodProvider:
    """Singleton class providing Yaramod parser object."""

    ymod = None

    @classmethod
    def instance(cls) -> yaramod.Yaramod:
        """Return singleton instance."""
        if cls.ymod is None:
            cls.ymod = PluginManagerProvider.instance().hook.create_yaramod_instance()
        return cls.ymod
