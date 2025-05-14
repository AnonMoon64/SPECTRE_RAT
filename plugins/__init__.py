# plugins/__init__.py
import os
import importlib
from .base_plugin import BasePlugin

def load_plugins(parent):
    plugins = []
    plugin_dir = os.path.dirname(__file__)
    for filename in os.listdir(plugin_dir):
        if filename.endswith('.py') and filename != '__init__.py' and filename != 'base_plugin.py':
            module_name = filename[:-3]  # Remove .py
            module = importlib.import_module(f".{module_name}", package='plugins')
            for attr in dir(module):
                obj = getattr(module, attr)
                if isinstance(obj, type) and issubclass(obj, BasePlugin) and obj != BasePlugin:
                    plugins.append(obj(parent))
    # Sort plugins by priority (descending, so higher priority is at the top)
    plugins.sort(key=lambda p: p.priority, reverse=True)
    return plugins