# plugins/__init__.py
import os
import importlib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_plugins(parent):
    plugins = []
    plugin_dir = os.path.dirname(__file__)
    logger.info(f"Scanning plugins directory: {plugin_dir}")
    files_in_dir = os.listdir(plugin_dir)
    logger.info(f"Files in plugins directory: {files_in_dir}")
    for filename in files_in_dir:
        if filename.endswith('.py') and filename not in ['__init__.py', 'base_plugin.py']:
            module_name = filename[:-3]  # Remove .py extension
            logger.info(f"Attempting to load plugin from file: {filename}")
            try:
                module = importlib.import_module(f'plugins.{module_name}')
                # Construct the expected plugin class name by capitalizing each word
                class_name_parts = module_name.split('_')
                plugin_class_name = ''.join(part.capitalize() for part in class_name_parts) + 'Plugin'
                logger.info(f"Looking for plugin class: {plugin_class_name} in module: {module_name}")
                plugin_class = getattr(module, plugin_class_name, None)
                if plugin_class is None:
                    logger.error(f"Plugin class {plugin_class_name} not found in module {module_name}. Available classes: {dir(module)}")
                    continue
                plugin_instance = plugin_class(parent)
                plugins.append(plugin_instance)
                logger.info(f"Successfully loaded plugin: {plugin_instance.name}, priority: {plugin_instance.priority}")
            except Exception as e:
                logger.error(f"Failed to load plugin {module_name}: {e}")
    try:
        sorted_plugins = sorted(plugins, key=lambda p: p.priority, reverse=True)  # Sort in descending order
        logger.info(f"Sorted plugins by priority: {[p.name + ' (priority ' + str(p.priority) + ')' for p in sorted_plugins]}")
        return sorted_plugins
    except Exception as e:
        logger.error(f"Error sorting plugins by priority: {e}")
        return plugins  # Fallback to unsorted list if sorting fails