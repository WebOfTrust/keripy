import copy
import re

from apispec import BasePlugin, yaml_utils
from apispec.exceptions import APISpecError
from apispec.core import VALID_METHODS


class FalconPlugin(BasePlugin):
    """APISpec plugin for Falcon"""

    def __init__(self, app):
        super(FalconPlugin, self).__init__()
        self._app = app

    def init_spec(self, spec):
        self._spec = spec

    def _get_valid_methods(self):
        return set(VALID_METHODS[self._spec.openapi_version.major])

    def _generate_resource_uri_mapping(self, app):
        valid_methods = self._get_valid_methods()
        routes_to_check = copy.copy(app._router._roots)

        mapping = {}
        for route in routes_to_check:
            uri = route.uri_template
            resource = route.resource
            mapping[resource] = {
                "uri": uri,
                "methods": {}
            }

            if route.method_map:
                for method_name, method_handler in route.method_map.items():
                    if method_handler.__module__ == "falcon.responders":
                        continue
                    if method_name.lower() not in valid_methods:
                        continue
                    mapping[resource]["methods"][method_name.lower()] = method_handler

            routes_to_check.extend(route.children)
        return mapping

    def path_helper(self, operations, resource, base_path=None, **kwargs):
        """Path helper that allows passing a Falcon resource instance."""
        resource_uri_mapping = self._generate_resource_uri_mapping(self._app)

        if resource not in resource_uri_mapping:
            raise APISpecError("Could not find endpoint for resource {0}".format(resource))

        operations.update(yaml_utils.load_operations_from_docstring(resource.__doc__) or {})
        path = resource_uri_mapping[resource]["uri"]

        if base_path is not None:
            # make sure base_path accept either with or without leading slash
            # swagger 2 usually come with leading slash but not in openapi 3.x.x
            base_path = '/' + base_path.strip('/')
            path = re.sub(base_path, "", path, 1)

        methods = resource_uri_mapping[resource]["methods"]

        for method_name, method_handler in methods.items():
            docstring_yaml = yaml_utils.load_yaml_from_docstring(method_handler.__doc__)
            operations[method_name] = docstring_yaml or dict()
        return path