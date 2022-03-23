import copy

import falcon
from apispec import yaml_utils
from apispec.core import VALID_METHODS, APISpec


class SpecResource:
    """
    Resource for OpenAPI spec

    """

    def __init__(self, app, title, resources, version='1.0.0', openapiVersion="3.0.2"):
        self.spec = APISpec(
            title=title,
            version=version,
            openapi_version=openapiVersion,
        )

        valid_methods = self._get_valid_methods(self.spec)
        routes_to_check = copy.copy(app._router._roots)

        for route in routes_to_check:
            if route.resource is not None:
                operations = dict()
                operations.update(yaml_utils.load_operations_from_docstring(route.resource.__doc__) or {})

                if route.method_map:
                    for method_name, method_handler in route.method_map.items():
                        if method_handler.__module__ == "falcon.responders":
                            continue
                        if method_name.lower() not in valid_methods:
                            continue
                        docstring_yaml = yaml_utils.load_yaml_from_docstring(method_handler.__doc__)
                        operations[method_name.lower()] = docstring_yaml or dict()

                self.spec.path(path=route.uri_template, operations=operations)
            routes_to_check.extend(route.children)

    def _get_valid_methods(self, spec):
        return set(VALID_METHODS[spec.openapi_version.major])

    def on_get(self, _, rep):
        """
        GET endpoint for OpenAPI spec

        Args:
            _: falcon.Request HTTP request
            rep: falcon.Response HTTP response


        """
        rep.status = falcon.HTTP_200
        rep.content_type = "application/yaml"
        rep.data = self.spec.to_yaml().encode("utf-8")
