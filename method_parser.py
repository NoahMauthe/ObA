import logging

from utility.exceptions import MalwareProjectException


class ParserError(MalwareProjectException):
    pass


class MethodParser:

    def __init__(self):
        self.method_invocations = {}
        self.params = set()
        self.logger = logging.getLogger('MethodParser')
        self.logger.setLevel(logging.NOTSET)
        self.parse_param = {
            'MethodInvocation': self._parse_method_invocation,
            'Local': lambda x: 'PARAM' if x[1] in self.params else 'LOCAL',
            'Literal': lambda x: f'LITERAL({x[1]})',
            'FieldAccess': self._parse_field,
            'ArrayAccess': self._parse_array_access,
            'ArrayInitializer': self._parse_array_initialization,
            'Parenthesis': self._parse_parenthesis,
            'TypeName': self._parse_type_name,
            'Cast': self._parse_cast,
            'Unary': self._parse_unary,
            'BinaryInfix': self._parse_binary,
            'ClassInstanceCreation': self._parse_class_creation,
        }

    def parse(self, ast):
        self._parse_param_names(ast.get('params'))
        self._find_method_invocations(ast.get('body', []))
        return self.method_invocations

    def reset(self):
        self.params = set()
        self.method_invocations = {}

    def _parse_generic(self, type_name, value):
        assert type(type_name) == str
        return self.parse_param.get(type_name, self._unknown)(value)

    def _find_method_invocations(self, elem):
        if not elem:
            return
        if elem[0] == 'MethodInvocation':
            try:
                self._parse_method_invocation(elem)
            except ParserError as e:
                self.logger.error(repr(e))
        else:
            for item in elem:
                if type(item) == list or type(item) == tuple:
                    self._find_method_invocations(item)

    def _parse_param_names(self, params):
        for param in params:
            self.params.add(param[1][1])

    def _parse_cast(self, param):
        assert param[0] == 'Cast'
        return self._parse_generic(param[1][1][0], param[1][1])

    def _parse_field(self, param):
        assert param[0] == 'FieldAccess'
        self._find_method_invocations(param[1])
        return "FIELD"

    def _parse_unary(self, param):
        assert param[0] == 'Unary'
        return self._parse_generic(param[1][0][0], param[1][0])

    def _parse_binary(self, param):
        assert param[0] == 'BinaryInfix'
        left = self._parse_generic(param[1][0][0], param[1][0])
        right = self._parse_generic(param[1][1][0], param[1][1])
        if left == right:
            return left
        else:
            return "LOCAL"

    def _parse_array_access(self, param):
        assert param[0] == 'ArrayAccess'
        self._parse_generic(param[1][0][0], param[1][0])
        return self._parse_generic(param[1][1][0], param[1][1])

    def _parse_array_initialization(self, array):
        assert array[0] == 'ArrayInitializer'
        items = []
        for statement in array[1]:
            items.append(self._parse_generic(statement, array))
        return f'ARRAY({", ".join(items)})'

    def _parse_class_creation(self, param):
        assert param[0] == 'ClassInstanceCreation'
        for p in param[2]:
            self._parse_generic(p[0], p)
        return f'CONSTRUCTOR(L{param[1][0]};)'

    def _parse_parenthesis(self, param):
        assert param[0] == 'Parenthesis'
        if len(param[1]) > 1:
            self.logger.error(f'Parenthesis:\t{param}')
        return self._parse_generic(param[1][0][0], param[1][0])

    def _parse_call_parameters(self, params):
        parameter_types = []
        for param in params:
            param_type = self.parse_param.get(param[0], self._unknown)(param)
            if param_type:
                parameter_types.append(param_type)
        return parameter_types

    def _unknown(self, param):
        self.logger.fatal(f'Found unknown type {param[0]}:\n\t{param}')
        return param[0]

    @staticmethod
    def _parse_type_name(param):
        assert param[0] == 'TypeName'
        return f'TYPE({param[1][0]})'

    def _parse_method_invocation(self, method_invocation):
        assert method_invocation[0] == 'MethodInvocation'
        params = method_invocation[1]
        class_name, method_name, method_types = method_invocation[2]
        class_name = f'L{class_name};'
        class_ = self.method_invocations.get(class_name, {})
        method_params = class_.get(method_name, [])
        parameters = self._parse_call_parameters(params)
        method_params.append(parameters)
        class_[method_name] = method_params
        self.method_invocations[class_name] = class_
        return f'METHOD({", ".join(parameters)})'
