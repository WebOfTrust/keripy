# Python Style Guide for keripy

The Python PEPs on style have many options or allowed variants.
The purpose of this document is to select a single preferred style
in every case. In general this guide follows PEP-8 but specifies styles
where PEP-8 is silent and varies from PEP-8 in a couple of places namely camelCase
versus underscore_case

Indentation 4 spaces (detab ie no tabs convert tabs to spaces)

## Naming conventions:

    alllowercase
    ALLUPPERCASE
    mixedCase lowerCamelCase
    CapitalCamelCase UpperCamelCase
    lower_case_with_underscores
    UPPER_CASE_WITH_UNDERSCORES
    Capitalized_With_Underscores
    lowercasenounderscores
    LeadingUnderscoreUpperCamelCase
    leadingUnderscoreLowerCamelCase



Rules:

Python Standard Library methods and attributes are small case with underscores.
   startswith()


Python builtins are small case no underscores
   setattr()

Spaces between methods and top level functions:
   two 2

Spaces between Class Definitions:
   two 2

DocStrings:
   Triple double quotes. """ """

```python
   """If one line doc string then may be all on one line"""

   """
   If more than one line doc string then linefeed and start even with first string
   such as this string. Embedded strings use 'single quotes'.
   """

   Format for code documentation in the the Google flavor of sphinx.ext.napolean format.
   See
   https://www.sphinx-doc.org/en/master/usage/extensions/napoleon.html
   and
   https://www.sphinx-doc.org/en/master/usage/extensions/example_google.html#example-google

   Napoleon supports two styles of docstrings: Google and NumPy. The main difference between
   the two styles is that Google uses indentation to separate sections, whereas NumPy uses underlines.
```
   Google style:

```python
def func(arg1, arg2):
    """Summary line.

    Extended description of function.

    Args:
        arg1 (int): Description of arg1
        arg2 (str): Description of arg2

    Returns:
        bool: Description of return value

    """
    return True
```

Acronyms:
When using underscores acronyms should be all uppercase if start uppercase
or all lowercase if start lowercase
    http_send  Send_HTTP

When using CapCamelCase or mixedCase the acronyms should be treated as words
    httpSend sendHttp


Local Variables and function parameters:
   lowerCamelCase

Any name that conflicts with python reserved word:
   add trailing underscore:
   Examples: id_, file_, Bork_

Module Names:
   all lower case. End name in 'ing' so when doing namespace know that first ref is module not class such as,
   behaving, clustering, functioning

Package Names:
   all lower case. Pithy and short but evocative

Class Names:
   CapCamelCase
   Examples:  Person  BigDogs

Exception Classes:
   CapCamelCase
   Example: StandardMuxError

Public Class Attributes, Class Methods, Static Methods:
   CapCamelCase
   Example: TotalInstances Storage

Private Class Attributes, Class Methods, Static Methods:
   LeadingUnderscoreUpperCamelCase, methods verbs, sequences plural nouns
   Example: `_TotalInstances _Storage __Entries`

Very Private Class Attributes, Class Methods, Static Methods (mangled with class name):
   leading double underscore CapCamelCase, methods verbs, sequences plural nouns
   Example: `__TotalInstances __Storage __Entries``

Public Instance Methods and Attributes:
   lowerCamelCase, Methods should be verbs, sequences should be plural nouns
   Examples: getName setStyle, display, first, last, itemCount, entities, books, data

Public Module Level Methods and Attributes:
   lowerCamelCase, Methods should be verbs, sequences should be plural nouns
   Examples: getName setStyle, display, first, last, itemCount, entities, books, data

Private Instance and Attributes (not exported with from import `*``):
   leadingUnderscoreLowerCamelCase, Methods should be verbs, sequences plural nouns
   Examples: `_getScore _setInternal _lastName _count _entries`

Private Module Level Methods and Attributes (not exported by from import `*`):
   leadingUnderscoreLowerCamelCase
   Examples:` _dirtyBit`

Very Private Instance Methods or Attributes  (mangled with class name):
   double leading underscore with lowerCamelCase, methods verbs, sequences plural nouns
   Examples:` __getMyName __displayMoney __creature __secretData __entries`

Constants Module Level:
   UPPER_CASE_WITH_UNDERSCORES
   not meant to be changed should be numbers or strings
   Examples: MY_CONSTANT

Dynamic Global Variables (not Constants) Module Level:
   These are reserved for module level globals that may be changed in multiple places intentionally.
   Usually this is bad practice so special syntax is used to indicate such practice only when necessary.
   Capitalized_With_Underscores
   Examples: Bad_Practice  REO_Lat_Lon_NE


