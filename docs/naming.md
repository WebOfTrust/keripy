
# Python Style Guide for keripy

The Python PEPs on style have many options or allowed variants.
The purpose of this document is to select a single preferred style
in every case. In general this guide follows PEP-8 but specifies styles
where PEP-8 is silent and varies from PEP-8 in a couple of places namely camelCase
versus underscore_case. The latter (camelCase instead of underscore_case) is
the most violated PEP-8 convention in the Python standard library.
For example the well known logging and unittest packages use camelCase.
Therefore, we are in good company. Because camelCase variables are equally
readable but also more concise than underscore_case_, that improved conciseness
contributes to shorter statement lengths which are themselves more readable.
Readability trumps convention.

## Indentation

4 spaces (detab ie no tabs convert tabs to spaces)

## Naming Convention Labels:
These are used in the rules below.


    alllowercase
    ALLUPPERCASE
    lowerCamelCase
    UpperCamelCase
    lower_case_with_underscores
    UPPER_CASE_WITH_UNDERSCORES
    Capitalized_With_Underscores
    _LeadingUnderscoreUpperCamelCase
    _leadingUnderscoreLowerCamelCase
    __LeadingDoubleUnderscoreUpperCamelCase
    __leadingDoubleUnderscoreLowerCamelCase



## Rules

### Python Standard Library methods and attributes

alllowercase
startswith()
In some cases may be lower_case_with_underscores

### Python builtins
alllowercase no underscores
setattr()

### Vertical Spacing
Spaces between methods and top level functions:
   two 2

Spaces between Class Definitions:
   two 2

### DocStrings
   Triple double quotes. """ """

```python
   """If one line doc string then may be all on one line"""

   """If more than one line doc string then first line starts after triple quotes.
   Following lines outdent. Embedded strings use 'single quotes'.
   """

   Format for code documentation in the the Google flavor of sphinx.ext.napolean format.
   See
   https://www.sphinx-doc.org/en/master/usage/extensions/napoleon.html
   and
   https://www.sphinx-doc.org/en/master/usage/extensions/example_google.html#example-google

   The Google style uses indentation to separate sections.
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

### Acronyms

When using underscores acronyms should be all uppercase if start uppercase,
or all lowercase if start lowercase.
    http_send  Send_HTTP

When using CapCamelCase or mixedCase the acronyms should be treated as words
    httpSend sendHttp


### Local Variables and function parameters:
   lowerCamelCase.

### Any name that conflicts with python reserved word
   add trailing underscore:
   Examples: id_, file_

### Package Names:
   alllowercase. Pithy and short but evocative.


### Module Names
   alllowercase. End name in 'ing' so can distinquish package and module references
   when namespacing. First ref is module not package variable such as:
   core.behaving, core.clustering

### Public Module Level Class Instances Singletons
   UpperCamelCase

### Private Module Level Class Instances Singletons
   _LeadingUnderscoreUpperCamelCase

### Public Module Level Methods and Attributes:
   lowerCamelCase.
   Methods use verbs.
   Attributes that are sequences use plural nouns.
   Examples: getName setStyle, display, first, last, itemCount, entities, books, data

### Private Module Level Methods and Attributes (not exported by from import `*`):
   _leadingUnderscoreLowerCamelCase.
   Methods use verbs.
   Attributes that are sequences use plural nouns.
   Examples: `_dirtyBit`

### Constants Module Level:
   UPPER_CASE_WITH_UNDERSCORES or ALLUPPERCASE
   Not meant to be changed should be numbers or strings.
   Examples: MY_CONSTANT, SOMECONSTANT

### Dynamic Global Variables (not constants) Module Level:
   Capitalized_With_Underscores.
   These are reserved for module level globals that may be changed in
   multiple places intentionally.
   Usually this is bad practice so special syntax is used to indicate
   such practice only when necessary.
   Examples: Bad_Practice  REO_Lat_Lon_NE


### Exception Classes:
   UpperCamelCase.
   Example: StandardMuxError

### Class Names:
   UpperCamelCase.
   Examples:  Person  BigDogs

### Public Class Attributes, Class Methods, Static Methods:
   UpperCamelCase.
   Methods use verbs.
   Attributes that are sequences use plural nouns.
   Example: TotalInstances, Storage, Store, Redact

### Private Class Attributes, Class Methods, Static Methods:
   _LeadingUnderscoreUpperCamelCase,
   Methods use verbs.
   Attributes that are sequences use plural nouns.
   Example: `_TotalInstances _Storage __Entries`

### Very Private Class Attributes, Class Methods, Static Methods (mangled with class name):
   __LeadingDoubleUnderscoreUpperCamelCase.
   Methods use verbs.
   Attributes that are sequences use plural nouns.
   Example: `__TotalInstances __Storage __Entries`

### Public Instance Methods and Attributes:
   lowerCamelCase'
   Methods use verbs.
   Attributes that are sequences use plural nouns.
   Examples: getName setStyle, display, first, last, itemCount, entities, books, data


### Private Instance and Attributes (not exported with from import `*``):
   _leadingUnderscoreLowerCamelCase.
   Methods use verbs.
   Attributes that are sequences use plural nouns.
   Examples: `_getScore _setInternal _lastName _count _entries`


### Very Private Instance Methods or Attributes  (mangled with class name):
   __leadingDoubleUnderscoreLowerCamelCase.
   Methods use verbs.
   Attributes that are sequences use plural nouns.
   Examples:` __getMyName __displayMoney __creature __secretData __entries`



## Readability

The book C Elements of Style by  Qualline used a quantitaive approach
to measuring readability in code. It measured error rate in reading and
understanding code as a function of style conventions.
These include horizontal and veritical white space,
line length, varible name length, code block demarcation, etc.

Results were that too much indentation and too little indentation both reduce
readability. Ideal is 2, 3, or 4 space indentation. We use 4 because it is the
python standard and too hard to fight uphill for the slightly more optimal 3.

Verticle white space matters. Code should have paragraphs. Balanced brackets,
indendation and blank lines demarcate paragraphs

For example
```c
void display(void)
{
  int start;

  start = -1;

  if(start == -1)
    return;
}
```

is more readable than

```c
void display(void){
int start; start = -1;
if(start == -1) return;
}
```

Line length matters. Which means variable length matters.
Simple logic statments that wrap are no longer simple.
Context may provide meaning.
Scope and class Nesting may provide meaning.

Shorter evocative names are more readable than long descriptive names when
composing code because the long names make the statements that use the variables
too long to be easily readable.

aviary vs flyingBirdCage

aviary.bird vs flyingBirdCage.bird

hawk.wing.size vs hawkWingSize

### Acronyms which are abbreviations that form pronounceable words may be
highly evocative.
radar (RAdio Detecting And Ranging),
laser (Light Amplification through Stimulated Emission and Radiation)
keri (Key Event Reciept Infrastructure)


## Evocative Semantic Naming

evocative -adjective tending to evoke:
   The perfume was evocative of spring.

evoke -verb (used with object),
    to call up or produce (memories, feelings, etc.):
        to evoke a memory.
    to elicit or draw forth:
        His comment evoked protests from the shocked listener

An evocative semanitic name is a name that calls up the meaning without having
to explicity detail the meaning. Its a type of mneumonic that balances semantics
with conciseness which balance improves overall readability and understanding.

aviary vs flyingBirdCage

Use English suffix composition rules to create pithy terse more consise names
that are sufficiently evocative.


## Suffix Mapping

Adjective describing module. What does the module enable one to do.

Verb is the deed or act

Object is actor doer

Place to keep track of or create Objects container or factory

 doery actorery doerage actorage

 of an Doer is a doery or doage or dodom or dohood

-er -or -eur -ster Agent one who does something brewer (Object Classes)

-ery a place for an actor to act  factory brewery  (Object Factories)

-ing  action of   running, wishing  (Module Names)

-age state of acting  actor to act  brewerage

-dom state of doing acting  kingdom

-hood state of being childhood

-ship quality of or state of rank of midship

-ize to make itemize

-izer Someone who makes one do itemizer

-ive having nature of active rotative inceptive

-acy -isy -ty  quality of  linty piracy clerisy

-ion -tion -sion act or state of action itemization

-y -ly like full of happening  noisy monthly

patron

patroner

patronist

patronery

patronage

patrondom

patronship

patronacy

patronhood

patronize

patronish

patronive

patronlet

patronly

patrony




### Rules for English suffixes

http://www.paulnoll.com/Books/Clear-English/English-suffixes-1.html
http://www.prefixsuffix.com/rootchart.php


Suffix   Meaning   Examples  Used

able, ible   capable of, worthy  agreeable, comfortable, credible

age          act of or state of  salvage, bondage

acy, isy   quality   hypocrisy, piracy

al, eal, ial   on account of related to, action of   judicial, official arrival, refusal

ance, ence   act or fact of doing state of   violence, dependence allowance, insurance

ant  quality of one who  defiant, expectant, reliant occupant, accountant

er, or, eur  agent, one who  author, baker, winner, dictator, chauffeur, worker

ed   past  jumped, baked

ery  a place to practice of condition of  nunnery, cannery surgery bravery, drudgery

dom  state, condition of   wisdom, kingdom, martyrdom

ent  having the quality of   different, dependent, innocent

en   made of, to make  woolen, wooden, darken

er   degree of comparison  harder, newer, older

est  highest of comparison   cleanest, hardest, softest

ful full of  graceful, restful, faithful

-hood  noun from noun group state of being  boyhood, knighthood, womanhood

ible, ile, il  capable of being  digestible, responsible, docile, civil

ier, ior   one who   carrier, warrior

ify  to make   magnify, beautify, falsify

ic   like, made of   metallic, toxic, poetic

ing  action of   running, wishing

ion, sion, tion  act or state of being  confusion, correction, protection

ism  fact of being   communism, socialism

ish  like  childish, sheepish, foolish

ist  a person who does   artist, geologist

ity, ty  state of  majesty, chastity, humanity

itis   inflammation of   appendicitis, tonsillitis

ive  having nature of  attractive, active

ize  to make   pasteurize, motorize

less   without   motionless, careless, childless


let  small   starlet, eaglet

ly   like, in a manner happening   heavenly, remarkably, suddenly every absolutely, monthly

ment   state or quality act of doing   accomplishment, excitement placement, movement

meter  device for measuring  thermometer, barometer

ness   state of  blindness, kindness

ology  study of  geology, zoology, archaeology

ous, ious  full of   joyous, marvelous, furious

-ship   noun from noun quality of state of rank of  friendship, leadership  lordship

-scope  instrument for seeing   telescope, microscope

-some   like  tiresome, lonesome

-tude  noun from adjective state of  altitude, latitude

-ty   quality or state of   liberty, majesty

-ward   toward  southward, forward

-y  like, full of, diminutive:  noisy, sooty, kitty

-ure noun from verb indicating act or office  seizure prefecture



