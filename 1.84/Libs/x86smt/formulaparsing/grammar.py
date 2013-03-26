import operator
import string

from pyparsing import Word, Literal
from pyparsing import ZeroOrMore, Forward, Optional
from pyparsing import StringEnd

"""
FORMULA     ::= RELATION (CONNECTIVE RELATION)* | '(' FORMULA ')'
RELATION    ::= LHS_EXPR EQ_SYMBOL RHS_EXPR | '(' RELATION ')'
RHS_EXPR    ::= LHS_EXPR | HEXNUM
LHS_EXPR    ::= REGISTER | MEMREF
MEMREF      ::= '[' MEMREF_EXPR ']' | '[' MEMREF ']'
MEMREF_EXPR ::= MEMREF_PTR (+ | -) MEMREF_PTR
MEMREF_PTR  ::= HEXNUM ^ REGISTER
CONNECTIVE  ::= '^' | 'v' 
REGISTER    ::= 'eax' | 'ebx' ... 
EQ_SYMBOL   ::= '<' ^ '>' ...
HEXNUM      ::= '0x' HEXDIGITS ^ HEXDIGITS
HEXDIGITS   ::= a-fA-F0-9
"""

hex_nums = '0123456789'
hex_letters = 'abcdef'
hex_letters_upper = hex_letters.upper()
hex_digits = ''.join([hex_nums, hex_letters, hex_letters_upper])

equality_symbols = ['<', '>', '=', '!=', '<=', '>=']
equality_literals = map(Literal, equality_symbols)

registers = ['eax', 'ebx', 'ecx', 
          'edx', 'esi', 'edi',
          'ebp', 'esp', 'eip']
registers.extend(map(string.upper, registers))
register_literals = map(Literal, registers)

logical_connectives = ['^', 'v']
logical_literals = map(Literal, logical_connectives)

HEXNUM = Literal('0x').suppress() + Word(hex_digits)

EQ_SYMBOL = reduce(operator.xor, equality_literals)
REGISTER = reduce(operator.xor, register_literals)
CONNECTIVE = reduce(operator.or_, logical_literals)

MEMREF_PTR = HEXNUM ^ REGISTER
MEMREF_PTR_EXPR = MEMREF_PTR + (Literal('-') | Literal('+')) + \
                  MEMREF_PTR 
MEMREF_PTR_EXPR |= MEMREF_PTR
MEMREF = Literal('[') + MEMREF_PTR_EXPR + Literal(']')
MEMREF |= Literal('[') + MEMREF + Literal(']')

LHS_EXPR = REGISTER | MEMREF
RHS_EXPR = LHS_EXPR | HEXNUM

RELATION = LHS_EXPR + EQ_SYMBOL + RHS_EXPR 
           
FORMULA = RELATION + ZeroOrMore(CONNECTIVE + RELATION) + StringEnd()

