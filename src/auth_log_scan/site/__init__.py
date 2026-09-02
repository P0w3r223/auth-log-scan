"""Static page generator for the published demo. Not imported by the scanner or the CLI.

Nothing is re-exported here on purpose: ``build`` is both the module and its main function,
and binding the function at package level would shadow the module for anyone importing it.
"""
