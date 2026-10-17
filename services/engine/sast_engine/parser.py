"""Parsers Python usados pelo motor SAST."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from tree_sitter import Language, Parser, Tree
import tree_sitter_python


@dataclass(frozen=True)
class ParsedTrees:
    """Árvores sintáticas do código-fonte."""

    ast_tree: ast.AST
    tree_sitter_tree: Tree


class GenericASTVisitor(ast.NodeVisitor):
    """Visitor genérico para percorrer uma AST Python."""

    def __init__(self) -> None:
        super().__init__()
        self.nodes: list[ast.AST] = []

    def generic_visit(self, node: ast.AST) -> None:
        self.nodes.append(node)
        super().generic_visit(node)


def parse_source(source: str) -> ParsedTrees:
    """Constrói a AST padrão e a árvore Tree-sitter."""
    ast_tree = ast.parse(source)
    parser = Parser(Language(tree_sitter_python.language()))
    tree_sitter_tree = parser.parse(source.encode("utf-8"))
    return ParsedTrees(ast_tree=ast_tree, tree_sitter_tree=tree_sitter_tree)


def generic_visitor(tree: ast.AST) -> GenericASTVisitor:
    """Percorre uma AST e devolve um visitor com os nós encontrados."""
    visitor = GenericASTVisitor()
    visitor.visit(tree)
    return visitor
