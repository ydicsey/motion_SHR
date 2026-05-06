#!/usr/bin/env python3
"""Compute static depth and interactive depth for Bristol and ABY circuits."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_INTERACTIVE_GATES = frozenset({"AND", "OR", "MUX", "MUL"})


@dataclass
class WireState:
    depth: int = 0
    interactive_depth: int = 0


@dataclass
class CircuitStats:
    path: str
    format: str
    gates: int
    wires: int
    inputs: int
    outputs: int
    depth: int
    interactive_depth: int
    max_wire_depth: int
    max_wire_interactive_depth: int
    xor: int = 0
    and_: int = 0
    inv: int = 0
    or_: int = 0
    mux: int = 0
    add: int = 0
    mul: int = 0
    other: int = 0

    def row(self) -> dict[str, object]:
        result = asdict(self)
        result["AND"] = result.pop("and_")
        result["OR"] = result.pop("or_")
        result["XOR"] = result.pop("xor")
        result["INV"] = result.pop("inv")
        result["MUX"] = result.pop("mux")
        result["ADD"] = result.pop("add")
        result["MUL"] = result.pop("mul")
        result["OTHER"] = result.pop("other")
        return result


def normalize_gate(gate: str) -> str:
    mapping = {
        "A": "AND",
        "X": "XOR",
        "V": "OR",
        "I": "INV",
        "M": "MUX",
    }
    gate = gate.upper()
    return mapping.get(gate, gate)


def bump_count(stats: CircuitStats, gate_type: str) -> None:
    if gate_type == "XOR":
        stats.xor += 1
    elif gate_type == "AND":
        stats.and_ += 1
    elif gate_type == "INV":
        stats.inv += 1
    elif gate_type == "OR":
        stats.or_ += 1
    elif gate_type == "MUX":
        stats.mux += 1
    elif gate_type == "ADD":
        stats.add += 1
    elif gate_type == "MUL":
        stats.mul += 1
    else:
        stats.other += 1


def update_wire(
    wires: dict[int, WireState],
    output: int,
    parents: Iterable[int],
    gate_type: str,
    interactive_gates: frozenset[str],
) -> None:
    parent_states = []
    for parent in parents:
        if parent not in wires:
            raise ValueError(f"wire {parent} is used before definition")
        parent_states.append(wires[parent])

    depth = max((state.depth for state in parent_states), default=0) + 1
    interactive_depth = max((state.interactive_depth for state in parent_states), default=0)
    if gate_type in interactive_gates:
        interactive_depth += 1
    wires[output] = WireState(depth, interactive_depth)


def nonempty_lines(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def looks_like_bristol_fashion(lines: list[str]) -> bool:
    if len(lines) < 3:
        return False
    second = lines[1].split()
    third = lines[2].split()
    if len(second) < 2 or len(third) < 2:
        return False
    try:
        second_count = int(second[0])
        third_count = int(third[0])
    except ValueError:
        return False
    return len(second) == second_count + 1 and len(third) == third_count + 1


def parse_bristol(
    path: Path, requested_format: str, interactive_gates: frozenset[str]
) -> CircuitStats:
    lines = nonempty_lines(path)
    if len(lines) < 2:
        raise ValueError("Bristol circuit is missing header lines")

    first = lines[0].split()
    declared_gates = int(first[0])
    number_of_wires = int(first[1])
    fashion = requested_format == "bristol-fashion" or (
        requested_format == "auto" and looks_like_bristol_fashion(lines)
    )

    if fashion:
        input_tokens = [int(token) for token in lines[1].split()]
        output_tokens = [int(token) for token in lines[2].split()]
        inputs = sum(input_tokens[1:])
        outputs = sum(output_tokens[1:])
        gate_lines = lines[3:]
        format_name = "bristol-fashion"
    else:
        io_tokens = [int(token) for token in lines[1].split()]
        if len(io_tokens) == 2:
            inputs = io_tokens[0]
            outputs = io_tokens[1]
        elif len(io_tokens) == 3:
            inputs = io_tokens[0] + io_tokens[1]
            outputs = io_tokens[2]
        else:
            raise ValueError("unsupported Bristol input/output header")
        gate_lines = lines[2:]
        format_name = "bristol"

    wires = {wire: WireState() for wire in range(inputs)}
    stats = CircuitStats(
        path=str(path),
        format=format_name,
        gates=0,
        wires=number_of_wires,
        inputs=inputs,
        outputs=outputs,
        depth=0,
        interactive_depth=0,
        max_wire_depth=0,
        max_wire_interactive_depth=0,
    )

    for line in gate_lines:
        tokens = line.split()
        if not tokens:
            continue
        gate_type = normalize_gate(tokens[-1])
        number_of_inputs = int(tokens[0])
        output_wire = int(tokens[-2])
        parents = [int(token) for token in tokens[2 : 2 + number_of_inputs]]
        update_wire(wires, output_wire, parents, gate_type, interactive_gates)
        bump_count(stats, gate_type)
        stats.gates += 1

    output_wires = list(range(number_of_wires - outputs, number_of_wires))
    finish_stats(stats, wires, output_wires)
    if declared_gates != stats.gates:
        raise ValueError(f"declared {declared_gates} gates, parsed {stats.gates}")
    return stats


def parse_aby(path: Path, interactive_gates: frozenset[str]) -> CircuitStats:
    wires: dict[int, WireState] = {}
    outputs: list[int] = []
    input_count = 0
    stats = CircuitStats(
        path=str(path),
        format="aby",
        gates=0,
        wires=0,
        inputs=0,
        outputs=0,
        depth=0,
        interactive_depth=0,
        max_wire_depth=0,
        max_wire_interactive_depth=0,
    )

    def define_wire(wire: int) -> None:
        if wire in wires:
            raise ValueError(f"wire {wire} is redefined")
        wires[wire] = WireState()

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        tag = tokens[0]

        if tag in {"S", "C"}:
            for token in tokens[1:]:
                define_wire(int(token))
                input_count += 1
        elif tag in {"0", "1"}:
            define_wire(int(tokens[1]))
        elif tag in {"A", "X", "V"}:
            gate_type = normalize_gate(tag)
            parent_a, parent_b, output_wire = map(int, tokens[1:4])
            update_wire(wires, output_wire, (parent_a, parent_b), gate_type, interactive_gates)
            bump_count(stats, gate_type)
            stats.gates += 1
        elif tag == "I":
            gate_type = normalize_gate(tag)
            parent, output_wire = map(int, tokens[1:3])
            update_wire(wires, output_wire, (parent,), gate_type, interactive_gates)
            bump_count(stats, gate_type)
            stats.gates += 1
        elif tag == "M":
            gate_type = normalize_gate(tag)
            in0, in1, selection, output_wire = map(int, tokens[1:5])
            update_wire(wires, output_wire, (in0, in1, selection), gate_type, interactive_gates)
            bump_count(stats, gate_type)
            stats.gates += 1
        elif tag == "O":
            outputs.extend(int(token) for token in tokens[1:])
        else:
            # ABY files may contain sections such as "DFFs:" that MOTION ignores too.
            continue

    if not outputs:
        raise ValueError("ABY circuit has no output list")

    stats.inputs = input_count
    stats.outputs = len(outputs)
    stats.wires = len(wires)
    finish_stats(stats, wires, outputs)
    return stats


def finish_stats(stats: CircuitStats, wires: dict[int, WireState], output_wires: Iterable[int]) -> None:
    output_states = []
    for wire in output_wires:
        if wire not in wires:
            raise ValueError(f"output wire {wire} is not defined")
        output_states.append(wires[wire])
    stats.depth = max((state.depth for state in output_states), default=0)
    stats.interactive_depth = max(
        (state.interactive_depth for state in output_states), default=0
    )
    stats.max_wire_depth = max((state.depth for state in wires.values()), default=0)
    stats.max_wire_interactive_depth = max(
        (state.interactive_depth for state in wires.values()), default=0
    )


def detect_format(path: Path, requested_format: str) -> str:
    if requested_format != "auto":
        return requested_format
    suffix = path.suffix.lower()
    if suffix == ".aby":
        return "aby"
    return "bristol"


def analyze_path(path: Path, requested_format: str, interactive_gates: frozenset[str]) -> CircuitStats:
    if requested_format == "auto" and path.suffix.lower() != ".aby":
        return parse_bristol(path, "auto", interactive_gates)

    actual_format = detect_format(path, requested_format)
    if actual_format == "aby":
        return parse_aby(path, interactive_gates)
    if actual_format in {"bristol", "bristol-fashion", "auto"}:
        return parse_bristol(path, actual_format, interactive_gates)
    raise ValueError(f"unsupported format: {requested_format}")


def print_table(rows: list[dict[str, object]]) -> None:
    columns = [
        "path",
        "format",
        "gates",
        "wires",
        "inputs",
        "outputs",
        "depth",
        "interactive_depth",
        "max_wire_depth",
        "max_wire_interactive_depth",
        "XOR",
        "AND",
        "OR",
        "MUX",
        "INV",
        "ADD",
        "MUL",
        "OTHER",
    ]
    widths = {
        column: max(len(column), *(len(str(row[column])) for row in rows)) for column in columns
    }
    print("  ".join(column.ljust(widths[column]) for column in columns))
    print("  ".join("-" * widths[column] for column in columns))
    for row in rows:
        print("  ".join(str(row[column]).ljust(widths[column]) for column in columns))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compute static depth and interactive depth for Bristol and ABY circuits."
    )
    parser.add_argument("circuits", nargs="+", type=Path, help="Circuit files to analyze")
    parser.add_argument(
        "--format",
        choices=("auto", "aby", "bristol", "bristol-fashion"),
        default="auto",
        help="Input format. auto uses .aby for ABY and Bristol otherwise.",
    )
    parser.add_argument(
        "--interactive-gates",
        default=",".join(sorted(DEFAULT_INTERACTIVE_GATES)),
        help="Comma-separated normalized gate names that add interactive depth.",
    )
    parser.add_argument(
        "--output",
        choices=("table", "csv", "json"),
        default="table",
        help="Output format.",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    interactive_gates = frozenset(
        normalize_gate(gate.strip()) for gate in args.interactive_gates.split(",") if gate.strip()
    )
    rows = []
    for circuit in args.circuits:
        try:
            rows.append(analyze_path(circuit, args.format, interactive_gates).row())
        except Exception as error:
            print(f"{circuit}: {error}", file=sys.stderr)
            return 1

    if args.output == "json":
        print(json.dumps(rows, indent=2))
    elif args.output == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    else:
        print_table(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
